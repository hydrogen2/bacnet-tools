#!/usr/bin/env python3
"""Forge an I-Am for any BACnet device that answers ReadProperty but never answers Who-Is.

BACstac will not route a single request to a device until bsResolveDeviceID
completes, and that needs an I-Am. Some old firmware ignores Who-Is entirely
(observed: IN-BAC-MBM, vendor 246, at 10.138.0.193) so the collect wedges
forever on

    devInst(N) ResolveDeviceID failed, status=Device unreachable

even though unicast ReadProperty to the same device works perfectly. I-Am is an
unconfirmed, unauthenticated service with no invoke id and no correlation to the
Who-Is that triggered it, so a fabricated one is indistinguishable from a real
one. Sent with the DEVICE's source address, BACstac binds the instance to the
real device and every subsequent request goes there, not here.

One I-Am is enough: BACstac caches the address binding and does not re-resolve
while the device keeps answering. So this is event-driven, not periodic -- it
watches for the failure and fires only then. The cases that lose the binding are
edge reboot, edge-dpf/BACstac restart, and collect republish; all three surface
as that same log line, which is why watching the log covers them all.

Generic by design: device IP and port come from the driver log directory name,
the instance from the log line. No per-device configuration, so a future silent
device is handled with no change here.

SAFETY GUARD -- the important part. Before forging anything it proves the device
is really alive by reading its object-identifier over unicast ReadProperty. If
that fails the device is genuinely down and NOTHING is sent. Without this guard
a dead device would be made to look present and the collect would report read
errors forever instead of a clean "unreachable", masking real outages.

If max-apdu-length-accepted / segmentation-supported cannot be read, it falls
back to the conservative BACnet floor (480, no segmentation) rather than
guessing high -- BACstac then sends small unsegmented requests, which any
conformant device accepts.

Needs CAP_NET_RAW (runs as root). TX uses IPPROTO_RAW + IP_HDRINCL so it
bypasses the UDP bind table and coexists with BACstac on 47808.
"""
import argparse, os, re, socket, sys, time
from datetime import datetime

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from bacnet_wire import Reader, build_ip_udp, parse_readprop_ack, detect_bacstac_ip
from fake_iam import build_iam

LOG_DIR = '/home/envuser/energy-os/edge-dpf/logs/bacstac_client'
# bacstac_client-other-10.138.0.193_47808-3287be16-eee5-485d-8aec-98cb80d8bc9b
DIR_RE = re.compile(r'-(\d{1,3}(?:\.\d{1,3}){3})_(\d+)-')
FAIL_RE = re.compile(
    r'\[(\d{4}-\d\d-\d\d \d\d:\d\d:\d\d)\.\d+\].*devInst\((\d+)\)\s+ResolveDeviceID failed')

PROP_OBJECT_ID, PROP_MAX_APDU, PROP_SEGMENTATION, PROP_VENDOR = 75, 62, 107, 120
OBJ_DEVICE = 8
SAFE_MAX_APDU, SAFE_SEGMENTATION = 480, 3   # BACnet floor: smallest APDU, no segmentation


LOG_FILE = '/var/log/bacnet-iam.log'
MAX_LOG_BYTES = 2 * 1024 * 1024
_log_path = LOG_FILE


def log(msg):
    """Print and append to our own file.

    systemd on this box does not capture the service's stdout into the journal,
    so relying on StandardOutput=journal would leave an unattended root daemon
    with no observable history. Events here are rare, so a 2 MB cap with one
    rollover is ample.
    """
    line = '[%s] %s' % (datetime.now().strftime('%Y-%m-%d %H:%M:%S'), msg)
    print(line, flush=True)
    if not _log_path:
        return
    try:
        if os.path.exists(_log_path) and os.path.getsize(_log_path) > MAX_LOG_BYTES:
            os.replace(_log_path, _log_path + '.1')
        with open(_log_path, 'a') as f:
            f.write(line + '\n')
    except OSError:
        pass


def latest_failure(path, stale_secs):
    """Instance from the most recent ResolveDeviceID failure, if it is recent.

    The driver stops emitting the line as soon as it resolves, so a line newer
    than stale_secs means the device is stuck RIGHT NOW. Reads only the tail,
    so log size does not matter and rotation is handled for free.
    """
    try:
        with open(path, 'rb') as f:
            f.seek(0, os.SEEK_END)
            f.seek(max(0, f.tell() - 65536))
            lines = f.read().decode('utf-8', 'replace').splitlines()
    except OSError:
        return None
    for line in reversed(lines):
        m = FAIL_RE.search(line)
        if not m:
            continue
        try:
            age = (datetime.now() - datetime.strptime(m.group(1), '%Y-%m-%d %H:%M:%S')).total_seconds()
        except ValueError:
            return None
        return int(m.group(2)) if 0 <= age <= stale_secs else None
    return None


def read_uint(reader, ip, port, inst, prop, default):
    """Read a property expected to be an integer; fall back on any failure."""
    try:
        apdu = reader.read(ip, port, OBJ_DEVICE, inst, prop, retries=2)
        if apdu is None:
            raise RuntimeError('timeout')
        vals = parse_readprop_ack(apdu)
        if not vals:
            raise RuntimeError('empty value list')
        # decode_app yields (tagname, value) pairs, e.g. ('uint', 1476) / ('enum', 0)
        v = vals[0]
        if isinstance(v, tuple) and len(v) == 2:
            v = v[1]
        if isinstance(v, int) and not isinstance(v, bool):
            return v, True
        raise RuntimeError('not an integer: %r' % (vals,))
    except Exception as e:
        log('    prop %d unreadable (%s) -- using conservative %d' % (prop, e, default))
        return default, False


def forge(stack_ip, ip, port, inst, args):
    """Verify the device is alive, then send a burst of accurate I-Am. True if sent."""
    reader = Reader(stack_ip, args.src_port, timeout=args.read_timeout)
    try:
        # --- safety guard: is this device actually there at all? ---
        apdu = reader.read(ip, port, OBJ_DEVICE, inst, PROP_OBJECT_ID, retries=2)
        if apdu is None:
            log('  %s:%d device:%d ignores ReadProperty too -- genuinely down, NOT forging'
                % (ip, port, inst))
            return False
        try:
            vals = parse_readprop_ack(apdu)
        except Exception as e:
            log('  %s:%d device:%d answered but could not be parsed (%s) -- NOT forging'
                % (ip, port, inst, e))
            return False
        log('  %s:%d device:%d is alive (object-identifier=%r) but will not answer Who-Is'
            % (ip, port, inst, vals))

        max_apdu, _ = read_uint(reader, ip, port, inst, PROP_MAX_APDU, SAFE_MAX_APDU)
        seg, _      = read_uint(reader, ip, port, inst, PROP_SEGMENTATION, SAFE_SEGMENTATION)
        vendor, _   = read_uint(reader, ip, port, inst, PROP_VENDOR, 0)
    finally:
        reader.close()

    pdu = build_iam(inst, max_apdu, seg, vendor, broadcast=True)
    pkt = build_ip_udp(ip, port, stack_ip, args.stack_port, pdu)
    tx = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
    tx.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
    try:
        # Burst: BACstac waits ~6s per attempt and retries every ~16s, so a few
        # sends a couple of seconds apart are certain to land inside a window.
        for i in range(args.burst):
            tx.sendto(pkt, (stack_ip, 0))
            if i + 1 < args.burst:
                time.sleep(args.burst_gap)
    finally:
        tx.close()
    log('  forged %dx I-Am device:%d max_apdu=%d seg=%d vendor=%d  src=%s:%d -> %s:%d'
        % (args.burst, inst, max_apdu, seg, vendor, ip, port, stack_ip, args.stack_port))
    return True


def scan(stack_ip, args, last_fired):
    try:
        names = sorted(os.listdir(args.log_dir))
    except OSError:
        return   # edge-dpf not up yet; next pass will find it
    for name in names:
        d = os.path.join(args.log_dir, name)
        m = DIR_RE.search(name)
        if not m or not os.path.isdir(d):
            continue
        ip, port = m.group(1), int(m.group(2))
        inst = latest_failure(os.path.join(d, 'default.log'), args.stale)
        if inst is None:
            continue
        key = (ip, port, inst)
        now = time.time()
        if now - last_fired.get(key, 0) < args.cooldown:
            continue
        log('stuck: %s:%d device:%d (%s)' % (ip, port, inst, name))
        last_fired[key] = now      # set before sending: a failure must not retry-storm
        forge(stack_ip, ip, port, inst, args)


def main():
    p = argparse.ArgumentParser(description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument('--log-dir', default=LOG_DIR)
    p.add_argument('--stack-ip', help='local BACstac bind IP (default: autodetect /proc/net/udp)')
    p.add_argument('--stack-port', type=int, default=47808)
    p.add_argument('--src-port', type=int, default=47808)
    p.add_argument('--interval', type=float, default=20, help='seconds between log scans')
    p.add_argument('--stale', type=float, default=90,
                   help='treat a failure line newer than this as "stuck now"')
    p.add_argument('--cooldown', type=float, default=120,
                   help='min seconds between attempts for the same device')
    p.add_argument('--read-timeout', type=float, default=3.0)
    p.add_argument('--burst', type=int, default=5, help='I-Am sends per attempt')
    p.add_argument('--burst-gap', type=float, default=2.0)
    p.add_argument('--once', action='store_true', help='scan once and exit (for testing)')
    p.add_argument('--log-file', default=LOG_FILE, help='"" to disable file logging')
    args = p.parse_args()

    global _log_path
    _log_path = args.log_file or None

    stack_ip = args.stack_ip or detect_bacstac_ip()
    if not stack_ip:
        log('FATAL: no BACnet/IP stack bound on UDP/47808 -- pass --stack-ip')
        return 1
    log('watching %s every %.0fs; local stack %s:%d'
        % (args.log_dir, args.interval, stack_ip, args.stack_port))

    last_fired = {}
    while True:
        try:
            scan(stack_ip, args, last_fired)
        except Exception as e:                      # never die on one bad pass
            log('scan error: %r' % (e,))
        if args.once:
            return 0
        time.sleep(args.interval)


if __name__ == '__main__':
    sys.exit(main())

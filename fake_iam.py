#!/usr/bin/env python3
"""Forge an I-Am for a BACnet device that answers ReadProperty but ignores Who-Is.

THE PROBLEM
-----------
Some old firmware never answers Who-Is -- not even a unicast one -- while
answering unicast ReadProperty perfectly. That is fatal to a BACstac-based
client (the EnOS edge's `bacstac_client` driver, Cimetrics BACstac underneath),
because BACstac will not route a single request to a device until
`bsResolveDeviceID` has completed, and that resolution needs an I-Am. The
collect therefore wedges forever on

    devInst(702193) ResolveDeviceID failed, status=Device unreachable

retried every ~16s with a ~6s window, while `tcpdump` shows traffic leaving the
edge and nothing at all coming back. The device is fine; only the handshake is
broken. Points never flow, and nothing in the portal explains why.

Diagnosing it takes three checks. Do them in this order -- each one rules out a
whole class of cause, and the cheap ones come first:

    ping <ip>                                      # IP reachability
    bacsearch_raw.py --bcast <ip> --window 10      # UNICAST Who-Is: 0 devices?
    bacread_multi.py <ip> 8:<inst>:75              # ReadProperty: works?

Reachable + silent to unicast Who-Is + ReadProperty working is the signature of
this bug. If instead the device answers a *unicast* Who-Is but not a broadcast
one, you have a different (and more common) problem -- the device cannot receive
broadcasts -- and the right fix there is to redirect or duplicate the edge's own
broadcast with nftables, not to forge anything:

    nft add rule ip nat output udp dport 47808 ip daddr <bcast> dnat to <ip>

That keeps the I-Am genuine. Only reach for this tool when the device will not
answer Who-Is at all.

WHY A FORGED I-Am IS LEGITIMATE BACnet
-------------------------------------
I-Am is an *unconfirmed* service. It carries no invoke id, it is not
authenticated, and nothing in the protocol ties it to the Who-Is that provoked
it -- a device may emit one unsolicited at any time (Clause 16.10). A receiving
stack has no way to distinguish a fabricated I-Am from a real one, and is not
supposed to: that is simply how BACnet address binding works. So injecting one
on the device's behalf is not an exploit, it is a prosthetic for a firmware bug.

THE TRAP: SOURCE ADDRESS
------------------------
BACstac learns the device's address from the *packet*, not from the I-Am
payload. Send the I-Am from the edge's own IP and BACstac will bind
device:702193 to the helper's address -- the handshake passes, and then every
ReadProperty goes to the helper instead of the controller. Collection stays
broken, now with a confusing success at the handshake stage.

So the I-Am must appear to come from `<device-ip>:47808`. That is why this tool
uses the repo's usual raw-socket TX (`IPPROTO_RAW` + `IP_HDRINCL`, see
`bacnet_wire.build_ip_udp`): it writes the IP header by hand, so the source
address is ours to choose, and it bypasses the UDP bind table so it coexists
with BACstac already holding 47808.

THE OTHER TRAP: FIELD ACCURACY
------------------------------
An I-Am advertises `max-apdu-length-accepted` and `segmentation-supported`, and
BACstac believes them. Guess them high and it will send oversize or segmented
requests the device silently drops -- you trade a clean handshake failure for an
intermittent, much harder bug. Since ReadProperty *does* work, read the real
values off the device first and forge an accurate I-Am:

    bacread_multi.py <ip> 8:<inst>:75 8:<inst>:62 8:<inst>:107 8:<inst>:120
                              |          |           |            |
                   object-identifier     |           |        vendor-id
                        max-apdu-length-accepted     |
                                     segmentation-supported

If a field cannot be read, prefer the conservative BACnet floor -- max-apdu 480
and segmentation 3 (none) -- over an optimistic guess. Every conformant device
accepts small unsegmented requests, so the worst case is slower polling rather
than silent drops.

DELIVERY
--------
The forged packet is sent to the IP that BACstac is bound to (see
`bacnet_wire.detect_bacstac_ip`, which reads `/proc/net/udp`). Destined for one
of the box's own addresses, it is routed over `lo` and delivered up the local
stack.

Reverse-path filtering is the thing to check if this ever stops working, since
the source address is by definition not reachable via the interface the packet
arrives on. Measured on the EnOS EdgeExtensive x86 image: `all.rp_filter=1`,
`lo.rp_filter=0`, and local delivery went through unmodified -- no sysctl change
was needed. On a host where it does not, `net.ipv4.conf.all.rp_filter=0` is the
lever, and `SOCK_RAW` + `IPPROTO_UDP` on the RX side will show whether the
packet is landing at all.

PERSISTENCE: ONE I-Am IS ENOUGH
-------------------------------
BACstac caches the address binding and does not re-resolve while the device
keeps answering. Measured: the collect was still pushing 1536 points/min 2.5
minutes after the sender stopped. So do NOT run this on a timer -- a periodic
resend is pure noise.

Exactly three things lose the binding and need a new I-Am:

    * edge reboot
    * edge-dpf / BACstac restart
    * collect republish from the portal

All three surface as the same `ResolveDeviceID failed` log line, which is why
the companion daemon watches for that line instead of trying to enumerate the
causes. See `iam_watch.py` and `bacnet-iam-helper.service` -- that is what you
want for unattended use; this script is the manual one-shot and the reference
implementation of the packet.

THE DAEMON'S SAFETY GUARD
-------------------------
`iam_watch.py` proves the device is alive with a unicast ReadProperty of its
object-identifier *before* forging anything, and sends nothing if that fails.
This matters more than it looks: without the guard, a genuinely dead controller
would be handed a fake binding, and the collect would grind out read errors
forever instead of reporting a clean "device unreachable". You would be trading
a visible fault for an invisible one, which is the alarm-masking failure mode.
Keep the guard.

CASE STUDY (measured 2026-11-03, PDD_EE_Active_CC1, eu2)
--------------------------------------------------------
Device    10.138.0.193:47808, device:702193
Identity  model-name `IN-BAC-MBM`, object-name `CC2-BAS-DDC-B2-56-2`, vendor 246
Fields    max-apdu 1476, segmentation 0 (both)
Fronting  10 solar/HT meters, all sharing device instance 702193
Symptom   `ResolveDeviceID failed` looping since the collect was published;
          40 packets out, 0 replies; unicast Who-Is discovered 0 devices;
          ReadProperty of all four device properties succeeded
Not the   Two sibling collects published in the same batch were healthy
cause     (10.130.0.211 on-subnet, 10.139.0.180 off-subnet via 10.130.0.1), so
          routing, broadcast scope and BBMD config were all ruled out -- the
          fault was this firmware alone
Result    forged I-Am accepted; COV subscriptions completed; collect went to
          1710 points/min, 0 failed

USAGE
-----
One-shot, after reading the real fields off the device:

    python3 fake_iam.py --dev-ip 10.138.0.193 --inst 702193 \\
        --max-apdu 1476 --seg 0 --vendor 246 --stack-ip 10.130.1.196

`--interval N` resends every N seconds, which is useful only to guarantee
overlap with BACstac's ~6s resolve window while testing by hand; for production
use the daemon.

Requires `CAP_NET_RAW` -- run as root.
"""
import argparse, random, socket, struct, sys, time


def inet_sum(buf):
    if len(buf) % 2:
        buf += b'\x00'
    s = 0
    for i in range(0, len(buf), 2):
        s += (buf[i] << 8) | buf[i + 1]
    while s >> 16:
        s = (s & 0xFFFF) + (s >> 16)
    return (~s) & 0xFFFF


def build_ip_udp(src_ip, src_port, dst_ip, dst_port, payload):
    """Hand-rolled IP+UDP so the source address can be chosen freely.

    Kept local rather than imported from bacnet_wire so this file stays a
    self-contained reference for the forged packet.
    """
    udp_len = 8 + len(payload)
    ip_hdr = struct.pack('!BBHHHBBH4s4s', 0x45, 0, 20 + udp_len,
                         random.randint(0, 0xFFFF), 0x4000, 64, 17, 0,
                         socket.inet_aton(src_ip), socket.inet_aton(dst_ip))
    ip_hdr = ip_hdr[:10] + struct.pack('!H', inet_sum(ip_hdr)) + ip_hdr[12:]
    pseudo = (socket.inet_aton(src_ip) + socket.inet_aton(dst_ip)
              + b'\x00\x11' + struct.pack('!H', udp_len))
    csum = inet_sum(pseudo + struct.pack('!HHHH', src_port, dst_port, udp_len, 0) + payload)
    if csum == 0:
        csum = 0xFFFF
    return ip_hdr + struct.pack('!HHHH', src_port, dst_port, udp_len, csum) + payload


def enc_uint(val):
    """Application-tagged Unsigned (tag 2), shortest encoding that fits."""
    if val < 0x100:
        return bytes([0x21, val])
    if val < 0x10000:
        return bytes([0x22]) + struct.pack('!H', val)
    return bytes([0x24]) + struct.pack('!I', val)


def build_iam(dev_inst, max_apdu, seg, vendor, broadcast=True):
    """An I-Am APDU wrapped in NPDU + BVLL, ready to put on the wire.

    The four parameters are the entire payload of an I-Am, in order, per
    Clause 16.10.1. Example for device:702193, 1476, both, vendor 246:

        810b 0014                    BVLL: Original-Broadcast-NPDU, len 20
        01 00                        NPDU: version 1, control 0 (no routing)
        10 00                        APDU: Unconfirmed-Request, service 0 = i-Am
        c4 020ab6f1                  ObjectIdentifier (8 << 22) | 702193
        22 05c4                       Unsigned  1476
        91 00                         Enumerated 0 = segmented-both
        21 f6                         Unsigned  246
    """
    apdu = bytes([0x10, 0x00])
    apdu += bytes([0xC4]) + struct.pack('!I', (8 << 22) | dev_inst)
    apdu += enc_uint(max_apdu)
    apdu += bytes([0x91, seg])
    apdu += enc_uint(vendor)
    body = bytes([0x01, 0x00]) + apdu
    # Original-Broadcast-NPDU is what a real device would emit for an I-Am;
    # Original-Unicast-NPDU also resolves, and --unicast selects it.
    fn = 0x0B if broadcast else 0x0A
    return bytes([0x81, fn]) + struct.pack('!H', 4 + len(body)) + body


def main():
    p = argparse.ArgumentParser(description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument('--dev-ip', required=True, help="real device IP; forged as the I-Am source")
    p.add_argument('--dev-port', type=int, default=47808)
    p.add_argument('--inst', type=int, required=True, help="device object instance")
    p.add_argument('--max-apdu', type=int, default=1476, help="read from prop 62")
    p.add_argument('--seg', type=int, default=0, help="prop 107: 0=both 1=tx 2=rx 3=none")
    p.add_argument('--vendor', type=int, default=0, help="read from prop 120")
    p.add_argument('--stack-ip', required=True, help="IP the local BACstac is bound to")
    p.add_argument('--stack-port', type=int, default=47808)
    p.add_argument('--unicast', action='store_true',
                   help="send as Original-Unicast-NPDU instead of Original-Broadcast-NPDU")
    p.add_argument('--interval', type=float, default=0,
                   help="resend every N seconds (0 = send once and exit)")
    a = p.parse_args()

    pdu = build_iam(a.inst, a.max_apdu, a.seg, a.vendor, broadcast=not a.unicast)
    pkt = build_ip_udp(a.dev_ip, a.dev_port, a.stack_ip, a.stack_port, pdu)

    tx = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
    tx.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)

    kind = 'unicast' if a.unicast else 'broadcast'
    print("I-Am device:%d max_apdu=%d seg=%d vendor=%d  (%s, %d byte BVLL)"
          % (a.inst, a.max_apdu, a.seg, a.vendor, kind, len(pdu)))
    print("   %s:%d  =>  %s:%d   [source address forged]"
          % (a.dev_ip, a.dev_port, a.stack_ip, a.stack_port))
    print("   pdu: %s" % pdu.hex())

    n = 0
    while True:
        tx.sendto(pkt, (a.stack_ip, 0))
        n += 1
        if a.interval <= 0:
            print("sent 1")
            return
        if n % 10 == 1:
            print("sent %d (every %.1fs)" % (n, a.interval), flush=True)
        time.sleep(a.interval)


if __name__ == '__main__':
    main()

#!/usr/bin/env python3
"""Full BACnet autosearch — Who-Is broadcast + per-device object-list walk.

Concurrency: one worker thread per IP. MS/TP behind a BACnet router is a
single token-ring, so devices sharing a router IP must serialize; different
router IPs run in parallel up to --workers.

Output is JSONL, one device per line, flushed after each device (crash-safe).
"""
import os, sys, time, json, struct, socket, argparse, threading
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from bacnet_wire import (
    Reader, build_ip_udp, build_whois, extract_apdu, parse_iam,
    parse_readprop_ack,
    BAC_PORT, OBJ_DEVICE, PROP_OBJECT_LIST, PROP_OBJECT_NAME,
    resolve_src_and_bcast,
)

def discover(src_ip, src_port, bcast_ip, bcast_port, window):
    pkt = build_ip_udp(src_ip, src_port, bcast_ip, bcast_port, build_whois())
    tx = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
    tx.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
    tx.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
    rx = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_UDP)
    rx.settimeout(0.5)
    tx.sendto(pkt, (bcast_ip, 0))
    devices = {}
    deadline = time.time() + window
    while time.time() < deadline:
        try:
            data, _ = rx.recvfrom(65535)
        except socket.timeout:
            continue
        if len(data) < 28: continue
        ihl  = (data[0] & 0x0F) * 4
        s_ip = socket.inet_ntoa(data[12:16])
        udp  = data[ihl:]
        if len(udp) < 8: continue
        sp, dp, ulen, _ = struct.unpack('!HHHH', udp[:8])
        if dp != src_port: continue
        if s_ip == src_ip and sp == src_port: continue
        apdu, snet, sadr = extract_apdu(udp[8:ulen])
        if apdu is None: continue
        info = parse_iam(apdu)
        if info is None: continue
        info['ip'] = s_ip; info['port'] = sp
        info['snet'] = snet; info['sadr'] = sadr
        if info['device_instance'] not in devices:
            devices[info['device_instance']] = info
    for s in (tx, rx):
        try: s.close()
        except OSError: pass
    return devices

def enumerate_device(reader, dev, want_names, rate):
    inst, ip, port = dev['device_instance'], dev['ip'], dev['port']
    dnet, dadr = dev['snet'], dev['sadr']
    base = {'device': inst, 'ip': ip, 'port': port, 'snet': dnet,
            'sadr': dadr.hex() if dadr else None}
    started = time.time()

    apdu = reader.read(ip, port, OBJ_DEVICE, inst, PROP_OBJECT_LIST,
                       array_index=0, dnet=dnet, dadr=dadr)
    if apdu is None:
        return {**base, 'status': 'no-reply-count', 'object_count': 0,
                'objects': [], 'elapsed': round(time.time()-started, 2)}
    try:
        vals = parse_readprop_ack(apdu)
    except RuntimeError as e:
        return {**base, 'status': f'error-count:{e}', 'object_count': 0,
                'objects': [], 'elapsed': round(time.time()-started, 2)}
    if not vals or vals[0][0] != 'uint':
        return {**base, 'status': f'bad-count:{vals!r}', 'object_count': 0,
                'objects': [], 'elapsed': round(time.time()-started, 2)}
    count = vals[0][1]

    objs = []; errs = 0
    for i in range(1, count + 1):
        time.sleep(rate)
        apdu = reader.read(ip, port, OBJ_DEVICE, inst, PROP_OBJECT_LIST,
                           array_index=i, dnet=dnet, dadr=dadr)
        if apdu is None:
            errs += 1; objs.append({'index': i, 'error': 'timeout'}); continue
        try:
            vals = parse_readprop_ack(apdu)
        except RuntimeError as e:
            errs += 1; objs.append({'index': i, 'error': str(e)}); continue
        if not vals or vals[0][0] != 'oid':
            errs += 1; objs.append({'index': i, 'error': f'unexpected:{vals!r}'}); continue
        ot, oi = vals[0][1]
        name = None
        if want_names:
            time.sleep(rate)
            apdu2 = reader.read(ip, port, ot, oi, PROP_OBJECT_NAME, dnet=dnet, dadr=dadr)
            if apdu2 is not None:
                try:
                    v2 = parse_readprop_ack(apdu2)
                    if v2 and v2[0][0] == 'string':
                        name = v2[0][1]
                except RuntimeError:
                    pass
        objs.append({'type': ot, 'instance': oi, 'name': name})

    return {**base,
            'status': 'ok' if errs == 0 else f'partial:{errs}-errors',
            'object_count': count, 'objects': objs,
            'elapsed': round(time.time()-started, 2)}

def load_cache(path):
    """Load cache from JSONL file. Returns (meta_dict, {device_instance: record})."""
    try:
        with open(path) as fh:
            first = fh.readline().strip()
            if not first:
                return None, {}
            meta = json.loads(first)
            if not meta.get('_meta'):
                return None, {}
            records = {}
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                rec = json.loads(line)
                if rec.get('_meta'):
                    continue
                records[rec['device']] = rec
            return meta, records
    except (FileNotFoundError, json.JSONDecodeError, KeyError):
        return None, {}

def worker(ip, devs_for_ip, args, src_ip, write_lock, out_fh, progress):
    reader = Reader(src_ip, args.src_port, args.timeout)
    try:
        for dev in devs_for_ip:
            res = enumerate_device(reader, dev, args.name, args.rate)
            with write_lock:
                out_fh.write(json.dumps(res) + '\n'); out_fh.flush()
                progress[0] += 1
                done, total, t0 = progress[0], progress[1], progress[2]
                eta = (time.time() - t0) / done * (total - done) if done else 0
                sadr_hex = dev['sadr'].hex() if dev['sadr'] else ''
                route_tag = (f'r/{dev["snet"]}/{sadr_hex}'
                             if dev['snet'] is not None else 'direct')
                print(f'  [{done:>3}/{total}] dev {dev["device_instance"]:<7} '
                      f'{ip:<15} {route_tag:<14} {res["status"]:<22} '
                      f'objs={len([o for o in res["objects"] if "type" in o]):>4}/{res["object_count"]:<4}  '
                      f'{res["elapsed"]:>5.1f}s  ETA {eta/60:>4.1f}m', file=sys.stderr)
    finally:
        reader.close()

def main():
    ap = argparse.ArgumentParser(description='Full BACnet autosearch (Who-Is + per-device object-list).')
    ap.add_argument('--src-ip',     default=None)
    ap.add_argument('--src-port',   type=int, default=BAC_PORT)
    ap.add_argument('--bcast',      default=None)
    ap.add_argument('--bcast-port', type=int, default=BAC_PORT)
    ap.add_argument('--window',     type=float, default=8.0)
    ap.add_argument('--workers',    type=int, default=16)
    ap.add_argument('--name',       action='store_true')
    ap.add_argument('--rate',       type=float, default=0.03)
    ap.add_argument('--timeout',    type=float, default=5.0)
    ap.add_argument('--out',        default='/tmp/bac_autosearch.jsonl')
    ap.add_argument('--limit-devices',    type=int, default=None)
    ap.add_argument('--limit-per-router', type=int, default=None)
    ap.add_argument('--cache-max-age', type=float, default=3600,
                    help='max cache age in seconds (default 3600, 0=no expiry)')
    ap.add_argument('--no-cache', action='store_true',
                    help='ignore cache and force a fresh scan')
    args = ap.parse_args()

    src_ip, bcast = resolve_src_and_bcast(args.src_ip, args.bcast)

    print(f'[phase 1] Who-Is {src_ip}:{args.src_port} => {bcast}:{args.bcast_port} '
          f'(window={args.window}s)', file=sys.stderr)
    t0 = time.time()
    devices = discover(src_ip, args.src_port, bcast, args.bcast_port, args.window)
    print(f'          {len(devices)} devices in {time.time()-t0:.1f}s', file=sys.stderr)

    by_ip = defaultdict(list)
    for d in sorted(devices.values(), key=lambda x: x['device_instance']):
        by_ip[d['ip']].append(d)
    if args.limit_per_router:
        for ip in list(by_ip):
            by_ip[ip] = by_ip[ip][:args.limit_per_router]
    if args.limit_devices is not None:
        keep = args.limit_devices; new = defaultdict(list)
        for ip, devs in by_ip.items():
            for d in devs:
                if keep <= 0: break
                new[ip].append(d); keep -= 1
            if keep <= 0: break
        by_ip = new

    discovered_ids = set()
    for devs in by_ip.values():
        for d in devs:
            discovered_ids.add(d['device_instance'])

    # --- cache logic ---
    cached_meta, cached_records = (None, {}) if args.no_cache else load_cache(args.out)
    cache_mode = 'full'  # full | resume | hit

    if cached_meta is not None:
        age = time.time() - cached_meta.get('ts', 0)
        cached_ids = set(cached_records.keys())
        if args.cache_max_age > 0 and age > args.cache_max_age:
            print(f'[cache] stale ({age/60:.0f}m old > {args.cache_max_age/60:.0f}m max), '
                  f'doing fresh scan', file=sys.stderr)
        elif discovered_ids <= cached_ids:
            cache_mode = 'hit'
            print(f'[cache] complete hit — {len(cached_records)} devices, '
                  f'{age/60:.1f}m old', file=sys.stderr)
        else:
            cache_mode = 'resume'
            missing = discovered_ids - cached_ids
            print(f'[cache] partial — {len(cached_ids)} cached, '
                  f'{len(missing)} remaining', file=sys.stderr)

    if cache_mode == 'hit':
        # print cached results to stdout and exit
        for inst in sorted(discovered_ids):
            print(json.dumps(cached_records[inst]))
        print(f'\n[done] {len(cached_records)} devices from cache  -> {args.out}',
              file=sys.stderr)
        return

    if cache_mode == 'resume':
        # filter out already-cached devices
        for ip in list(by_ip):
            by_ip[ip] = [d for d in by_ip[ip]
                         if d['device_instance'] not in cached_records]
            if not by_ip[ip]:
                del by_ip[ip]

    total = sum(len(v) for v in by_ip.values())
    print(f'[phase 2] enumerate {total} devices across {len(by_ip)} router IPs, '
          f'{args.workers} workers, names={args.name}', file=sys.stderr)

    if cache_mode == 'full':
        open_mode = 'w'
    else:
        open_mode = 'a'

    write_lock = threading.Lock()
    progress = [0, total, time.time()]
    with open(args.out, open_mode) as out_fh:
        if cache_mode == 'full':
            meta = {'_meta': True, 'ts': time.time(), 'src_ip': src_ip,
                    'bcast': bcast, 'window': args.window}
            out_fh.write(json.dumps(meta) + '\n'); out_fh.flush()
        with ThreadPoolExecutor(max_workers=args.workers) as ex:
            futs = [ex.submit(worker, ip, devs, args, src_ip, write_lock, out_fh, progress)
                    for ip, devs in by_ip.items()]
            for f in as_completed(futs):
                exc = f.exception()
                if exc:
                    print(f'  worker exception: {exc!r}', file=sys.stderr)

    elapsed = time.time() - progress[2]
    total_objs = 0; ok = partial = bad = 0
    with open(args.out) as fh:
        for line in fh:
            rec = json.loads(line)
            if rec.get('_meta'):
                continue
            total_objs += len([o for o in rec['objects'] if 'type' in o])
            if   rec['status'] == 'ok':                 ok += 1
            elif rec['status'].startswith('partial:'):  partial += 1
            else:                                       bad += 1
    print(f'\n[done] {progress[0]} devices in {elapsed/60:.1f}m  '
          f'ok={ok} partial={partial} failed={bad}  total_objects={total_objs}  '
          f'-> {args.out}', file=sys.stderr)

if __name__ == '__main__':
    main()

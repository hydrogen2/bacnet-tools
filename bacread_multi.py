#!/usr/bin/env python3
"""Batch BACnet ReadProperty — fire all requests, then collect responses."""
import os, sys, time, struct, socket, random, argparse, json
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from bacnet_wire import (
    Reader, build_readprop, build_ip_udp, extract_apdu,
    parse_readprop_ack, BAC_PORT, resolve_src_and_bcast,
)

def batch_read(reader, dst_ip, dst_port, requests, dnet=None, dadr=None):
    """Send all requests at once, then collect responses by invoke ID.

    requests: list of (obj_type, obj_instance, prop_id, label)
    Returns: [(label, values_or_None), ...] in same order as requests.
    """
    invoke_to_idx = {}
    for i, (obj_type, obj_inst, prop_id, _label) in enumerate(requests):
        invoke_id = random.randint(1, 254)
        while invoke_id in invoke_to_idx:
            invoke_id = random.randint(1, 254)
        pkt = build_readprop(obj_type, obj_inst, prop_id, invoke_id,
                             dnet=dnet, dadr=dadr)
        reader.send(dst_ip, dst_port, pkt)
        invoke_to_idx[invoke_id] = i

    apdus = [None] * len(requests)
    remaining = len(requests)
    deadline = time.time() + reader.timeout
    while remaining > 0 and time.time() < deadline:
        try:
            data, _ = reader.rx.recvfrom(65535)
        except socket.timeout:
            continue
        if len(data) < 28:
            continue
        ihl = (data[0] & 0x0F) * 4
        s_ip = socket.inet_ntoa(data[12:16])
        udp = data[ihl:]
        if len(udp) < 8:
            continue
        sp, dp, ulen, _ = struct.unpack('!HHHH', udp[:8])
        if not (s_ip == dst_ip and sp == dst_port and dp == reader.src_port):
            continue
        apdu, _, _ = extract_apdu(udp[8:ulen])
        if apdu is None or len(apdu) < 3:
            continue
        inv = apdu[1]
        if inv in invoke_to_idx and apdus[invoke_to_idx[inv]] is None:
            apdus[invoke_to_idx[inv]] = apdu
            remaining -= 1

    results = []
    for i, (_, _, _, label) in enumerate(requests):
        if apdus[i] is None:
            results.append((label, None))
        else:
            try:
                results.append((label, parse_readprop_ack(apdus[i])))
            except RuntimeError as e:
                results.append((label, f'error:{e}'))
    return results

def main():
    ap = argparse.ArgumentParser(
        description='Batch BACnet ReadProperty — read multiple points in one shot.',
        epilog='Example: bacread_multi.py 192.168.67.5 0:608:85:CHWP1_Hz 0:610:85:CHWP2_Hz')
    ap.add_argument('target', help='ip[:port] of the device or its router')
    ap.add_argument('points', nargs='+',
                    help='obj_type:obj_instance:prop_id[:label]')
    ap.add_argument('--dnet', type=int, default=None)
    ap.add_argument('--dadr', default=None)
    ap.add_argument('--src-ip', default=None)
    ap.add_argument('--src-port', type=int, default=BAC_PORT)
    ap.add_argument('--timeout', type=float, default=5.0)
    ap.add_argument('--json', action='store_true', help='output as JSON')
    args = ap.parse_args()

    src_ip, _ = resolve_src_and_bcast(args.src_ip, None)
    if ':' in args.target:
        dst_ip, dst_port = args.target.rsplit(':', 1)
        dst_port = int(dst_port)
    else:
        dst_ip, dst_port = args.target, BAC_PORT
    dadr = bytes.fromhex(args.dadr) if args.dadr else None

    requests = []
    for p in args.points:
        parts = p.split(':')
        obj_type, obj_inst, prop_id = int(parts[0]), int(parts[1]), int(parts[2])
        label = parts[3] if len(parts) > 3 else f'AI:{obj_inst}'
        requests.append((obj_type, obj_inst, prop_id, label))

    r = Reader(src_ip, args.src_port, args.timeout)
    try:
        t0 = time.time()
        results = batch_read(r, dst_ip, dst_port, requests,
                             dnet=args.dnet, dadr=dadr)
        elapsed = time.time() - t0
    finally:
        r.close()

    if args.json:
        out = []
        for label, vals in results:
            if vals is None:
                out.append({'label': label, 'value': None, 'error': 'timeout'})
            elif isinstance(vals, str):
                out.append({'label': label, 'value': None, 'error': vals})
            elif not vals:
                out.append({'label': label, 'value': [], 'type': None})
            elif len(vals) == 1:
                out.append({'label': label, 'value': vals[0][1], 'type': vals[0][0]})
            else:
                out.append({'label': label, 'value': [v for _, v in vals],
                            'type': [t for t, _ in vals]})
        print(json.dumps(out, indent=2))
    else:
        for label, vals in results:
            if vals is None:
                print(f'{label:<20} timeout')
            elif isinstance(vals, str):
                print(f'{label:<20} {vals}')
            elif not vals:
                print(f'{label:<20} <empty>')
            elif len(vals) == 1:
                print(f'{label:<20} {vals[0][1]}')
            else:
                print(f'{label:<20} [{len(vals)}] {", ".join(repr(v) for _, v in vals)}')

    ok = sum(1 for _, v in results if v is not None and not isinstance(v, str))
    print(f'\n{ok}/{len(results)} in {elapsed:.2f}s', file=sys.stderr)

if __name__ == '__main__':
    main()

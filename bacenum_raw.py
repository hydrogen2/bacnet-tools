#!/usr/bin/env python3
"""BACnet object-list enumeration for a single device (step 2 of autosearch).

Walks object-list one index at a time — universal across vendors and works
regardless of segmentation support (each response is ~40 bytes).
"""
import os, sys, time, argparse
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from bacnet_wire import (
    Reader, parse_readprop_ack, OBJ_TYPE_NAMES,
    OBJ_DEVICE, PROP_OBJECT_LIST, PROP_OBJECT_NAME, BAC_PORT,
    resolve_src_and_bcast,
)

def fmt_obj(ot, oi):
    return f'{OBJ_TYPE_NAMES.get(ot, f"T{ot}")}:{oi}'

def main():
    ap = argparse.ArgumentParser(description="Walk one device's object-list")
    ap.add_argument('target', help='ip[:port] of the device or its router')
    ap.add_argument('device_instance', type=int)
    ap.add_argument('--dnet', type=int, default=None)
    ap.add_argument('--dadr', default=None)
    ap.add_argument('--name', action='store_true', help='also read object-name')
    ap.add_argument('--rate',    type=float, default=0.03)
    ap.add_argument('--timeout', type=float, default=3.0)
    ap.add_argument('--limit',   type=int,   default=None, help='cap object count (debug)')
    ap.add_argument('--src-ip',   default=None)
    ap.add_argument('--src-port', type=int, default=BAC_PORT)
    args = ap.parse_args()

    src_ip, _ = resolve_src_and_bcast(args.src_ip, None)

    if ':' in args.target:
        dst_ip, dst_port = args.target.split(':', 1); dst_port = int(dst_port)
    else:
        dst_ip, dst_port = args.target, BAC_PORT
    dadr = bytes.fromhex(args.dadr) if args.dadr else None

    route = f' via DNET={args.dnet} DADR={args.dadr}' if args.dnet is not None else ''
    print(f'=> Device:{args.device_instance} @ {dst_ip}:{dst_port}{route}', file=sys.stderr)

    r = Reader(src_ip, args.src_port, args.timeout)
    try:
        apdu = r.read(dst_ip, dst_port, OBJ_DEVICE, args.device_instance,
                      PROP_OBJECT_LIST, array_index=0, dnet=args.dnet, dadr=dadr)
        if apdu is None:
            print('no reply to object-list[0]; check reachability / DNET-DADR', file=sys.stderr)
            sys.exit(1)
        vals = parse_readprop_ack(apdu)
        if not vals or vals[0][0] != 'uint':
            print(f'unexpected count response: {vals}', file=sys.stderr); sys.exit(1)
        count = vals[0][1]
        todo  = min(count, args.limit) if args.limit else count
        print(f'   object-list count = {count}'
              + (f' (reading first {todo})' if todo < count else ''), file=sys.stderr)

        objects = []; errors = 0
        start = time.time()
        for i in range(1, todo + 1):
            time.sleep(args.rate)
            apdu = r.read(dst_ip, dst_port, OBJ_DEVICE, args.device_instance,
                          PROP_OBJECT_LIST, array_index=i, dnet=args.dnet, dadr=dadr)
            if apdu is None:
                errors += 1; print(f'  [{i:>4}] (timeout)', file=sys.stderr); continue
            try:
                vals = parse_readprop_ack(apdu)
            except RuntimeError as e:
                errors += 1; print(f'  [{i:>4}] error: {e}', file=sys.stderr); continue
            if not vals or vals[0][0] != 'oid':
                errors += 1; print(f'  [{i:>4}] unexpected: {vals}', file=sys.stderr); continue
            ot, oi = vals[0][1]
            name = ''
            if args.name:
                time.sleep(args.rate)
                apdu2 = r.read(dst_ip, dst_port, ot, oi, PROP_OBJECT_NAME,
                               dnet=args.dnet, dadr=dadr)
                if apdu2 is not None:
                    try:
                        v2 = parse_readprop_ack(apdu2)
                        if v2 and v2[0][0] == 'string':
                            name = v2[0][1]
                    except RuntimeError:
                        pass
            objects.append((ot, oi, name))
            print(f'  [{i:>4}] {fmt_obj(ot, oi)}' + (f"  {name!r}" if name else ''))

        print(f'\nfound {len(objects)}/{todo} objects in {time.time()-start:.1f}s '
              f'({errors} errors)', file=sys.stderr)
    finally:
        r.close()

if __name__ == '__main__':
    main()

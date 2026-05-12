#!/usr/bin/env python3
"""BACnet/IP ReadProperty via raw sockets.

Sends one ReadProperty request and decodes the ComplexACK. Coexists with a
local BACstac daemon owning UDP/47808.
"""
import os, sys, argparse
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from bacnet_wire import Reader, parse_readprop_ack, BAC_PORT, resolve_src_and_bcast

def main():
    ap = argparse.ArgumentParser(description='BACnet ReadProperty via raw sockets')
    ap.add_argument('target', help='ip[:port] of the device or its router')
    ap.add_argument('object_type', type=int)
    ap.add_argument('object_instance', type=int)
    ap.add_argument('property_id', type=int)
    ap.add_argument('--index', type=int, default=None, help='property array index')
    ap.add_argument('--dnet', type=int, default=None, help='dest network (routed devices)')
    ap.add_argument('--dadr', default=None, help='dest MAC, hex (routed devices)')
    ap.add_argument('--src-ip',   default=None, help='source IP (default: auto-detect)')
    ap.add_argument('--src-port', type=int, default=BAC_PORT)
    ap.add_argument('--timeout',  type=float, default=6.0)
    args = ap.parse_args()

    src_ip, _ = resolve_src_and_bcast(args.src_ip, None)

    if ':' in args.target:
        dst_ip, dst_port = args.target.split(':', 1); dst_port = int(dst_port)
    else:
        dst_ip, dst_port = args.target, BAC_PORT
    dadr = bytes.fromhex(args.dadr) if args.dadr else None
    route = f'  routed DNET={args.dnet} DADR={args.dadr}' if args.dnet is not None else ''
    print(f'-> {src_ip}:{args.src_port} => {dst_ip}:{dst_port}{route}', file=sys.stderr)

    r = Reader(src_ip, args.src_port, args.timeout)
    try:
        apdu = r.read(dst_ip, dst_port, args.object_type, args.object_instance,
                      args.property_id, array_index=args.index,
                      dnet=args.dnet, dadr=dadr)
        if apdu is None:
            print('no reply within deadline', file=sys.stderr); sys.exit(1)
        try:
            print('RESULT:', parse_readprop_ack(apdu))
        except RuntimeError as e:
            print('decode failed:', e, file=sys.stderr); sys.exit(1)
    finally:
        r.close()

if __name__ == '__main__':
    main()

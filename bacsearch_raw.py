#!/usr/bin/env python3
"""BACnet Who-Is autosearch — broadcast and collect I-Am replies.

Step 1 of the autosearch toolchain. Coexists with a local BACstac daemon.
"""
import os, sys, time, struct, socket, argparse
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from bacnet_wire import (
    build_whois, build_ip_udp, extract_apdu, parse_iam,
    SEG_NAMES, BAC_PORT, resolve_src_and_bcast,
)

def main():
    ap = argparse.ArgumentParser(
        description='BACnet Who-Is broadcast + I-Am collector',
        epilog='Routed mode: pass --dnet N --router IP to send Who-Is via a '
               'router into BACnet network N. I-Am replies come back unicast '
               'through the router.')
    ap.add_argument('low',  type=int, nargs='?', default=None, help='low device-instance')
    ap.add_argument('high', type=int, nargs='?', default=None, help='high device-instance')
    ap.add_argument('--src-ip',     default=None, help='default: auto-detect')
    ap.add_argument('--src-port',   type=int, default=BAC_PORT)
    ap.add_argument('--bcast',      default=None, help='default: /24 of src-ip')
    ap.add_argument('--bcast-port', type=int, default=BAC_PORT)
    ap.add_argument('--window',     type=float, default=5.0, help='collection seconds')
    ap.add_argument('--dnet',       type=int, default=None,
                    help='routed Who-Is: destination BACnet network number')
    ap.add_argument('--dadr',       default=None,
                    help='routed Who-Is: unicast MAC on dnet (hex); default = broadcast on dnet')
    ap.add_argument('--router',     default=None,
                    help='routed Who-Is: router IP (required with --dnet)')
    args = ap.parse_args()

    src_ip, bcast = resolve_src_and_bcast(args.src_ip, args.bcast)
    if args.dnet is not None:
        if not args.router:
            ap.error('--dnet requires --router IP')
        dst_ip = args.router
        dadr = bytes.fromhex(args.dadr) if args.dadr else None
        whois = build_whois(args.low, args.high, dnet=args.dnet, dadr=dadr)
    else:
        dst_ip = bcast
        whois = build_whois(args.low, args.high)
    pkt = build_ip_udp(src_ip, args.src_port, dst_ip, args.bcast_port, whois)

    tx = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
    tx.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
    tx.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
    rx = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_UDP)
    rx.settimeout(0.5)

    bounds = f'[{args.low},{args.high}]' if args.low is not None else '[any]'
    route = f' DNET={args.dnet}' + (f' DADR=0x{args.dadr}' if args.dadr else '') if args.dnet is not None else ''
    print(f'-> Who-Is {bounds}{route}  {src_ip}:{args.src_port} => {dst_ip}:{args.bcast_port}  '
          f'window={args.window}s', file=sys.stderr)
    tx.sendto(pkt, (dst_ip, 0))

    devices = {}
    deadline = time.time() + args.window
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
        if dp != args.src_port: continue
        if s_ip == src_ip and sp == args.src_port: continue
        apdu, snet, sadr = extract_apdu(udp[8:ulen])
        if apdu is None: continue
        info = parse_iam(apdu)
        if info is None: continue
        info['ip'] = s_ip; info['port'] = sp
        info['snet'] = snet; info['sadr'] = sadr
        inst = info['device_instance']
        if inst not in devices:
            devices[inst] = info
            route = f'  via SNET={snet} SADR={sadr.hex()}' if snet is not None else ''
            print(f"  + dev {inst:<7} {s_ip}:{sp}  max={info['max_apdu']}  "
                  f"seg={SEG_NAMES.get(info['segmentation'], info['segmentation'])}  "
                  f"vendor={info['vendor_id']}{route}", file=sys.stderr)

    for s in (tx, rx):
        try: s.close()
        except OSError: pass

    print(f'\ndiscovered {len(devices)} device(s):')
    for inst in sorted(devices):
        d = devices[inst]
        sadr_str = f' sadr={d["sadr"].hex()}' if d['sadr'] else ''
        route = f' snet={d["snet"]}{sadr_str}' if d['snet'] is not None else ''
        print(f'  device_instance={inst:<7} ip={d["ip"]:<15} port={d["port"]} '
              f'max_apdu={d["max_apdu"]} seg={SEG_NAMES.get(d["segmentation"], d["segmentation"])} '
              f'vendor_id={d["vendor_id"]}{route}')

if __name__ == '__main__':
    main()

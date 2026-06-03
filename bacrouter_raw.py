#!/usr/bin/env python3
"""BACnet Who-Is-Router-To-Network — discover BACnet/IP routers and the
network numbers they route to.

Network-Layer Message (NLM); unaffected by Tridium-style Who-Is debounce
which only suppresses Unconfirmed-Request Who-Is at the APDU layer.

Receives via AF_PACKET because I-Am-Router-To-Network replies are sent to
the IP broadcast address, and SOCK_RAW + IPPROTO_UDP does not reliably
deliver broadcast-destination UDP datagrams.
"""
import os, sys, time, struct, socket, argparse
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from bacnet_wire import (
    build_ip_udp, build_whois_router_to_network,
    BAC_PORT, resolve_src_and_bcast,
)

def main():
    ap = argparse.ArgumentParser(
        description='BACnet Who-Is-Router-To-Network probe')
    ap.add_argument('--src-ip',     default=None, help='default: auto-detect')
    ap.add_argument('--src-port',   type=int, default=BAC_PORT)
    ap.add_argument('--bcast',      default=None, help='default: /24 of src-ip')
    ap.add_argument('--bcast-port', type=int, default=BAC_PORT)
    ap.add_argument('--iface',      default=None,
                    help='AF_PACKET capture interface; default: auto-pick by --src-ip')
    ap.add_argument('--dnet',       type=int, default=None,
                    help='ask about a specific BACnet network (default: all)')
    ap.add_argument('--window',     type=float, default=6.0, help='collection seconds')
    args = ap.parse_args()

    src_ip, bcast = resolve_src_and_bcast(args.src_ip, args.bcast)
    iface = args.iface or _iface_for_ip(src_ip)
    if not iface:
        print(f'error: cannot determine interface for src-ip {src_ip}; pass --iface',
              file=sys.stderr)
        sys.exit(2)

    bvlc = build_whois_router_to_network(dnet=args.dnet)
    pkt  = build_ip_udp(src_ip, args.src_port, bcast, args.bcast_port, bvlc)

    tx = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
    tx.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
    tx.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
    ETH_P_ALL = 0x0003
    rx = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(ETH_P_ALL))
    rx.bind((iface, 0))
    rx.settimeout(0.3)

    target = f'DNET={args.dnet}' if args.dnet is not None else 'any'
    print(f'-> Who-Is-Router-To-Network ({target})  '
          f'{src_ip}:{args.src_port} => {bcast}:{args.bcast_port}  '
          f'iface={iface} window={args.window}s', file=sys.stderr)
    tx.sendto(pkt, (bcast, 0))

    routers = {}  # ip -> set of network ids
    deadline = time.time() + args.window
    while time.time() < deadline:
        try:
            frame, _ = rx.recvfrom(65535)
        except socket.timeout:
            continue
        parsed = _parse_iam_router(frame, src_ip, args.src_port)
        if parsed is None:
            continue
        ip, nets = parsed
        new = nets - routers.get(ip, set())
        if new:
            routers.setdefault(ip, set()).update(nets)
            print(f'  + router {ip}  routes networks: '
                  f'{", ".join(str(n) for n in sorted(nets))}', file=sys.stderr)

    for s in (tx, rx):
        try: s.close()
        except OSError: pass

    print(f'\ndiscovered {len(routers)} router(s):')
    for ip, nets in routers.items():
        print(f'  {ip:<15}  networks: {", ".join(str(n) for n in sorted(nets))}')

def _iface_for_ip(ip):
    """Return the interface name whose IPv4 address matches `ip`."""
    try:
        import subprocess
        r = subprocess.run(['ip', '-o', '-4', 'addr'],
                           capture_output=True, text=True, check=False)
        for line in r.stdout.splitlines():
            parts = line.split()
            if len(parts) >= 4 and parts[3].split('/')[0] == ip:
                return parts[1]
    except Exception:
        pass
    return None

def _parse_iam_router(frame, our_src_ip, our_src_port):
    """Return (router_ip, set_of_networks) for an I-Am-Router-To-Network
    NLM in the given Ethernet frame, or None if the frame isn't one."""
    if len(frame) < 14 + 20 + 8:
        return None
    if struct.unpack('>H', frame[12:14])[0] != 0x0800:
        return None
    ip = frame[14:]
    if (ip[0] >> 4) != 4 or ip[9] != 17:  # not IPv4 UDP
        return None
    ihl = (ip[0] & 0x0F) * 4
    s_ip = socket.inet_ntoa(ip[12:16])
    if s_ip == our_src_ip:
        return None
    udp = ip[ihl:]
    if len(udp) < 8:
        return None
    sp, dp, ulen, _ = struct.unpack('!HHHH', udp[:8])
    if sp != BAC_PORT or dp != our_src_port:
        return None
    payload = udp[8:ulen]
    if len(payload) < 4 or payload[0] != 0x81:
        return None
    func = payload[1]
    if func not in (0x0A, 0x0B, 0x04):
        return None
    off = 4
    if func == 0x04:
        off += 6  # forwarded BBMD originator
    npdu = payload[off:]
    if len(npdu) < 3 or (npdu[1] & 0x80) == 0:
        return None
    pos = 2
    if npdu[1] & 0x20:
        pos += 2  # DNET
        if pos >= len(npdu):
            return None
        dlen = npdu[pos]; pos += 1 + dlen
    if npdu[1] & 0x08:
        pos += 2  # SNET
        if pos >= len(npdu):
            return None
        slen = npdu[pos]; pos += 1 + slen
        pos += 1  # hop
    if pos >= len(npdu):
        return None
    msg_type = npdu[pos]; pos += 1
    if msg_type != 0x01:  # only I-Am-Router-To-Network
        return None
    nets = set()
    while pos + 1 < len(npdu):
        nets.add(struct.unpack_from('>H', npdu, pos)[0])
        pos += 2
    return s_ip, nets

if __name__ == '__main__':
    main()

#!/usr/bin/env python3
"""BACnet/IP ReadProperty via raw sockets.

Sidesteps the local port 47808 bind conflict with the Cimetrics BACstac daemon.
We send an IP packet with source IP/port chosen freely, and receive replies
via a raw IPPROTO_UDP socket — kernel UDP demux still delivers a copy to
bacstac, but raw sockets get their own copy.
"""
import os, socket, struct, sys, time, random

def inet_sum(buf: bytes) -> int:
    if len(buf) % 2: buf += b'\x00'
    s = 0
    for i in range(0, len(buf), 2):
        s += (buf[i] << 8) | buf[i+1]
    while s >> 16: s = (s & 0xFFFF) + (s >> 16)
    return (~s) & 0xFFFF

def build_ip_udp(src_ip: str, src_port: int, dst_ip: str, dst_port: int, payload: bytes) -> bytes:
    udp_len = 8 + len(payload)
    ip_total = 20 + udp_len
    ip_id = random.randint(0, 0xFFFF)
    ip_hdr = struct.pack('!BBHHHBBH4s4s',
        0x45, 0, ip_total, ip_id, 0x4000, 64, 17, 0,
        socket.inet_aton(src_ip), socket.inet_aton(dst_ip))
    ip_hdr = ip_hdr[:10] + struct.pack('!H', inet_sum(ip_hdr)) + ip_hdr[12:]
    # UDP checksum (with pseudo header)
    udp_hdr_nocsum = struct.pack('!HHHH', src_port, dst_port, udp_len, 0)
    pseudo = socket.inet_aton(src_ip) + socket.inet_aton(dst_ip) + b'\x00\x11' + struct.pack('!H', udp_len)
    csum = inet_sum(pseudo + udp_hdr_nocsum + payload)
    if csum == 0: csum = 0xFFFF
    udp_hdr = struct.pack('!HHHH', src_port, dst_port, udp_len, csum)
    return ip_hdr + udp_hdr + payload

def build_readprop(obj_type: int, obj_inst: int, prop_id: int, invoke_id: int) -> bytes:
    apdu = bytearray()
    apdu += bytes([0x00, 0x05, invoke_id & 0xFF, 0x0C])
    oid = ((obj_type & 0x3FF) << 22) | (obj_inst & 0x3FFFFF)
    apdu += bytes([0x0C]) + struct.pack('>I', oid)
    if prop_id < 256:
        apdu += bytes([0x19, prop_id])
    else:
        apdu += bytes([0x1A]) + struct.pack('>H', prop_id)
    npdu = bytes([0x01, 0x04])
    body = npdu + bytes(apdu)
    return bytes([0x81, 0x0A]) + struct.pack('>H', 4 + len(body)) + body

def parse_tag(buf, pos):
    t = buf[pos]; pos += 1
    tn = t >> 4; tc = (t >> 3) & 1; lvt = t & 0x07
    if tn == 0x0F:
        tn = buf[pos]; pos += 1
    if lvt == 0x05:
        lvt = buf[pos]; pos += 1
        if lvt == 254:
            lvt = struct.unpack_from('>H', buf, pos)[0]; pos += 2
        elif lvt == 255:
            lvt = struct.unpack_from('>I', buf, pos)[0]; pos += 4
    return tn, tc, lvt, pos

def decode_app(tag_num, data):
    if tag_num == 0: return ('null', None)
    if tag_num == 1: return ('boolean', bool(data[0]) if data else False)
    if tag_num == 2:
        n = 0
        for b in data: n = (n << 8) | b
        return ('uint', n)
    if tag_num == 3:
        if not data: return ('int', 0)
        n = data[0] - 0x100 if data[0] & 0x80 else data[0]
        for b in data[1:]: n = (n << 8) | b
        return ('int', n)
    if tag_num == 4: return ('real', struct.unpack('>f', data)[0])
    if tag_num == 5: return ('double', struct.unpack('>d', data)[0])
    if tag_num == 6: return ('octet', data.hex())
    if tag_num == 7:
        enc = data[0]; raw = data[1:]
        codec = {0: 'utf-8', 3: 'utf-32-be', 4: 'utf-16-be', 5: 'latin-1'}.get(enc, 'latin-1')
        try: return ('string', raw.decode(codec, errors='replace'))
        except Exception: return ('string', raw.hex())
    if tag_num == 8: return ('bitstring', data.hex())
    if tag_num == 9:
        n = 0
        for b in data: n = (n << 8) | b
        return ('enum', n)
    return (f'app{tag_num}', data.hex())

def parse_readprop_ack(apdu):
    if not apdu: raise ValueError('empty APDU')
    pdu_type = apdu[0] >> 4
    if pdu_type == 5: raise RuntimeError(f'BACnet Error PDU: {apdu.hex()}')
    if pdu_type == 6: raise RuntimeError(f'BACnet Reject PDU: {apdu.hex()}')
    if pdu_type == 7: raise RuntimeError(f'BACnet Abort PDU: {apdu.hex()}')
    if pdu_type != 3: raise RuntimeError(f'Unexpected APDU type {pdu_type}: {apdu.hex()}')
    if apdu[2] != 0x0C: raise RuntimeError(f'Not ReadProperty ACK: service={apdu[2]:#x}')
    pos = 3
    tn, tc, lv, pos = parse_tag(apdu, pos); pos += lv  # objectId
    tn, tc, lv, pos = parse_tag(apdu, pos); pos += lv  # propertyId
    tn, tc, lv, pos = parse_tag(apdu, pos)
    if tc == 1 and tn == 2:
        pos += lv
        tn, tc, lv, pos = parse_tag(apdu, pos)
    if not (tc == 1 and tn == 3 and lv == 6):
        raise RuntimeError(f'Expected open tag 3, got tn={tn} tc={tc} lv={lv}')
    values = []
    while True:
        tn, tc, lv, p2 = parse_tag(apdu, pos)
        if tc == 1 and tn == 3 and lv == 7:
            break
        data = apdu[p2:p2+lv]
        values.append(decode_app(tn, data) if tc == 0 else (f'ctx{tn}', data.hex()))
        pos = p2 + lv
    return values

def extract_apdu(bvlc_payload: bytes):
    body = bvlc_payload
    if body[1] == 0x04:        # BVLC Forwarded-NPDU
        body = body[4:] + b''  # sanity; we rebuild below
    # Re-extract from BVLC fully:
    if len(bvlc_payload) < 4 or bvlc_payload[0] != 0x81: return None
    func = bvlc_payload[1]
    if func not in (0x0A, 0x0B, 0x04): return None
    off = 4
    if func == 0x04: off += 6  # 6-byte origin
    npdu = bvlc_payload[off:]
    if len(npdu) < 2: return None
    ctrl = npdu[1]; pos = 2
    if ctrl & 0x20:
        pos += 2; dlen = npdu[pos]; pos += 1 + dlen
    if ctrl & 0x08:
        pos += 2; slen = npdu[pos]; pos += 1 + slen
    if ctrl & 0x20:
        pos += 1
    if ctrl & 0x80:
        return None             # network-layer
    return bytes(npdu[pos:])

def main():
    if len(sys.argv) != 5:
        print('Usage: bacread_raw.py <ip[:port]> <object_type> <object_instance> <property_id>', file=sys.stderr)
        sys.exit(2)
    tgt = sys.argv[1]
    if ':' in tgt:
        dst_ip, dst_port = tgt.split(':', 1); dst_port = int(dst_port)
    else:
        dst_ip, dst_port = tgt, 47808
    obj_type = int(sys.argv[2]); obj_inst = int(sys.argv[3]); prop_id = int(sys.argv[4])
    src_ip = os.environ.get('BAC_SRC_IP', '192.168.23.201')
    src_port = int(os.environ.get('BAC_SRC_PORT', '47808'))
    invoke_id = random.randint(1, 254)

    bacnet = build_readprop(obj_type, obj_inst, prop_id, invoke_id)
    pkt = build_ip_udp(src_ip, src_port, dst_ip, dst_port, bacnet)

    # Send raw
    tx = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
    tx.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)

    # Receive copy of UDP via raw
    rx = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_UDP)
    rx.settimeout(6.0)

    print(f'-> {src_ip}:{src_port} => {dst_ip}:{dst_port}  bacnet={bacnet.hex()}', file=sys.stderr)
    tx.sendto(pkt, (dst_ip, 0))

    deadline = time.time() + 6.0
    while time.time() < deadline:
        try:
            data, src = rx.recvfrom(65535)
        except socket.timeout:
            break
        if len(data) < 28: continue
        # Linux raw IPPROTO_UDP: data starts at IP header
        ihl = (data[0] & 0x0F) * 4
        s_ip = socket.inet_ntoa(data[12:16])
        d_ip = socket.inet_ntoa(data[16:20])
        udp = data[ihl:]
        if len(udp) < 8: continue
        sp, dp, ulen, _ = struct.unpack('!HHHH', udp[:8])
        payload = udp[8:ulen]
        if not (s_ip == dst_ip and sp == dst_port and d_ip == src_ip and dp == src_port):
            continue
        print(f'<- {s_ip}:{sp} => {d_ip}:{dp}  bacnet={payload.hex()}', file=sys.stderr)
        apdu = extract_apdu(payload)
        if apdu is None: continue
        if apdu[1] != invoke_id:
            print(f'  (invoke-id mismatch: got {apdu[1]} want {invoke_id})', file=sys.stderr)
            continue
        try:
            vals = parse_readprop_ack(apdu)
            print('RESULT:', vals)
            return
        except RuntimeError as e:
            print('decode failed:', e, file=sys.stderr)
            return
    print('no reply within deadline', file=sys.stderr); sys.exit(1)

if __name__ == '__main__':
    main()

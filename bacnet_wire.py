"""Shared BACnet/IP wire helpers for the raw-socket toolchain.

The kernel-bypass pattern used throughout:
  * TX: SOCK_RAW + IPPROTO_RAW + IP_HDRINCL builds the IP packet by hand,
    so a colocated BACnet stack (e.g. Cimetrics BACstac) owning UDP/47808
    via bind() does not block our send.
  * RX: SOCK_RAW + IPPROTO_UDP receives a kernel-issued copy of every UDP
    datagram destined for this host, in parallel with normal UDP demux,
    so we see replies (and broadcasts) the bound stack also sees.

Requires CAP_NET_RAW (run as root or setcap on the interpreter).
"""
import os, sys, struct, socket, time, random, subprocess

# ---------- constants ----------

BAC_PORT = 47808

BVLC_TYPE                = 0x81
BVLC_FUNC_ORIG_UNICAST   = 0x0A
BVLC_FUNC_ORIG_BROADCAST = 0x0B
BVLC_FUNC_FORWARDED_NPDU = 0x04

# APDU types (high nibble of byte 0)
APDU_CONFIRMED_REQUEST   = 0
APDU_UNCONFIRMED_REQUEST = 1
APDU_COMPLEX_ACK         = 3
APDU_ERROR               = 5
APDU_REJECT              = 6
APDU_ABORT               = 7

SVC_READ_PROPERTY        = 0x0C  # confirmed service 12
SVC_IAM                  = 0x00  # unconfirmed service 0
SVC_WHOIS                = 0x08  # unconfirmed service 8

PROP_OBJECT_LIST = 76
PROP_OBJECT_NAME = 77

OBJ_DEVICE = 8

OBJ_TYPE_NAMES = {
    0: 'AI', 1: 'AO', 2: 'AV', 3: 'BI', 4: 'BO', 5: 'BV',
    8: 'Device', 10: 'File', 13: 'MSI', 14: 'MSO', 15: 'MSV',
    17: 'NotificationClass', 19: 'Program', 20: 'Schedule', 23: 'TrendLog',
}

SEG_NAMES = {0: 'both', 1: 'tx', 2: 'rx', 3: 'none'}

# ---------- IP / UDP framing ----------

def inet_sum(buf):
    if len(buf) % 2: buf += b'\x00'
    s = 0
    for i in range(0, len(buf), 2):
        s += (buf[i] << 8) | buf[i+1]
    while s >> 16: s = (s & 0xFFFF) + (s >> 16)
    return (~s) & 0xFFFF

def build_ip_udp(src_ip, src_port, dst_ip, dst_port, payload):
    udp_len = 8 + len(payload)
    ip_total = 20 + udp_len
    ip_id = random.randint(0, 0xFFFF)
    ip_hdr = struct.pack('!BBHHHBBH4s4s',
        0x45, 0, ip_total, ip_id, 0x4000, 64, 17, 0,
        socket.inet_aton(src_ip), socket.inet_aton(dst_ip))
    ip_hdr = ip_hdr[:10] + struct.pack('!H', inet_sum(ip_hdr)) + ip_hdr[12:]
    udp_hdr_nocsum = struct.pack('!HHHH', src_port, dst_port, udp_len, 0)
    pseudo = (socket.inet_aton(src_ip) + socket.inet_aton(dst_ip)
              + b'\x00\x11' + struct.pack('!H', udp_len))
    csum = inet_sum(pseudo + udp_hdr_nocsum + payload)
    if csum == 0: csum = 0xFFFF
    udp_hdr = struct.pack('!HHHH', src_port, dst_port, udp_len, csum)
    return ip_hdr + udp_hdr + payload

# ---------- BACnet encoding ----------

def _encode_ctx_uint(tag, val):
    if val < 0x100:
        return bytes([(tag << 4) | 0x09, val])
    if val < 0x10000:
        return bytes([(tag << 4) | 0x0A]) + struct.pack('>H', val)
    if val < 0x1000000:
        return bytes([(tag << 4) | 0x0B]) + struct.pack('>I', val)[1:]
    return bytes([(tag << 4) | 0x0C]) + struct.pack('>I', val)

def build_npdu(dnet=None, dadr=None, expecting_reply=True):
    """NPDU header. dnet/dadr set => routed (DNET/DLEN/DADR + hop count)."""
    ctrl = 0
    if expecting_reply: ctrl |= 0x04
    if dnet is not None: ctrl |= 0x20
    out = bytes([0x01, ctrl])
    if dnet is not None:
        dadr = dadr or b''
        out += struct.pack('>H', dnet) + bytes([len(dadr)]) + dadr + bytes([0xFF])
    return out

def build_whois(low=None, high=None):
    apdu = bytearray([(APDU_UNCONFIRMED_REQUEST << 4), SVC_WHOIS])
    if low is not None and high is not None:
        apdu += _encode_ctx_uint(0, low)
        apdu += _encode_ctx_uint(1, high)
    # Global broadcast NPDU: DNET=0xFFFF, DLEN=0, hop=0xFF
    npdu = bytes([0x01, 0x20, 0xFF, 0xFF, 0x00, 0xFF])
    body = npdu + bytes(apdu)
    return (bytes([BVLC_TYPE, BVLC_FUNC_ORIG_BROADCAST])
            + struct.pack('>H', 4 + len(body)) + body)

def build_readprop(obj_type, obj_inst, prop_id, invoke_id,
                   array_index=None, dnet=None, dadr=None):
    apdu = bytearray([0x00, 0x05, invoke_id & 0xFF, SVC_READ_PROPERTY])
    oid = ((obj_type & 0x3FF) << 22) | (obj_inst & 0x3FFFFF)
    apdu += bytes([0x0C]) + struct.pack('>I', oid)
    if prop_id < 256:
        apdu += bytes([0x19, prop_id])
    else:
        apdu += bytes([0x1A]) + struct.pack('>H', prop_id)
    if array_index is not None:
        apdu += _encode_ctx_uint(2, array_index)
    npdu = build_npdu(dnet=dnet, dadr=dadr, expecting_reply=True)
    body = npdu + bytes(apdu)
    return (bytes([BVLC_TYPE, BVLC_FUNC_ORIG_UNICAST])
            + struct.pack('>H', 4 + len(body)) + body)

# ---------- BACnet decoding ----------

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

def extract_apdu(bvlc_payload):
    """Peel BVLC + NPDU. Returns (apdu_bytes, snet, sadr).
    snet/sadr are None unless the reply carries source routing info."""
    if len(bvlc_payload) < 4 or bvlc_payload[0] != BVLC_TYPE:
        return None, None, None
    func = bvlc_payload[1]
    if func not in (BVLC_FUNC_ORIG_UNICAST, BVLC_FUNC_ORIG_BROADCAST, BVLC_FUNC_FORWARDED_NPDU):
        return None, None, None
    off = 4
    if func == BVLC_FUNC_FORWARDED_NPDU:
        off += 6  # B/IP originator address
    npdu = bvlc_payload[off:]
    if len(npdu) < 2:
        return None, None, None
    ctrl = npdu[1]; pos = 2
    if ctrl & 0x20:
        pos += 2  # DNET
        dlen = npdu[pos]; pos += 1 + dlen
    snet = sadr = None
    if ctrl & 0x08:
        snet = struct.unpack_from('>H', npdu, pos)[0]; pos += 2
        slen = npdu[pos]; pos += 1
        sadr = bytes(npdu[pos:pos+slen]); pos += slen
    if ctrl & 0x20:
        pos += 1  # hop count
    if ctrl & 0x80:
        return None, None, None  # network-layer message
    return bytes(npdu[pos:]), snet, sadr

def parse_iam(apdu):
    if len(apdu) < 2 or apdu[0] != (APDU_UNCONFIRMED_REQUEST << 4) or apdu[1] != SVC_IAM:
        return None
    pos = 2
    tn, tc, lv, pos = parse_tag(apdu, pos)
    if tc != 0 or tn != 12 or lv != 4:
        return None
    oid = struct.unpack_from('>I', apdu, pos)[0]; pos += 4
    obj_type = oid >> 22
    obj_inst = oid & 0x3FFFFF
    if obj_type != OBJ_DEVICE:
        return None
    out = {'device_instance': obj_inst}
    for key, want_tag in (('max_apdu', 2), ('segmentation', 9), ('vendor_id', 2)):
        tn, tc, lv, p2 = parse_tag(apdu, pos)
        if tc != 0 or tn != want_tag:
            return None
        n = 0
        for b in apdu[p2:p2+lv]:
            n = (n << 8) | b
        out[key] = n
        pos = p2 + lv
    return out

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
    if tag_num == 12:
        oid = struct.unpack('>I', data)[0]
        return ('oid', (oid >> 22, oid & 0x3FFFFF))
    return (f'app{tag_num}', data.hex())

def parse_readprop_ack(apdu):
    if not apdu: raise ValueError('empty APDU')
    pdu_type = apdu[0] >> 4
    if pdu_type == APDU_ERROR:  raise RuntimeError(f'BACnet Error PDU: {apdu.hex()}')
    if pdu_type == APDU_REJECT: raise RuntimeError(f'BACnet Reject PDU: {apdu.hex()}')
    if pdu_type == APDU_ABORT:  raise RuntimeError(f'BACnet Abort PDU: {apdu.hex()}')
    if pdu_type != APDU_COMPLEX_ACK:
        raise RuntimeError(f'Unexpected APDU type {pdu_type}: {apdu.hex()}')
    if apdu[2] != SVC_READ_PROPERTY:
        raise RuntimeError(f'Not ReadProperty ACK: service={apdu[2]:#x}')
    pos = 3
    tn, tc, lv, pos = parse_tag(apdu, pos); pos += lv  # objectId
    tn, tc, lv, pos = parse_tag(apdu, pos); pos += lv  # propertyId
    tn, tc, lv, pos = parse_tag(apdu, pos)
    if tc == 1 and tn == 2:                            # optional propertyArrayIndex
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

# ---------- Reader (raw-socket ReadProperty client) ----------

class Reader:
    """One-at-a-time ReadProperty over raw sockets. Each instance owns one
    TX+RX socket pair; use one per thread when parallelizing."""
    def __init__(self, src_ip, src_port=BAC_PORT, timeout=3.0):
        self.src_ip, self.src_port, self.timeout = src_ip, src_port, timeout
        self.tx = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
        self.tx.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
        self.tx.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        self.rx = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_UDP)
        self.rx.settimeout(0.3)

    def send(self, dst_ip, dst_port, payload):
        pkt = build_ip_udp(self.src_ip, self.src_port, dst_ip, dst_port, payload)
        self.tx.sendto(pkt, (dst_ip, 0))

    def read(self, dst_ip, dst_port, obj_type, obj_inst, prop_id,
             array_index=None, dnet=None, dadr=None, retries=1):
        for _ in range(retries + 1):
            invoke_id = random.randint(1, 254)
            req = build_readprop(obj_type, obj_inst, prop_id, invoke_id,
                                 array_index=array_index, dnet=dnet, dadr=dadr)
            self.send(dst_ip, dst_port, req)
            deadline = time.time() + self.timeout
            while time.time() < deadline:
                try:
                    data, _ = self.rx.recvfrom(65535)
                except socket.timeout:
                    continue
                if len(data) < 28: continue
                ihl  = (data[0] & 0x0F) * 4
                s_ip = socket.inet_ntoa(data[12:16])
                udp  = data[ihl:]
                if len(udp) < 8: continue
                sp, dp, ulen, _ = struct.unpack('!HHHH', udp[:8])
                if not (s_ip == dst_ip and sp == dst_port and dp == self.src_port):
                    continue
                apdu, _, _ = extract_apdu(udp[8:ulen])
                if apdu is None or len(apdu) < 3: continue
                if apdu[1] != invoke_id: continue
                return apdu
        return None

    def close(self):
        for s in (self.tx, self.rx):
            try: s.close()
            except OSError: pass

# ---------- environment detection ----------

def detect_bacstac_ip():
    """Inspect /proc/net/udp for a non-loopback bind on UDP/47808 — typically
    Cimetrics BACstac or another BACnet/IP stack on the BACnet NIC. Returns
    the unicast bind (skips the directed-broadcast bind that some stacks
    register alongside). None if nothing matches."""
    try:
        with open('/proc/net/udp') as f:
            next(f)
            for line in f:
                parts = line.split()
                ip_hex, port_hex = parts[1].split(':')
                if int(port_hex, 16) != BAC_PORT:
                    continue
                ip = '.'.join(str(int(ip_hex[i:i+2], 16)) for i in (6, 4, 2, 0))
                if ip.startswith('127.') or ip == '0.0.0.0':
                    continue
                octets = list(map(int, ip.split('.')))
                if octets[-1] == 255:
                    continue
                return ip
    except OSError:
        pass
    return None

def default_bcast(src_ip):
    """Pragmatic /24 directed broadcast. Override with --bcast on non-/24 subnets."""
    o = src_ip.split('.'); o[-1] = '255'
    return '.'.join(o)

def list_local_ipv4():
    out = []
    try:
        r = subprocess.run(['ip', '-o', '-4', 'addr'],
                           capture_output=True, text=True, check=False)
        for line in r.stdout.splitlines():
            parts = line.split()
            if len(parts) >= 4:
                iface, cidr = parts[1], parts[3]
                ip = cidr.split('/')[0]
                if not ip.startswith('127.'):
                    out.append((iface, cidr))
    except Exception:
        pass
    return out

def resolve_src_and_bcast(arg_src, arg_bcast):
    """Decide src_ip and bcast for BACnet/IP. Order:
       1. --src-ip / --bcast args
       2. BAC_SRC_IP / BAC_BCAST env
       3. detect_bacstac_ip() / default_bcast(src)
    Errors helpfully to stderr if src cannot be resolved."""
    src = arg_src or os.environ.get('BAC_SRC_IP') or detect_bacstac_ip()
    if not src:
        print('error: cannot determine source IP. BACstac not bound to UDP/47808,', file=sys.stderr)
        print('       and --src-ip / BAC_SRC_IP not set.', file=sys.stderr)
        ifaces = list_local_ipv4()
        if ifaces:
            print('       available IPv4 interfaces:', file=sys.stderr)
            for iface, cidr in ifaces:
                print(f'         {iface}: {cidr}', file=sys.stderr)
        print('       Set BAC_SRC_IP=<ip> or pass --src-ip <ip>.', file=sys.stderr)
        sys.exit(2)
    bcast = arg_bcast or os.environ.get('BAC_BCAST') or default_bcast(src)
    return src, bcast

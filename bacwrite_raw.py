#!/usr/bin/env python3
"""Raw-socket BACnet WriteProperty — for one-shot writes to commandable points
or structured properties (priority array, list-of-object-property-references).

Usage examples (run on the edge box):

  # Write list-of-object-property-references (LOPR) on a Schedule object.
  # Encodes one DeviceObjectPropertyReference: (object_type, instance).property
  # The script accepts a list via repeated --dopr OBJTYPE:INST:PROP[:ARRIDX].
  bacwrite_raw.py 192.168.67.67 schedule:2 175 \\
      --dopr analog-value:1:85

  # Write a real value to AV:1's present-value at priority 9.
  bacwrite_raw.py 192.168.67.67 analog-value:1 85 --real 23.5 --priority 9

  # Release a priority slot (write null) at priority 9.
  bacwrite_raw.py 192.168.67.67 analog-value:1 85 --null --priority 9
"""
import os, sys, time, struct, socket, random, argparse
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from bacnet_wire import (
    Reader, build_ip_udp, extract_apdu, build_npdu, parse_tag,
    BAC_PORT, BVLC_TYPE, BVLC_FUNC_ORIG_UNICAST,
    APDU_COMPLEX_ACK, APDU_ERROR, APDU_REJECT, APDU_ABORT,
    resolve_src_and_bcast,
)

SVC_WRITE_PROPERTY = 0x0F  # confirmed service 15

OBJ_TYPES = {
    'analog-input': 0, 'analog-output': 1, 'analog-value': 2,
    'binary-input': 3, 'binary-output': 4, 'binary-value': 5,
    'calendar': 6, 'device': 8,
    'multistate-input': 13, 'multistate-output': 14,
    'notification-class': 15, 'schedule': 17,
    'multistate-value': 19, 'trend-log': 20,
}

def parse_objref(s):
    """Accept 'analog-value:1' or '2:1' (numeric type)."""
    name, inst = s.rsplit(':', 1)
    if name.isdigit():
        t = int(name)
    else:
        t = OBJ_TYPES[name]
    return t, int(inst)

def encode_app_uint(n):
    """Application-tagged Unsigned (tag 2)."""
    if n == 0:
        b = b'\x00'
    else:
        b = b''
        m = n
        while m > 0:
            b = bytes([m & 0xFF]) + b
            m >>= 8
    return bytes([0x20 | len(b)]) + b

def encode_ctx_uint(tag, n):
    """Context-tagged Unsigned."""
    if n == 0:
        b = b'\x00'
    else:
        b = b''
        m = n
        while m > 0:
            b = bytes([m & 0xFF]) + b
            m >>= 8
    return bytes([(tag << 4) | 0x08 | len(b)]) + b

def encode_app_oid(obj_type, obj_inst):
    """Application-tagged ObjectIdentifier (tag 12, length 4)."""
    oid = ((obj_type & 0x3FF) << 22) | (obj_inst & 0x3FFFFF)
    return bytes([0xC4]) + struct.pack('>I', oid)

def encode_ctx_oid(tag, obj_type, obj_inst):
    """Context-tagged ObjectIdentifier (length 4)."""
    oid = ((obj_type & 0x3FF) << 22) | (obj_inst & 0x3FFFFF)
    return bytes([(tag << 4) | 0x0C]) + struct.pack('>I', oid)

def encode_ctx_enum(tag, n):
    """Context-tagged Enumerated."""
    if n == 0:
        b = b'\x00'
    else:
        b = b''
        m = n
        while m > 0:
            b = bytes([m & 0xFF]) + b
            m >>= 8
    return bytes([(tag << 4) | 0x08 | len(b)]) + b

def encode_dopr(obj_type, obj_inst, prop_id, arr_idx=None, device_inst=None):
    """Encode one DeviceObjectPropertyReference (4520-ish wire form).
    Fields are context-tagged 0,1,2,3 within the DOPR."""
    out = encode_ctx_oid(0, obj_type, obj_inst)
    out += encode_ctx_enum(1, prop_id)
    if arr_idx is not None:
        out += encode_ctx_uint(2, arr_idx)
    if device_inst is not None:
        out += encode_ctx_oid(3, 8, device_inst)  # 8 = device
    return out

def encode_app_real(x):
    return bytes([0x44]) + struct.pack('>f', x)

def encode_app_null():
    return bytes([0x00])

def encode_app_bool(b):
    return bytes([0x11 if b else 0x10])

def build_writeprop(obj_type, obj_inst, prop_id, value_bytes, invoke_id, priority=None):
    apdu = bytearray([0x00, 0x05, invoke_id & 0xFF, SVC_WRITE_PROPERTY])
    # [0] objectIdentifier
    apdu += encode_ctx_oid(0, obj_type, obj_inst)
    # [1] propertyIdentifier
    apdu += encode_ctx_enum(1, prop_id)
    # [3] propertyValue (constructed open/close)
    apdu += bytes([0x3E])           # open ctx[3]
    apdu += value_bytes
    apdu += bytes([0x3F])           # close ctx[3]
    if priority is not None:
        apdu += encode_ctx_uint(4, priority)
    npdu = build_npdu(expecting_reply=True)
    body = npdu + bytes(apdu)
    return (bytes([BVLC_TYPE, BVLC_FUNC_ORIG_UNICAST])
            + struct.pack('>H', 4 + len(body)) + body)

def send_and_wait(reader, dst_ip, dst_port, pkt, invoke_id, timeout=5.0):
    reader.send(dst_ip, dst_port, pkt)
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            data, _ = reader.rx.recvfrom(65535)
        except socket.timeout:
            continue
        if len(data) < 28: continue
        ihl = (data[0] & 0x0F) * 4
        s_ip = socket.inet_ntoa(data[12:16])
        udp = data[ihl:]
        if len(udp) < 8: continue
        sp, dp, ulen, _ = struct.unpack('!HHHH', udp[:8])
        if not (s_ip == dst_ip and sp == dst_port and dp == reader.src_port): continue
        apdu, _, _ = extract_apdu(udp[8:ulen])
        if apdu is None or len(apdu) < 2: continue
        if apdu[1] != invoke_id: continue
        return apdu
    return None

def describe_response(apdu):
    if apdu is None:
        return 'TIMEOUT'
    pdu_type = apdu[0] >> 4
    if pdu_type == 2:   # SimpleACK
        return 'ACK'
    if pdu_type == APDU_ERROR:
        # Error PDU: error-class + error-code as enumerated tags
        return 'ERROR apdu=' + apdu.hex()
    if pdu_type == APDU_REJECT:
        return f'REJECT reason={apdu[2]} apdu={apdu.hex()}'
    if pdu_type == APDU_ABORT:
        return f'ABORT reason={apdu[2]} apdu={apdu.hex()}'
    return f'unexpected pdu_type={pdu_type} apdu={apdu.hex()}'

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('target', help='ip[:port]')
    ap.add_argument('objref', help='OBJTYPE:INST (e.g. schedule:2)')
    ap.add_argument('prop_id', type=int)
    ap.add_argument('--dopr', action='append', default=[],
                    help='Append DeviceObjectPropertyReference OBJTYPE:INST:PROP[:ARRIDX]. Repeatable.')
    ap.add_argument('--real', type=float, help='Write a single Real (app tag 4).')
    ap.add_argument('--uint', type=int, help='Write a single Unsigned (app tag 2).')
    ap.add_argument('--enum', type=int, help='Write a single Enumerated (app tag 9).')
    ap.add_argument('--bool', dest='boolean', type=lambda s: s.lower() in ('1','true','t','yes'),
                    help='Write a single Boolean.')
    ap.add_argument('--null', action='store_true', help='Write Null (release priority slot).')
    ap.add_argument('--priority', type=int, default=None,
                    help='BACnet priority (1..16) for commandable writes.')
    ap.add_argument('--timeout', type=float, default=5.0)
    ap.add_argument('--src-ip', default=None)
    ap.add_argument('--src-port', type=int, default=BAC_PORT)
    args = ap.parse_args()

    src_ip, _ = resolve_src_and_bcast(args.src_ip, None)
    if ':' in args.target:
        dst_ip, dst_port = args.target.rsplit(':', 1); dst_port = int(dst_port)
    else:
        dst_ip, dst_port = args.target, BAC_PORT
    obj_type, obj_inst = parse_objref(args.objref)

    # Build the value bytes (what goes between open[3] and close[3]).
    value_bytes = b''
    if args.dopr:
        for spec in args.dopr:
            parts = spec.split(':')
            ot = OBJ_TYPES[parts[0]] if not parts[0].isdigit() else int(parts[0])
            oi = int(parts[1])
            pid = int(parts[2])
            arr = int(parts[3]) if len(parts) > 3 else None
            value_bytes += encode_dopr(ot, oi, pid, arr_idx=arr)
    elif args.real is not None:
        value_bytes = encode_app_real(args.real)
    elif args.uint is not None:
        value_bytes = encode_app_uint(args.uint)
    elif args.enum is not None:
        value_bytes = encode_ctx_enum(9, args.enum)  # app-tag enumerated = 0x91 etc
    elif args.boolean is not None:
        value_bytes = encode_app_bool(args.boolean)
    elif args.null:
        value_bytes = encode_app_null()
    else:
        print('error: provide one of --dopr / --real / --uint / --enum / --bool / --null', file=sys.stderr)
        sys.exit(2)

    r = Reader(src_ip, args.src_port, args.timeout)
    try:
        invoke_id = random.randint(1, 254)
        pkt = build_writeprop(obj_type, obj_inst, args.prop_id, value_bytes,
                              invoke_id, priority=args.priority)
        print(f'-> WriteProperty {args.objref} prop={args.prop_id} priority={args.priority} '
              f'value_bytes={value_bytes.hex()} apdu_size={len(pkt)}')
        apdu = send_and_wait(r, dst_ip, dst_port, pkt, invoke_id, args.timeout)
        print('<-', describe_response(apdu))
    finally:
        r.close()

if __name__ == '__main__':
    main()

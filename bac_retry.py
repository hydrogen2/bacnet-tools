#!/usr/bin/env python3
"""Retry timed-out object-list indices in a bac_autosearch.jsonl run.

For each device with status='partial:...', re-reads exactly the array indices
that failed last time (using a longer per-request timeout). Updates objects
in place and downgrades status to 'ok' when all gaps fill.
"""
import os, sys, json, time, argparse
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from bacnet_wire import (
    Reader, parse_readprop_ack,
    OBJ_DEVICE, PROP_OBJECT_LIST, BAC_PORT,
    resolve_src_and_bcast,
)

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--in',  dest='inp', default='/tmp/bac_autosearch.jsonl')
    ap.add_argument('--out',             default='/tmp/bac_autosearch.retried.jsonl')
    ap.add_argument('--timeout', type=float, default=6.0)
    ap.add_argument('--rate',    type=float, default=0.1)
    ap.add_argument('--src-ip',   default=None)
    ap.add_argument('--src-port', type=int, default=BAC_PORT)
    args = ap.parse_args()

    src_ip, _ = resolve_src_and_bcast(args.src_ip, None)

    records = [json.loads(l) for l in open(args.inp)]
    partials = [r for r in records if r['status'].startswith('partial:')]
    print(f'found {len(partials)} partial devices in {args.inp}', file=sys.stderr)

    reader = Reader(src_ip, args.src_port, args.timeout)
    fixed = still_bad = 0
    try:
        for r in partials:
            dnet = r['snet']
            dadr = bytes.fromhex(r['sadr']) if r['sadr'] else None
            ip, port, inst = r['ip'], r['port'], r['device']
            holes = [(slot, o['index']) for slot, o in enumerate(r['objects']) if 'error' in o]
            print(f'  dev {inst:<7} @ {ip:<15} r/{dnet}/{r["sadr"]}  retrying {len(holes)} idx',
                  file=sys.stderr)
            for slot, idx in holes:
                time.sleep(args.rate)
                apdu = reader.read(ip, port, OBJ_DEVICE, inst, PROP_OBJECT_LIST,
                                   array_index=idx, dnet=dnet, dadr=dadr, retries=2)
                if apdu is None:
                    still_bad += 1
                    print(f'      [{idx:>4}] still timeout', file=sys.stderr); continue
                try:
                    vals = parse_readprop_ack(apdu)
                except RuntimeError as e:
                    still_bad += 1
                    print(f'      [{idx:>4}] error: {e}', file=sys.stderr); continue
                if not vals or vals[0][0] != 'oid':
                    still_bad += 1
                    print(f'      [{idx:>4}] unexpected: {vals!r}', file=sys.stderr); continue
                ot, oi = vals[0][1]
                r['objects'][slot] = {'type': ot, 'instance': oi, 'name': None}
                fixed += 1
                print(f'      [{idx:>4}] OK -> type={ot} inst={oi}', file=sys.stderr)
            remaining = sum(1 for o in r['objects'] if 'error' in o)
            r['status'] = 'ok' if remaining == 0 else f'partial:{remaining}-errors'
    finally:
        reader.close()

    with open(args.out, 'w') as fh:
        for r in records:
            fh.write(json.dumps(r) + '\n')

    still_partial = sum(1 for r in records if r['status'].startswith('partial:'))
    print(f'\nfixed {fixed} indices, {still_bad} still failing', file=sys.stderr)
    print(f'devices still partial: {still_partial}/{len(partials)}', file=sys.stderr)
    print(f'-> {args.out}', file=sys.stderr)

if __name__ == '__main__':
    main()

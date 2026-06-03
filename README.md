# bacnet-tools

Raw-socket BACnet/IP utilities for aarch64 Linux edge boxes. Discovers and enumerates BACnet devices on the local network while coexisting with a colocated BACnet stack (e.g. Cimetrics BACstac) already bound to UDP/47808.

## Why raw sockets

A normal UDP socket can't `bind()` to port 47808 when BACstac owns it (`EADDRINUSE`). These scripts sidestep the conflict:

- **TX**: `SOCK_RAW + IPPROTO_RAW + IP_HDRINCL` — hand-built IP+UDP+BVLC+NPDU+APDU bytes. The kernel does not consult the UDP bind table on raw sends, so source port 47808 is freely usable.
- **RX**: `SOCK_RAW + IPPROTO_UDP` — Linux delivers a copy of every inbound UDP datagram (unicast, subnet broadcast, 255.255.255.255) to such sockets in parallel with normal UDP demux, so BACstac and these tools both receive replies. Userspace filters by `(src_ip, src_port, dst_port, invoke_id)`.

Requires `CAP_NET_RAW` — run as root, or `setcap cap_net_raw+ep $(which python3)`.

## Auto-detect

If `--src-ip` / `BAC_SRC_IP` is not set, the scripts read `/proc/net/udp` to find whichever IP BACstac is bound to and use that. `--bcast` defaults to the `/24` directed broadcast of the source IP. On a typical site, no flags are needed.

## Files

### `bacnet_wire.py` — shared library

Holds the IP/UDP packet builder, BACnet encoders/decoders (Who-Is, ReadProperty, I-Am, ComplexACK, tagged values including `objectIdentifier`), the `Reader` class (per-thread TX+RX raw-socket pair with invoke-id filtering), and the auto-detect helpers. Everything else imports from here.

### `bacread_raw.py` — one ReadProperty

```
bacread_raw.py <ip[:port]> <obj_type> <obj_inst> <prop_id> [--index N] [--dnet N --dadr HEX]
```

```sh
# Direct: read object-list count of Device:1401
bacread_raw.py 192.168.23.21 8 1401 76 --index 0

# Routed: same, through a BACnet/IP -> MS/TP router
bacread_raw.py 192.168.23.118 8 901 76 --index 0 --dnet 23023 --dadr 17
```

### `bacsearch_raw.py` — Who-Is broadcast + I-Am collector

```
bacsearch_raw.py [low high] [--window 5]
bacsearch_raw.py [low high] --dnet N --router IP   # routed Who-Is
```

Sends one Who-Is, collects I-Am replies for `--window` seconds, prints `{device_instance, ip, port, max_apdu, segmentation, vendor_id}` plus `snet/sadr` for routed devices. Step 1 of autosearch — yields a directory of every reachable device.

`--dnet N --router IP` switches to routed Who-Is: NPDU carries DNET=N, BVLC is unicast to the router IP, and the router broadcasts on the remote BACnet network. Use after `bacrouter_raw.py` discovers a router. `--dadr HEX` narrows to a unicast MAC on the remote network.

### `bacrouter_raw.py` — Who-Is-Router-To-Network probe

```
bacrouter_raw.py [--dnet N] [--window 6]
```

Sends a Who-Is-Router-To-Network NLM (Network Layer Message); collects `I-Am-Router-To-Network` replies and prints each router's IP plus the BACnet network numbers it routes to. With `--dnet N`, asks only about routes to network N.

Lives below the APDU layer, so it is **not affected by Tridium-style Who-Is debounce** which suppresses Unconfirmed-Request Who-Is at the APDU layer. Useful when `bacsearch_raw.py` returns nothing after a burst of probes.

Receives via `AF_PACKET` (Linux) because I-Am-Router-To-Network replies are broadcast, and the `SOCK_RAW + IPPROTO_UDP` pattern used elsewhere in this toolkit does not reliably deliver broadcast-destination UDP datagrams.

### `bacenum_raw.py` — walk one device's object-list

```
bacenum_raw.py <ip[:port]> <device_instance> [--dnet N --dadr HEX] [--name] [--limit N]
```

Reads `object-list[0]` for the count, then iterates indices `1..N` one at a time. Universal — works on `segmentation=none` devices with `max_apdu=480`. With `--name`, also reads `object-name` (property 77) for each object.

### `bacscan_raw.py` — full autosearch

```
bacscan_raw.py [--name] [--workers 16] [--timeout 5] [--out /tmp/bac_autosearch.jsonl]
```

- **Phase 1**: Who-Is, build device directory.
- **Phase 2**: one worker thread per router IP. Devices on the same router serialize (MS/TP is a single token-ring; parallel just queues and times out); different routers run concurrently up to `--workers`.
- **Output**: JSONL, one device per line, flushed after each device — crash-safe.

JSONL record shape:

```json
{
  "device": 901,
  "ip": "192.168.23.118",
  "port": 47808,
  "snet": 23023,
  "sadr": "17",
  "status": "ok",
  "object_count": 88,
  "objects": [
    {"type": 8, "instance": 901, "name": "NPCCR-FCU-L2-101-103-01"},
    {"type": 0, "instance": 1,   "name": "NPCCR_FCU_L2_101_103_01_RaT"}
  ],
  "elapsed": 12.3
}
```

`status` is `ok`, `partial:N-errors`, `no-reply-count`, or `error-count:<msg>`. Indices that timed out appear in `objects` as `{"index": N, "error": "timeout"}` and can be filled later by `bac_retry.py`.

### `bac_retry.py` — fix timeouts in a previous scan

```
bac_retry.py --in scan.jsonl --out scan.jsonl --timeout 6
```

Reads only `status=partial:*` records, re-reads exactly the `array_index` slots that failed (not the whole object-list), updates `status` to `ok` when gaps fill. Much cheaper than re-running `bacscan_raw.py`; typically closes every gap with a longer timeout on the first try.

## Typical workflow

```sh
git clone git@github.com:hydrogen2/bacnet-tools.git
cd bacnet-tools

# Full scan with object names — ~35-40 min on a ~300-device site
sudo python3 bacscan_raw.py --name

# Close any timeout gaps in place
sudo python3 bac_retry.py --in /tmp/bac_autosearch.jsonl \
                          --out /tmp/bac_autosearch.jsonl
```

## Environment variables

- `BAC_SRC_IP` — override auto-detected source IP
- `BAC_BCAST` — override default `/24` broadcast (e.g. for non-`/24` subnets)
- `BAC_SRC_PORT`, `BAC_DST_PORT` — default `47808`

## Tested on

A 317-device site (28 direct BACnet/IP + 287 routed behind 15 BACnet/IP↔MS/TP routers, two vendors). Full `--name` scan: 316/316 devices, 28,028 objects, 0 failures after one retry pass.

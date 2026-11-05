curl -fsSL https://raw.githubusercontent.com/hydrogen2/bacnet-tools/refs/heads/main/install_tailscale.sh | sh

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

Reads `object-list[0]` for the count, then iterates indices `1..N` one at a time. Universal — works on `segmentation=none` devices with `max_apdu=480`. With `--name`, also reads `object-name` (property 77) for each object. (`bacscan_raw.py --name` reads `description` too — see below.)

### `bacscan_raw.py` — full autosearch

```
bacscan_raw.py [--name] [--no-desc] [--workers 16] [--timeout 5] [--out /tmp/bac_autosearch.jsonl]
```

- **Phase 1**: Who-Is, build device directory.
- **Phase 2**: one worker thread per router IP. Devices on the same router serialize (MS/TP is a single token-ring; parallel just queues and times out); different routers run concurrently up to `--workers`.
- **Output**: JSONL, one device per line, flushed after each device — crash-safe.
- **`--name` reads BOTH `Object_Name` (77) and `Description` (28)** into `name` and
  `desc`. Read both: on many gateways `Object_Name` is a placeholder and the point's
  real role is only in `Description`. A Synapsys SIP+ publishes `binary value 3` as the
  name and `Filter Sign` as the description — a scan that keeps only the name loses the
  entire point vocabulary and leaves the mapping unrecoverable from the wire. Pass
  `--no-desc` to skip it and halve the per-object reads.

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

### `bacwrite_raw.py` — one WriteProperty

```
bacwrite_raw.py <ip[:port]> <objref> <prop_id>
    (--real X | --uint N | --enum N | --bool 0/1 | --null | --dopr ...)
    [--priority 1..16]
```

WriteProperty for commandable points (priority array slots) and structured properties. `objref` accepts `analog-value:1` style or numeric `2:1`. `--null` releases a priority slot. `--dopr OBJTYPE:INST:PROP[:ARRIDX]` (repeatable) builds a list of `DeviceObjectPropertyReference` values — needed for properties like a `Schedule` object's `list-of-object-property-references`.

```sh
# Override AV:1 present-value at priority 9
bacwrite_raw.py 192.168.67.67 analog-value:1 85 --real 23.5 --priority 9

# Release that override
bacwrite_raw.py 192.168.67.67 analog-value:1 85 --null --priority 9

# Wire Schedule:2's LOPR to drive AV:1's present-value
bacwrite_raw.py 192.168.67.67 schedule:2 175 --dopr analog-value:1:85
```

### `bac_retry.py` — fix timeouts in a previous scan

```
bac_retry.py --in scan.jsonl --out scan.jsonl --timeout 6
```

Reads only `status=partial:*` records, re-reads exactly the `array_index` slots that failed (not the whole object-list), updates `status` to `ok` when gaps fill. Much cheaper than re-running `bacscan_raw.py`; typically closes every gap with a longer timeout on the first try.

### `fake_iam.py` — unblock a device that ignores Who-Is

```
# read the real fields off the device first (ReadProperty works; Who-Is does not)
bacread_multi.py 10.138.0.193 8:702193:75 8:702193:62 8:702193:107 8:702193:120

fake_iam.py --dev-ip 10.138.0.193 --inst 702193 \
    --max-apdu 1476 --seg 0 --vendor 246 --stack-ip 10.130.1.196
```

Some old firmware never answers Who-Is — not even unicast — while answering unicast ReadProperty perfectly. BACstac will not route a single request until `bsResolveDeviceID` completes, so the colocated `bacstac_client` collect wedges forever on `devInst(N) ResolveDeviceID failed, status=Device unreachable` even though the device is healthy. This injects an I-Am on the device's behalf.

Two things decide whether it works, both documented at length in the script's header:

- **Source address.** BACstac binds the instance to the packet's source, not the I-Am payload, so the I-Am must be forged *from the device's* IP — otherwise the handshake passes and every subsequent read goes to the helper.
- **Field accuracy.** BACstac believes the advertised `max-apdu-length-accepted` and `segmentation-supported`. Guess them high and you trade a clean handshake failure for intermittent silent drops. Read them off the device; if unreadable, fall back to the BACnet floor (480, no segmentation).

If the device answers a *unicast* Who-Is but not a broadcast one, this is the wrong tool — that is a broadcast-reception problem, and redirecting the edge's own broadcast with nftables keeps the I-Am genuine.

### `iam_watch.py` + `bacnet-iam-helper.service` — keep it unblocked

```
cp iam_watch.py fake_iam.py bacnet_wire.py /root/bacnet-tools/
install -m 0644 bacnet-iam-helper.service /etc/systemd/system/
systemctl daemon-reload && systemctl enable --now bacnet-iam-helper
tail -f /var/log/bacnet-iam.log
```

One I-Am is enough — BACstac caches the binding and does not re-resolve while the device keeps answering (measured: still 1536 points/min 2.5 min after the sender stopped). So this is **event-driven, not periodic**: it watches the driver logs for the `ResolveDeviceID failed` line and fires once. The only three things that lose a binding — edge reboot, `edge-dpf`/BACstac restart, collect republish — all surface as that same line.

Generic by design: device IP and port come from the driver log directory name, the instance from the log line, so a future silent device needs no configuration.

**It verifies the device is alive with a unicast ReadProperty before forging anything, and sends nothing if that fails.** Without that guard a genuinely dead controller would be handed a fake binding and the collect would report read errors forever instead of a clean "unreachable" — trading a visible fault for an invisible one. Keep it.

Run `iam_watch.py --once --log-dir <synthetic dir>` to exercise the detect/guard/forge paths without waiting for a real failure.

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

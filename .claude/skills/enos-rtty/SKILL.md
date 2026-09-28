---
name: enos-rtty
description: |
  Use to run shell commands on an EnOS Edge device (edge box / gateway)
  headlessly through the Dev Portal's rtty web terminal — no browser. Logs
  into the portal IAM (public key -> RSA-encrypt password -> /iam/api/v3/login),
  then drives the rtty WebSocket (wss://<host>/edge-rttys/connect/<DEVICE_ID>,
  authenticated by the global_id session cookie) to run one command and return
  its stdout + exit code. rtty is authorized to SPECIFIC portal accounts, so a
  suitable account must be supplied. Triggers on: "run a command on the edge
  via rtty", "edge web shell / web terminal", "rtty", "edge-rttys", "exec on
  edge box without SSH", "portal shell on gateway".
---

# EnOS Edge rtty — headless command runner

rtty is the Dev Portal's browser web-shell to an edge box (the "compliant
replacement" for direct SSH/tailscale). `enos_rtty.py` reproduces the browser
client so you can run commands from the shell/CI, **no browser and no CDP**.

## Auth model (verified)

rtty is authorized to **specific portal accounts** — a generic onboarding
account will not open the terminal. Supply an rtty-authorized account.

Login is the same flow the `hvac-onboarding` skill uses
(`DevPortalLogin.java`), ported to Python:

1. `GET  https://<host>/iam-web/v1/encrypt/publicKey` → `{key_id, public_key(PEM)}`
   (`key_id` is currently the constant `FIXED_KEY_ID`).
2. RSA-encrypt the password with that public key, **PKCS#1 v1.5** padding,
   base64 (matches Java `Cipher.getInstance("RSA")`).
3. `POST https://<host>/iam/api/v3/login`
   `{"authType":0,"principal":<user>,"credentials":<enc>,"keyId":<key_id>}`
   → `sessionId`.
4. (optional) `POST /iam-web/session/set {"working_organization_id":<org>}`
   with header `Cookie: global_id=<sessionId>`.

The rtty WebSocket authenticates with **`Cookie: global_id=<sessionId>` alone**
(verified — no other cookie needed) plus an `Origin: https://<host>` header.
Sessions last ~1h; cache the sessionId with `--login-only` and reuse via
`--session` to avoid re-login.

## Protocol (reverse-engineered from portal-sg.enos-iot.com/edge-rttys)

```
ws  wss://<host>/edge-rttys/connect/<DEVICE_ID>
<-  {"type":"login","err":0}          text JSON; err != 0 => failed
->  {"type":"winsize","cols":C,"rows":R}   text JSON
->  0x00 + <input bytes>              binary frame: byte0=0x00 (data), rest = keystrokes/command
<-  0x00 + <output bytes>            binary frame: byte0 is msg type (0x00=data), strip it; rest is PTY output
```

Control messages (login/winsize) are **text JSON**; terminal I/O are **binary**
frames whose first byte is the message type (`0x00` = data). It is a real PTY:
input is echoed and a shell prompt is printed, so the runner brackets the
command with random markers and captures the text between them plus `$?`:

```
echo <START>; <your cmd>; echo <END>$?
```

then strips ANSI escapes and reads stdout between `<START>` and `<END><code>`.

## DEVICE_ID

Looks like `V1_<box-uuid>_<iface>_<mac>`, e.g.
`V1_1D441D60-E841-11F0-B210-729685733400_ETH0_CC827FB4ED62`. It is the last
path segment of the rtty tab URL (`…/edge-rttys/rtty/<DEVICE_ID>`). Open rtty
once in the portal for a device and copy it from the address bar. (A portal API
to map edge box → DEVICE_ID is not yet wired in here; add it if bulk use needs
it.)

## Usage

```bash
# one command (prompts for password if not given via env/stdin/file):
python3 enos_rtty.py --host portal-sg.enos-iot.com --user <acct> --password-stdin \
    --device 'V1_..._ETH0_...' --cmd 'ls /usr/bin/tailscale*'

# cache the session and reuse it (sessions ~1h):
SID=$(python3 enos_rtty.py --host portal-sg.enos-iot.com --user <acct> --password-stdin --login-only)
python3 enos_rtty.py --host portal-sg.enos-iot.com --session "$SID" \
    --device 'V1_..._ETH0_...' --cmd 'id; hostname'

# creds from a file: {"host","user","password","org"}
python3 enos_rtty.py --creds-file ./acct.json --device D --cmd 'uptime'
```

Credentials resolve from (any of): `--user/--password`, `--password-stdin`,
env `ENOS_RTTY_HOST/USER/PASSWORD/ORG`, or `--creds-file`. Exit code mirrors the
remote command's `$?`. `--raw` prints unparsed output (for debugging).

## Requirements

`requests`, `websocket-client`, `cryptography` (all present in this env).

## Notes / gotchas

- rtty exposes a **root** shell on the box; treat commands with care.
- If you see `rtty login err=…`, the session is invalid/expired — re-login.
- Region host varies: `portal-sg.enos-iot.com` (SG), etc. Login endpoints and
  the WebSocket are on the same host.
- No browser is used at runtime. (During development the protocol was captured
  by attaching to a logged-in Chrome over CDP; that is not needed to run.)

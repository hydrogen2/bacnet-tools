#!/usr/bin/env python3
"""
enos_rtty — run a command on an EnOS Edge device through the Dev Portal's rtty
web shell, fully headless (no browser).

It logs into the portal IAM the same way the hvac-onboarding skill does
(public key -> RSA-encrypt password -> /iam/api/v3/login), takes the returned
sessionId, and opens the rtty WebSocket authenticated by the `global_id`
cookie (verified: global_id alone is sufficient).

Protocol (reverse-engineered from portal-sg.enos-iot.com/edge-rttys):
  ws  wss://<host>/edge-rttys/connect/<DEVICE_ID>   (Origin + Cookie: global_id=<sessionId>)
  <-  {"type":"login","err":0}         (text JSON; err!=0 => failed)
  ->  {"type":"winsize","cols":C,"rows":R}   (text JSON)
  ->  0x00 + <input bytes>             (binary: command line, ending in \n)
  <-  0x00 + <output bytes>            (binary: PTY output; strip byte0)

DEVICE_ID looks like  V1_<box-uuid>_<iface>_<mac>  and is the last path segment
of the rtty tab URL (…/edge-rttys/rtty/<DEVICE_ID>).

Auth (rtty is authorized to specific accounts — supply that account):
  --user/--password, or --password-stdin, or env ENOS_RTTY_USER/ENOS_RTTY_PASSWORD,
  or --creds-file (JSON {"host","user","password","org"}).
  --session <id> reuses a sessionId and skips login. --login-only prints the
  sessionId and exits (cache it; sessions last ~1h).

Examples:
  python3 enos_rtty.py --host portal-sg.enos-iot.com --user U --password-stdin \
      --device 'V1_..._ETH0_...' --cmd 'ls /usr/bin/tailscale*'
  SID=$(python3 enos_rtty.py --host H --user U --password-stdin --login-only)
  python3 enos_rtty.py --host H --session "$SID" --device D --cmd 'id'

Requires: requests, websocket-client, cryptography (all stdlib-adjacent).
"""
import sys, os, re, json, time, base64, argparse, secrets, getpass
import requests
import websocket  # websocket-client
from cryptography.hazmat.primitives.serialization import load_pem_public_key
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.backends import default_backend

ANSI = re.compile(r'\x1b\[[0-9;?]*[ -/]*[@-~]|\x1b\][^\x07\x1b]*(?:\x07|\x1b\\)|[\x00-\x08\x0b\x0c\x0e-\x1f]')

def clean(s: str) -> str:
    return ANSI.sub('', s.replace('\r\n', '\n').replace('\r', '\n'))

# ---------------- IAM login (ported from DevPortalLogin.java) ----------------
def get_public_key(base):
    r = requests.get(base + "/iam-web/v1/encrypt/publicKey", timeout=15)
    r.raise_for_status()
    d = r.json()
    if d.get("status") != 0:
        raise RuntimeError("publicKey failed: %s" % d.get("message"))
    return d["data"]["key_id"], d["data"]["public_key"]

def encrypt_password(password, public_key_pem):
    pub = load_pem_public_key(public_key_pem.encode(), backend=default_backend())
    return base64.b64encode(pub.encrypt(password.encode("utf-8"), padding.PKCS1v15())).decode()

def login(base, principal, password, org_id=None):
    key_id, pub_pem = get_public_key(base)
    enc = encrypt_password(password, pub_pem)
    r = requests.post(base + "/iam/api/v3/login",
                      json={"authType": 0, "principal": principal, "credentials": enc, "keyId": key_id},
                      timeout=15)
    r.raise_for_status()
    d = r.json()
    if not (d.get("success") and not d.get("failed") and d.get("status") == 0 and d.get("sessionId")):
        raise RuntimeError("login failed: %s" % (d.get("message") or d))
    sid = d["sessionId"]
    if org_id:
        rr = requests.post(base + "/iam-web/session/set",
                           json={"working_organization_id": org_id},
                           headers={"Cookie": "global_id=" + sid}, timeout=15)
        if rr.ok and rr.json().get("status") == 0:
            pass  # working org set
    return sid

# ---------------- run one command over the rtty WebSocket ----------------
def run_command(host, device, cmd, session_id, cols=120, rows=40, timeout=30):
    url = "wss://%s/edge-rttys/connect/%s" % (host, device)
    ws = websocket.create_connection(
        url, header=["Origin: https://%s" % host, "User-Agent: enos_rtty/1.0"],
        cookie="global_id=%s" % session_id, timeout=min(timeout, 15))
    start = 'RS_' + secrets.token_hex(6)
    end = 'RE_' + secrets.token_hex(6)
    buf = b""
    t0 = time.time()
    try:
        while time.time() - t0 < timeout:
            try:
                ws.settimeout(2)
                msg = ws.recv()
            except websocket.WebSocketTimeoutException:
                continue
            except Exception:
                break
            if isinstance(msg, (bytes, bytearray)):
                buf += msg[1:] if msg[:1] == b"\x00" else msg
                if re.search((re.escape(end) + r"\d").encode(), buf):
                    break
            else:
                try:
                    j = json.loads(msg)
                except Exception:
                    continue
                if j.get("type") == "login":
                    if j.get("err"):
                        raise RuntimeError("rtty login err=%s (session invalid/expired?)" % j["err"])
                    ws.send(json.dumps({"type": "winsize", "cols": cols, "rows": rows}))
                    line = "echo %s; %s; echo %s$?\n" % (start, cmd, end)
                    ws.send(b"\x00" + line.encode(), opcode=websocket.ABNF.OPCODE_BINARY)
    finally:
        try: ws.close()
        except Exception: pass
    text = clean(buf.decode("utf-8", "replace"))
    m1 = re.search(re.escape(start) + r'\n', text)
    m2 = re.search(re.escape(end) + r'(\d+)', text)
    if m1 and m2 and m2.start() >= m1.end():
        return text[m1.end():m2.start()].rstrip('\n'), int(m2.group(1)), None
    return text, None, "unparsed"

def resolve_creds(args):
    host = args.host or os.environ.get("ENOS_RTTY_HOST")
    user = args.user or os.environ.get("ENOS_RTTY_USER")
    pw = args.password or os.environ.get("ENOS_RTTY_PASSWORD")
    org = args.org or os.environ.get("ENOS_RTTY_ORG")
    if args.creds_file:
        with open(args.creds_file) as f:
            c = json.load(f)
        host = host or c.get("host"); user = user or c.get("user")
        pw = pw or c.get("password"); org = org or c.get("org")
    if args.password_stdin and not pw:
        pw = sys.stdin.readline().rstrip("\n")
    return host, user, pw, org

def main():
    ap = argparse.ArgumentParser(description="Run a command on an EnOS Edge device via rtty (headless).")
    ap.add_argument('--host', help='portal host, e.g. portal-sg.enos-iot.com')
    ap.add_argument('--user', help='portal username (rtty-authorized account)')
    ap.add_argument('--password', help='portal password (prefer --password-stdin or env)')
    ap.add_argument('--password-stdin', action='store_true', help='read password from stdin')
    ap.add_argument('--org', help='working organization id (optional)')
    ap.add_argument('--creds-file', help='JSON file {host,user,password,org}')
    ap.add_argument('--session', help='reuse an existing sessionId (skip login)')
    ap.add_argument('--login-only', action='store_true', help='log in, print sessionId, exit')
    ap.add_argument('--device', help='rtty connect id V1_<uuid>_<iface>_<mac>')
    ap.add_argument('--cmd', help='command to run')
    ap.add_argument('--cols', type=int, default=120)
    ap.add_argument('--rows', type=int, default=40)
    ap.add_argument('--timeout', type=float, default=30)
    ap.add_argument('--raw', action='store_true', help='print raw output, do not parse')
    args = ap.parse_args()

    host, user, pw, org = resolve_creds(args)
    if not host:
        print("--host (or ENOS_RTTY_HOST) required", file=sys.stderr); sys.exit(2)
    base = "https://" + host

    session_id = args.session
    if not session_id:
        if not user:
            print("need --user (or --session)", file=sys.stderr); sys.exit(2)
        if not pw:
            pw = getpass.getpass("portal password: ")
        try:
            session_id = login(base, user, pw, org)
        except Exception as e:
            print("login error: %s" % e, file=sys.stderr); sys.exit(1)

    if args.login_only:
        print(session_id); return

    if not (args.device and args.cmd):
        print("--device and --cmd are required (unless --login-only)", file=sys.stderr); sys.exit(2)

    try:
        out, code, err = run_command(host, args.device, args.cmd, session_id,
                                     args.cols, args.rows, args.timeout)
    except Exception as e:
        print("rtty error: %s" % e, file=sys.stderr); sys.exit(1)

    if args.raw:
        sys.stdout.write(out or ""); return
    if err == "unparsed":
        sys.stdout.write(out or "")
        print("\n[could not parse output markers; use --raw to inspect]", file=sys.stderr)
        sys.exit(1)
    sys.stdout.write(out + ('\n' if out and not out.endswith('\n') else ''))
    sys.exit(code if code is not None else 0)

if __name__ == '__main__':
    main()

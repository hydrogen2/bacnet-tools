#!/bin/sh
# Uninstall tailscale installed by install_tailscale.sh (package or static
# binary). Only removes tailscale's own package, files and service; other
# packages, network config and services are left untouched.
#
# Usage: curl -fsSL https://raw.githubusercontent.com/hydrogen2/bacnet-tools/refs/heads/main/uninstall_tailscale.sh | sudo sh
#
# Safe to run over tailscale SSH: the work runs in its own transient systemd
# unit (systemd-run), so neither the session dropping nor stopping tailscaled
# (which kills everything in its cgroup, including tailscale SSH sessions)
# interrupts it.
#
# On a clean uninstall the log (/var/log/tailscale-uninstall.log) deletes
# itself, leaving no artifact from this script; it is kept only if something
# failed, so there is a record to debug. (The journal, apt/dpkg logs and shell
# history still record that tailscale was installed; those are not touched.)

if [ "$(id -u)" -ne 0 ]; then
    echo "Run as root" >&2
    exit 1
fi

LOG=/var/log/tailscale-uninstall.log
WORKER=$(mktemp /tmp/tailscale-uninstall.XXXXXX) || exit 1

cat > "$WORKER" <<'EOF'
#!/bin/sh
# $1 = log path (deleted on a clean run, kept on failure)
LOGPATH=$1
echo "=== tailscale uninstall started $(date) ==="

have() { command -v "$1" >/dev/null 2>&1; }
with_timeout() { if have timeout; then timeout 15 "$@"; else "$@"; fi; }

# Expire this node's key so it drops off the tailnet
if have tailscale; then
    with_timeout tailscale logout && echo "Logged out of tailnet"
fi

# Stop and disable the service
if have systemctl; then
    systemctl disable --now tailscaled 2>/dev/null && echo "Stopped tailscaled (systemd)"
elif have rc-service; then
    rc-service tailscale stop 2>/dev/null
    rc-update del tailscale 2>/dev/null
fi

# Undo any routes/DNS/firewall rules tailscaled may have set (no-op in userspace mode)
for d in /usr/sbin/tailscaled /usr/bin/tailscaled; do
    [ -x "$d" ] && { with_timeout "$d" --cleanup --no-logs-no-support >/dev/null 2>&1; break; }
done

# Remove the package (only tailscale itself; no autoremove of other packages).
# dpkg/rpm are used directly so this works even when apt/dnf is broken.
if have dpkg && dpkg -s tailscale >/dev/null 2>&1; then
    dpkg --purge tailscale && echo "Purged tailscale deb"
    dpkg -s tailscale-archive-keyring >/dev/null 2>&1 && dpkg --purge tailscale-archive-keyring
elif have rpm && rpm -q tailscale >/dev/null 2>&1; then
    rpm -e tailscale && echo "Removed tailscale rpm"
elif have apk && apk info -e tailscale >/dev/null 2>&1; then
    apk del tailscale && echo "Removed tailscale apk"
fi

# Static-binary install leftovers, systemd unit/override, state and repo files
rm -rf \
    /usr/sbin/tailscale /usr/sbin/tailscaled \
    /usr/bin/tailscale /usr/bin/tailscaled \
    /usr/local/bin/tailscale /usr/local/bin/tailscaled \
    /usr/local/sbin/tailscale /usr/local/sbin/tailscaled \
    /etc/systemd/system/tailscaled.service \
    /etc/systemd/system/tailscaled.service.d \
    /etc/systemd/system/multi-user.target.wants/tailscaled.service \
    /lib/systemd/system/tailscaled.service \
    /usr/local/lib/systemd/system/tailscaled.service \
    /etc/default/tailscaled \
    /var/lib/tailscale /var/cache/tailscale /run/tailscale \
    /etc/apt/sources.list.d/tailscale.list \
    /usr/share/keyrings/tailscale-archive-keyring.gpg \
    /etc/yum.repos.d/tailscale.repo

if have systemctl; then
    systemctl daemon-reload
    systemctl reset-failed tailscaled 2>/dev/null
fi

# Verify nothing tailscale-related is left behind
LEFT=$(ls /usr/sbin/tailscale* /usr/bin/tailscale* /usr/local/bin/tailscale* /usr/local/sbin/tailscale* 2>/dev/null)
PKG=""
have dpkg && dpkg -s tailscale >/dev/null 2>&1 && PKG="deb"
have rpm && rpm -q tailscale >/dev/null 2>&1 && PKG="rpm"
have apk && apk info -e tailscale >/dev/null 2>&1 && PKG="apk"

if [ -n "$LEFT" ] || [ -n "$PKG" ]; then
    echo "WARNING: tailscale not fully removed (binaries: ${LEFT:-none}; package: ${PKG:-none})"
    echo "=== tailscale uninstall finished with errors $(date) ==="
    echo "Log kept at $LOGPATH for debugging."
else
    echo "tailscale removed"
    echo "=== tailscale uninstall finished $(date) ==="
    # Clean run: remove this script and its own log so no artifact remains.
    rm -f "$0"
    [ -n "$LOGPATH" ] && rm -f "$LOGPATH"
    exit 0
fi
rm -f "$0"
EOF

echo "Uninstalling tailscale in background."
echo "(If you're connected over tailscale, this session will drop; that's expected.)"
if command -v systemd-run >/dev/null 2>&1 && [ -d /run/systemd/system ]; then
    systemd-run --quiet --description="tailscale uninstall" \
        sh -c "sh '$WORKER' '$LOG' >'$LOG' 2>&1"
elif command -v setsid >/dev/null 2>&1; then
    setsid nohup sh "$WORKER" "$LOG" >"$LOG" 2>&1 </dev/null &
else
    nohup sh "$WORKER" "$LOG" >"$LOG" 2>&1 </dev/null &
fi

# If the session survives (not connected via tailscale), wait for the worker
# (it deletes itself when done) and report. On a clean run the log is gone.
while [ -e "$WORKER" ]; do sleep 1; done
if [ -e "$LOG" ]; then
    cat "$LOG"
else
    echo "tailscale removed cleanly; no log kept."
fi

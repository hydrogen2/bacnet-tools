#!/bin/sh
# Uninstall tailscale installed by install_tailscale.sh (package or static
# binary). Only removes tailscale's own package, files and service; other
# packages, network config and services are left untouched.
#
# Usage: curl -fsSL https://raw.githubusercontent.com/hydrogen2/bacnet-tools/refs/heads/main/uninstall_tailscale.sh | sudo sh
#
# The work runs detached (setsid/nohup) because the SSH session is likely
# going over tailscale and will drop midway. Log: /var/log/tailscale-uninstall.log

if [ "$(id -u)" -ne 0 ]; then
    echo "Run as root" >&2
    exit 1
fi

LOG=/var/log/tailscale-uninstall.log
WORKER=$(mktemp /tmp/tailscale-uninstall.XXXXXX) || exit 1

cat > "$WORKER" <<'EOF'
#!/bin/sh
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
    /etc/systemd/system/tailscaled.service \
    /etc/systemd/system/tailscaled.service.d \
    /etc/systemd/system/multi-user.target.wants/tailscaled.service \
    /etc/default/tailscaled \
    /var/lib/tailscale /var/cache/tailscale /run/tailscale \
    /etc/apt/sources.list.d/tailscale.list \
    /usr/share/keyrings/tailscale-archive-keyring.gpg \
    /etc/yum.repos.d/tailscale.repo

if have systemctl; then
    systemctl daemon-reload
    systemctl reset-failed tailscaled 2>/dev/null
fi

LEFT=$(ls /usr/sbin/tailscale* /usr/bin/tailscale* /usr/local/bin/tailscale* /usr/local/sbin/tailscale* 2>/dev/null)
if [ -n "$LEFT" ]; then
    echo "WARNING: tailscale binaries still present:" $LEFT
else
    echo "tailscale removed"
fi
echo "=== tailscale uninstall finished $(date) ==="
rm -f "$0"
EOF

START=$(cat "$LOG" 2>/dev/null | wc -l)
echo "Uninstalling tailscale in background; log: $LOG"
echo "(If you're connected over tailscale, this session will drop.)"
if command -v setsid >/dev/null 2>&1; then
    setsid nohup sh "$WORKER" >>"$LOG" 2>&1 </dev/null &
else
    nohup sh "$WORKER" >>"$LOG" 2>&1 </dev/null &
fi
PID=$!

# If the session survives (not connected via tailscale), wait and show the result
while kill -0 "$PID" 2>/dev/null; do sleep 1; done
tail -n +"$((START + 1))" "$LOG"

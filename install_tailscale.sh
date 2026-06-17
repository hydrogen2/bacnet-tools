#!/bin/sh
set -e

# Install tailscale with userspace networking and SSH enabled.
# Supports x86_64 and armv7l. Survives reboot via systemd override.

if [ "$(id -u)" -ne 0 ]; then
    echo "Run as root" >&2
    exit 1
fi

# Install tailscale if not present
if ! command -v tailscale >/dev/null 2>&1; then
    curl -fsSL https://tailscale.com/install.sh | sh
fi

# Override systemd unit for userspace networking
mkdir -p /etc/systemd/system/tailscaled.service.d
cat > /etc/systemd/system/tailscaled.service.d/userspace.conf <<'EOF'
[Service]
ExecStart=
ExecStart=/usr/sbin/tailscaled --tun=userspace-networking --state=/var/lib/tailscale/tailscaled.state --socket=/run/tailscale/tailscaled.sock
EOF

systemctl daemon-reload
systemctl enable --now tailscaled
systemctl restart tailscaled

# Wait for tailscaled to be ready
sleep 2

tailscale up --ssh

echo "Done. tailscale status:"
tailscale status

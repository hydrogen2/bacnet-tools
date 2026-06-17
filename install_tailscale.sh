#!/bin/sh
# Install tailscale with userspace networking and SSH enabled.
# Supports x86_64, aarch64, armv7l. Survives reboot via systemd override.

if [ "$(id -u)" -ne 0 ]; then
    echo "Run as root" >&2
    exit 1
fi

# Install tailscale if not present
if ! command -v tailscale >/dev/null 2>&1; then
    curl -fsSL https://tailscale.com/install.sh | sh || true
fi
if ! command -v tailscale >/dev/null 2>&1; then
    echo "Package install failed, falling back to static binary"
    TS_VER="1.82.5"
    case "$(uname -m)" in
        x86_64)  TS_ARCH="amd64" ;;
        aarch64) TS_ARCH="arm64" ;;
        armv7l)  TS_ARCH="arm"   ;;
        *)       echo "Unsupported arch: $(uname -m)" >&2; exit 1 ;;
    esac
    curl -fsSL "https://pkgs.tailscale.com/stable/tailscale_${TS_VER}_${TS_ARCH}.tgz" | tar xz -C /tmp
    cp /tmp/tailscale_${TS_VER}_${TS_ARCH}/tailscale /usr/sbin/
    cp /tmp/tailscale_${TS_VER}_${TS_ARCH}/tailscaled /usr/sbin/
    cp /tmp/tailscale_${TS_VER}_${TS_ARCH}/systemd/tailscaled.service /etc/systemd/system/
    rm -rf "/tmp/tailscale_${TS_VER}_${TS_ARCH}"
fi

# Ensure runtime dirs and env file exist (some systemd versions
# fail to auto-create RuntimeDirectory/StateDirectory)
mkdir -p /run/tailscale /var/lib/tailscale /var/cache/tailscale
touch /etc/default/tailscaled

# Override systemd unit for userspace networking
mkdir -p /etc/systemd/system/tailscaled.service.d
cat > /etc/systemd/system/tailscaled.service.d/userspace.conf <<'EOF'
[Service]
Type=simple
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

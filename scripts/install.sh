#!/usr/bin/env bash
# install.sh — mqvpn server setup for Ubuntu/Debian
#
# Usage:
#   curl -fsSL https://github.com/mp0rta/mqvpn/releases/latest/download/install.sh | sudo bash
#   curl -fsSL .../install.sh | sudo bash -s -- --port 10020 --subnet 10.8.0.0/24
#   curl -fsSL .../install.sh | sudo bash -s -- --uninstall
#   curl -fsSL .../install.sh | sudo bash -s -- --purge

set -euo pipefail

REPO="mp0rta/mqvpn"
INSTALL_PREFIX="/usr/local"
DEFAULT_PORT=443
DEFAULT_SUBNET="10.0.0.0/24"

# --- Helpers ---
info()  { echo "[*] $*"; }
ok()    { echo "[+] $*"; }
warn()  { echo "[!] $*" >&2; }
err()   { echo "[!] $*" >&2; exit 1; }

# Generate a per-install ULA prefix per RFC 4193: fd + 40 random bits, /112.
# /112 keeps the 16-bit host pool (matches IPv4 /24) and stays within the
# [96,126] range required by mqvpn_addr_pool_init6.
gen_subnet6() {
    local hex
    hex=$(openssl rand -hex 5)
    printf 'fd%s:%s:%s::/112' "${hex:0:2}" "${hex:2:4}" "${hex:6:4}"
}

# Probe whether IPv6 is usable on this host. Skipping Subnet6 generation when
# the kernel has IPv6 disabled (ipv6.disable=1) or ip6tables is unavailable
# avoids breaking IPv4-only deployments — mqvpn-server-nat.sh runs sysctl /
# ip6tables under set -e and would otherwise fail ExecStartPre.
probe_ipv6() {
    [ -d /proc/sys/net/ipv6 ] || return 1
    [ -w /proc/sys/net/ipv6/conf/all/forwarding ] || return 1
    ip6tables -L FORWARD >/dev/null 2>&1 || return 1
    return 0
}

# --- Parse arguments ---
PORT="$DEFAULT_PORT"
SUBNET="$DEFAULT_SUBNET"
SUBNET6=""
UNINSTALL=0
PURGE=0
START=0

require_arg() { [ "$1" -ge 2 ] || err "$2 requires an argument"; }

while [[ $# -gt 0 ]]; do
    case "$1" in
        --port)    require_arg "$#" --port;    PORT="$2";    shift 2 ;;
        --subnet)  require_arg "$#" --subnet;  SUBNET="$2";  shift 2 ;;
        --subnet6) require_arg "$#" --subnet6; SUBNET6="$2"; shift 2 ;;
        --start)   START=1; shift ;;
        --uninstall) UNINSTALL=1; shift ;;
        --purge)   PURGE=1; UNINSTALL=1; shift ;;
        --help|-h)
            echo "Usage: install.sh [--port PORT] [--subnet CIDR] [--subnet6 CIDR6] [--start] [--uninstall] [--purge]"
            exit 0 ;;
        *) echo "Unknown option: $1"; exit 1 ;;
    esac
done

# --- Uninstall ---
do_uninstall() {
    info "Stopping mqvpn-server..."
    systemctl stop mqvpn-server 2>/dev/null || true
    systemctl disable mqvpn-server 2>/dev/null || true

    info "Removing files..."
    rm -f "$INSTALL_PREFIX/bin/mqvpn"
    rm -f "$INSTALL_PREFIX/lib/libmqvpn.so"*
    rm -f "$INSTALL_PREFIX/lib/libxquic.so"
    rm -rf "$INSTALL_PREFIX/lib/mqvpn"
    rm -f /lib/systemd/system/mqvpn-server.service
    rm -f /lib/systemd/system/mqvpn-client@.service
    systemctl daemon-reload 2>/dev/null || true
    ldconfig 2>/dev/null || true

    if [ "$PURGE" -eq 1 ]; then
        info "Purging configuration..."
        rm -rf /etc/mqvpn
    else
        info "Configuration preserved in /etc/mqvpn"
    fi

    ok "mqvpn uninstalled."
    exit 0
}

if [ "$UNINSTALL" -eq 1 ]; then
    do_uninstall
fi

# --- Step 1: Environment checks ---
info "[1/6] Detecting system..."

[ "$(id -u)" -eq 0 ] || err "This script must be run as root (use sudo)"

# OS check
if [ -f /etc/os-release ]; then
    . /etc/os-release
    case "$ID" in
        ubuntu|debian) ;;
        *) err "Unsupported OS: $ID. This script supports Ubuntu/Debian only." ;;
    esac
else
    err "Cannot detect OS (/etc/os-release not found)"
fi

# Architecture
ARCH=$(dpkg --print-architecture 2>/dev/null || uname -m)
case "$ARCH" in
    amd64|x86_64) ARCH="amd64" ;;
    arm64|aarch64) ARCH="arm64" ;;
    *) err "Unsupported architecture: $ARCH" ;;
esac

# Dependencies (ip/sysctl/ip6tables required by mqvpn-server-nat.sh)
for cmd in curl openssl systemctl iptables ip sysctl ip6tables; do
    command -v "$cmd" >/dev/null 2>&1 || err "Required command not found: $cmd"
done

ok "Detected ${PRETTY_NAME:-$ID}, $ARCH"

# --- Step 2: Download ---
info "[2/6] Downloading mqvpn..."

VERSION=$(curl -fsSL "https://api.github.com/repos/$REPO/releases/latest" \
    | grep '"tag_name"' | head -1 | sed 's/.*"v\([^"]*\)".*/\1/')
[ -n "$VERSION" ] || err "Failed to detect latest version"

TARBALL="mqvpn_${VERSION}_${ARCH}.tar.gz"
DOWNLOAD_URL="https://github.com/$REPO/releases/latest/download/$TARBALL"
CHECKSUMS_URL="https://github.com/$REPO/releases/latest/download/SHA256SUMS"

WORK_DIR=$(mktemp -d)
trap 'rm -rf "$WORK_DIR"' EXIT

curl -fsSL -o "$WORK_DIR/$TARBALL" "$DOWNLOAD_URL" || err "Failed to download $TARBALL"
curl -fsSL -o "$WORK_DIR/SHA256SUMS" "$CHECKSUMS_URL" || err "Failed to download SHA256SUMS"

ok "Downloaded mqvpn v$VERSION"

# --- Step 3: Verify + Install ---
info "[3/6] Installing to $INSTALL_PREFIX/..."

cd "$WORK_DIR"
grep "$TARBALL" SHA256SUMS | sha256sum -c --quiet || err "Checksum verification failed"
tar xzf "$TARBALL"

install -m 755 bin/mqvpn "$INSTALL_PREFIX/bin/mqvpn"
install -m 644 lib/libmqvpn.so.* "$INSTALL_PREFIX/lib/" 2>/dev/null || true
install -m 644 lib/libxquic.so "$INSTALL_PREFIX/lib/"
mkdir -p "$INSTALL_PREFIX/lib/mqvpn"
install -m 755 lib/mqvpn/mqvpn-server-nat.sh "$INSTALL_PREFIX/lib/mqvpn/"
install -m 644 systemd/mqvpn-server.service /lib/systemd/system/
install -m 644 systemd/mqvpn-client@.service /lib/systemd/system/
ldconfig

ok "Installed to $INSTALL_PREFIX"

# --- Step 4: Generate TLS certificate ---
info "[4/6] Generating TLS certificate..."

mkdir -p /etc/mqvpn
if [ ! -f /etc/mqvpn/server.crt ] || [ ! -f /etc/mqvpn/server.key ]; then
    openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 \
        -keyout /etc/mqvpn/server.key -out /etc/mqvpn/server.crt \
        -days 365 -nodes -subj "/CN=mqvpn" 2>/dev/null
    chmod 600 /etc/mqvpn/server.key /etc/mqvpn/server.crt
    ok "Generated self-signed certificate"
else
    ok "Certificate already exists, skipping"
fi

# --- Step 5: Configure NAT ---
info "[5/6] Configuring NAT and IP forwarding..."

# Write server config
if [ ! -f /etc/mqvpn/server.conf ]; then
    # Generate PSK
    AUTH_KEY=$("$INSTALL_PREFIX/bin/mqvpn" --genkey) || err "Failed to generate auth key"
    [ -n "$AUTH_KEY" ] || err "Empty auth key generated"

    # Auto-generate Subnet6 only when IPv6 is usable. Explicit --subnet6 is
    # honored regardless (the caller takes responsibility).
    if [ -z "$SUBNET6" ]; then
        if probe_ipv6; then
            SUBNET6=$(gen_subnet6)
        else
            warn "IPv6 unavailable (kernel disabled or ip6tables missing); skipping Subnet6"
        fi
    fi

    {
        echo "[Interface]"
        echo "Listen = 0.0.0.0:$PORT"
        echo "Subnet = $SUBNET"
        [ -n "$SUBNET6" ] && echo "Subnet6 = $SUBNET6"
        echo "TunName = mqvpn0"
        echo "LogLevel = info"
        echo
        echo "[TLS]"
        echo "Cert = /etc/mqvpn/server.crt"
        echo "Key = /etc/mqvpn/server.key"
        echo
        echo "[Auth]"
        echo "Key = $AUTH_KEY"
        echo "MaxClients = 64"
        echo
        echo "[Multipath]"
        echo "Scheduler = wlb"
    } > /etc/mqvpn/server.conf
    chmod 600 /etc/mqvpn/server.conf
    ok "Generated /etc/mqvpn/server.conf"
else
    ok "Config already exists, skipping"
    # Parse actual values from existing config for status display
    # AUTH_KEY must come from [Auth] section, not [TLS] (which also has Key=)
    AUTH_KEY=$(sed -n '/^\[Auth\]/,/^\[/{ s/^[[:space:]]*Key[[:space:]]*=[[:space:]]*\(.*\)/\1/p; }' /etc/mqvpn/server.conf | head -1 | tr -d '[:space:]')
    PORT=$(sed -n 's/^[[:space:]]*Listen[[:space:]]*=[[:space:]]*[^:]*:\([0-9]*\)/\1/p' /etc/mqvpn/server.conf | head -1 | tr -d '[:space:]')
    SUBNET=$(sed -n 's/^[[:space:]]*Subnet[[:space:]]*=[[:space:]]*\([^[:space:]].*\)/\1/p' /etc/mqvpn/server.conf | head -1 | tr -d '[:space:]')
    SUBNET6=$(sed -n 's/^[[:space:]]*Subnet6[[:space:]]*=[[:space:]]*\([^[:space:]].*\)/\1/p' /etc/mqvpn/server.conf | head -1 | tr -d '[:space:]')
    PORT="${PORT:-443}"
    SUBNET="${SUBNET:-10.0.0.0/24}"
fi

# --- Step 6: Start or show next steps ---
systemctl daemon-reload

if [ "$START" -eq 1 ]; then
    info "[6/6] Starting mqvpn-server..."
    systemctl enable --now mqvpn-server

    sleep 1
    if systemctl is-active --quiet mqvpn-server; then
        SERVER_IP=$(curl -fsSL -4 --max-time 5 ifconfig.me 2>/dev/null || hostname -I | awk '{print $1}')

        echo ""
        ok "mqvpn server is running"
        echo ""
        echo "  Auth key:  $AUTH_KEY"
        echo "  Port:      ${PORT}/udp"
        echo "  Subnet:    $SUBNET"
        [ -n "${SUBNET6:-}" ] && echo "  Subnet6:   $SUBNET6"
        echo ""
        echo "  Client:"
        echo "    sudo mqvpn --mode client --server ${SERVER_IP}:${PORT} \\"
        echo "        --auth-key \"$AUTH_KEY\" --insecure"
        echo ""
    else
        err "mqvpn-server failed to start. Check: journalctl -u mqvpn-server"
    fi
else
    echo ""
    ok "mqvpn installed successfully"
    echo ""
    echo "  Config:    /etc/mqvpn/server.conf"
    echo "  Auth key:  $AUTH_KEY"
    echo "  Port:      ${PORT}/udp"
    echo "  Subnet:    $SUBNET"
    [ -n "${SUBNET6:-}" ] && echo "  Subnet6:   $SUBNET6"
    echo ""
    echo "  To start now:"
    echo "    sudo systemctl start mqvpn-server"
    echo ""
    echo "  To enable on boot and start:"
    echo "    sudo systemctl enable --now mqvpn-server"
    echo ""
fi

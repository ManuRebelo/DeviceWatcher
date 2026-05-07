#!/usr/bin/env bash
# DeviceWatcher setup script
# Installs system dependencies, creates a Python virtualenv, and installs Python packages.
# Run with: bash setup.sh

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

ok()   { echo -e "${GREEN}[OK]${NC}  $*"; }
warn() { echo -e "${YELLOW}[WARN]${NC} $*"; }
err()  { echo -e "${RED}[ERR]${NC}  $*"; }

echo "=== DeviceWatcher Setup ==="
echo

# ── System dependencies ────────────────────────────────────────────────────────

echo ">> Checking system dependencies..."

MISSING_PKGS=()

check_cmd() {
    command -v "$1" &>/dev/null || MISSING_PKGS+=("$2")
}

check_cmd python3  python3
check_cmd pip3     python3-pip

# bluez provides hcitool (BT Classic discovery) and btvhci
dpkg -l bluez &>/dev/null 2>&1 || MISSING_PKGS+=("bluez")

# aircrack-ng / iw for Wi-Fi monitor mode
check_cmd iw       iw

if [ ${#MISSING_PKGS[@]} -gt 0 ]; then
    warn "Missing system packages: ${MISSING_PKGS[*]}"
    echo "   Install with: sudo apt install ${MISSING_PKGS[*]}"
    echo "   Or run:       sudo bash setup.sh  (to let this script install them)"

    if [ "$EUID" -eq 0 ]; then
        echo ">> Running as root — installing system packages..."
        apt-get update -q
        apt-get install -y -q "${MISSING_PKGS[@]}"
        ok "System packages installed."
    else
        err "Re-run as root to auto-install, or install manually and re-run setup.sh."
        exit 1
    fi
else
    ok "All system packages present."
fi

# ── Python virtualenv ──────────────────────────────────────────────────────────

VENV_DIR="$(dirname "$0")/venv"

if [ ! -d "$VENV_DIR" ]; then
    echo ">> Creating Python virtualenv at $VENV_DIR..."
    python3 -m venv "$VENV_DIR"
    ok "Virtualenv created."
else
    ok "Virtualenv already exists — skipping creation."
fi

PIP="$VENV_DIR/bin/pip"
PYTHON="$VENV_DIR/bin/python"

echo ">> Upgrading pip..."
"$PIP" install --quiet --upgrade pip

echo ">> Installing Python dependencies..."
"$PIP" install --quiet -r "$(dirname "$0")/requirements.txt"
ok "Python dependencies installed."

# ── Wi-Fi adapter check ────────────────────────────────────────────────────────

echo
echo "=== Setup complete ==="
echo
echo "Usage:"
echo "  Activate venv:    source venv/bin/activate"
echo
echo "  Wi-Fi only:       sudo venv/bin/python DeviceWatcher.py --wifi wlan1mon"
echo "  BLE only:         sudo venv/bin/python DeviceWatcher.py --ble 0"
echo "  BT Classic only:  sudo venv/bin/python DeviceWatcher.py --bt 0"
echo "  All at once:      sudo venv/bin/python DeviceWatcher.py --wifi wlan1mon --bt 0 --ble 1"
echo
echo "  Dashboard:        http://localhost:5000"
echo
echo "NOTE: Raw socket capture (Wi-Fi/BLE/BT) requires root or CAP_NET_RAW."
echo "NOTE: For Wi-Fi, put the adapter into monitor mode first:"
echo "        sudo airmon-ng start wlan1"
echo "        sudo iwconfig wlan1mon channel 6"

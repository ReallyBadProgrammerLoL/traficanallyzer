#!/usr/bin/env bash
# Automated setup for the NIDS. Creates a venv that can also see system
# packages (handy on Arch/CachyOS where scapy/pyahocorasick are prebuilt),
# then installs anything missing from requirements.txt.
set -euo pipefail

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VENV="$DIR/.venv"

echo "[*] Creating virtualenv at $VENV"
python -m venv --system-site-packages "$VENV"

echo "[*] Installing Python dependencies"
"$VENV/bin/pip" install --quiet --upgrade pip
"$VENV/bin/pip" install --quiet -r "$DIR/requirements.txt"

echo
echo "[+] Done."
echo "    Launch the live dashboard (needs root, protection OFF by default):"
echo "        ./start.sh"
echo "    Or replay a pcap offline (no root):"
echo "        ./run.sh --pcap attack.pcap --web"

#!/usr/bin/env bash
# Offline pcap analysis (the old IDS path). For the live NIDS/IPS dashboard
# use ./start.sh instead. All args pass through to main.py.
#   ./run.sh --pcap attack.pcap --home-net 10.0.0.0/24
set -euo pipefail

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PY="$DIR/.venv/bin/python"
[ -x "$PY" ] || PY="$(command -v python)"

exec sudo "$PY" "$DIR/main.py" "$@"

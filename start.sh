#!/usr/bin/env bash
# Single entry point for the NIDS/IPS.
#
# Ensures the venv exists (creating it with --system-site-packages so the
# system scapy/pyahocorasick/netfilterqueue are visible), then launches the
# web control-plane as root.  Protection starts OFF — the network is never
# touched until you enable PROTECT mode from the dashboard, so this is safe
# to run on a machine with a live connection.
#
#   ./start.sh                 # dashboard on http://127.0.0.1:8080
#   ./start.sh --port 9000     # any app.py flag passes through
set -euo pipefail

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$DIR"

VENV="$DIR/.venv"
PY="$VENV/bin/python"

if [ ! -x "$PY" ]; then
    echo "[*] Creating venv (first run)…"
    python -m venv --system-site-packages "$VENV"
    "$PY" -m pip install --quiet -r requirements.txt
fi

# netfilterqueue may live in the invoking user's ~/.local, which root's Python
# does not search under sudo.  If a clean root-like interpreter can't import it,
# bridge the user-site path through PYTHONPATH; if it's installed system-wide
# this stays empty and changes nothing.
# PYTHONNOUSERSITE=1 drops ~/.local from the search path, so this import test
# sees exactly what root will see under sudo (system site-packages only).
PYPATH_ARG=()
if ! PYTHONNOUSERSITE=1 "$PY" -c 'import netfilterqueue' >/dev/null 2>&1; then
    USERSITE="$("$PY" -c 'import site; print(site.getusersitepackages())')"
    PYPATH_ARG=("PYTHONPATH=${USERSITE}${PYTHONPATH:+:$PYTHONPATH}")
    echo "[*] netfilterqueue not system-wide — bridging $USERSITE"
fi

echo "[*] Launching dashboard as root (protection OFF by default)…"
exec sudo env "${PYPATH_ARG[@]}" "$PY" "$DIR/app.py" "$@"

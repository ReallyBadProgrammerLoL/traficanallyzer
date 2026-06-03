#!/usr/bin/env bash
# Demo network for the IPS: an isolated veth pair + namespace so you can attack
# a "victim" without touching the real network.
#
# The host owns 10.0.0.1 on veth0; the namespace owns 10.0.0.2 on veth1.
# Traffic between them crosses veth0's INPUT/OUTPUT chains — exactly what
# firewall.py manages — so set the dashboard scope to iface veth0,
# HOME_NET 10.0.0.0/24, then enable Protection.
#
#   sudo ./netns.sh up      # create testns + veth0/veth1, assign IPs
#   sudo ./netns.sh down    # tear everything down
#   sudo ./netns.sh attack  # run the attack suite from inside the namespace
#
# (FORWARD NFQUEUE rules are NOT needed: the host owns the IP, so host<->ns
#  traffic goes through INPUT/OUTPUT, never FORWARD.)
set -euo pipefail

NS=testns
HOST_IF=veth0
NS_IF=veth1
HOST_IP=10.0.0.1
NS_IP=10.0.0.2
CIDR=24

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

if [ "$(id -u)" -ne 0 ]; then
    echo "Run as root:  sudo $0 $*" >&2
    exit 1
fi

down() {
    ip netns del "$NS" 2>/dev/null || true
    ip link del "$HOST_IF" 2>/dev/null || true   # deletes the peer too
    echo "[*] demo network removed"
}

up() {
    down                                          # start from a clean slate
    ip netns add "$NS"
    ip link add "$HOST_IF" type veth peer name "$NS_IF"
    ip link set "$NS_IF" netns "$NS"

    ip link set "$HOST_IF" up
    ip addr add "$HOST_IP/$CIDR" dev "$HOST_IF"

    ip netns exec "$NS" ip link set lo up
    ip netns exec "$NS" ip link set "$NS_IF" up
    ip netns exec "$NS" ip addr add "$NS_IP/$CIDR" dev "$NS_IF"

    echo "[*] demo network up:"
    echo "      host   $HOST_IP  on $HOST_IF"
    echo "      victim $NS_IP  in netns '$NS'"
    echo
    echo "    Dashboard scope: iface $HOST_IF, HOME_NET 10.0.0.0/$CIDR, then PROTECT."
    echo "    Attack:          sudo ./netns.sh attack"
}

attack() {
    local py="$DIR/.venv/bin/python"
    [ -x "$py" ] || py=python
    # DNS/UDP first: the port-scan/sweep below trip the correlation auto-block
    # and quarantine this source for ~30s, which would otherwise swallow the
    # later UDP probes (they'd be dropped as "Quarantined scanner", not by their
    # own DPI/signature). connect runs first to warm the ARP entry for the host.
    for scen in connect dns-evil dns-tunnel port-scan sweep; do
        echo "=== $scen ==="
        ip netns exec "$NS" "$py" "$DIR/simulate.py" "$scen" --target "$HOST_IP" || true
    done
}

case "${1:-}" in
    up)     up ;;
    down)   down ;;
    attack) attack ;;
    *) echo "usage: sudo $0 {up|down|attack}" >&2; exit 1 ;;
esac

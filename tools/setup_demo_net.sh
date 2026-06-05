#!/usr/bin/env bash
# setup_demo_net.sh — Create bridge + 5 netns with non-loopback IPs.
# Agents in separate netns can enforce iptables/nftables isolation against
# non-loopback targets, bypassing PolicyEnforcer::is_loopback() safety block.
set -euo pipefail

if [[ $EUID -ne 0 ]]; then
    echo "[FATAL] This script requires root. Run with: sudo ./tools/setup_demo_net.sh"
    exit 1
fi

# ── bridge ─────────────────────────────────────────────────────────────
echo "[SETUP] Creating bridge br-neuro..."
ip link add br-neuro type bridge 2>/dev/null || true
ip link set br-neuro up

# ── namespaces + veth pairs ────────────────────────────────────────────
# IFNAMSIZ on Linux is 16 bytes (including null). Keep all names <= 15 chars.
declare -A IPS=(
    ["ALPHA"]="192.168.50.2"
    ["BRAVO"]="192.168.50.3"
    ["CHARLIE"]="192.168.50.4"
    ["DELTA"]="192.168.50.5"
    ["ECHO"]="192.168.50.6"
)

for ns in ALPHA BRAVO CHARLIE DELTA ECHO; do
    echo "[SETUP] Creating namespace $ns..."
    ip netns add $ns 2>/dev/null || true

    host_veth="v-${ns}"       # e.g. "v-ALPHA"    (7 chars)
    peer_veth="vp-${ns}"      # e.g. "vp-ALPHA"   (8 chars)

    ip link add "$host_veth" type veth peer name "$peer_veth"
    ip link set "$peer_veth" netns $ns
    ip link set "$host_veth" master br-neuro
    ip link set "$host_veth" up

    ip netns exec $ns ip link set "$peer_veth" up
    ip netns exec $ns ip link set lo up
    ip netns exec $ns ip addr add ${IPS[$ns]}/24 dev "$peer_veth"
    # Required for UDP broadcast to 255.255.255.255 — the subnet route
    # alone only covers 192.168.50.0/24, not the global broadcast address.
    ip netns exec $ns ip route add 255.255.255.255/32 dev "$peer_veth" 2>/dev/null || true
done

# ── forwarding ─────────────────────────────────────────────────────────
echo "[SETUP] Enabling IP + broadcast forwarding..."
sysctl -w net.ipv4.ip_forward=1 >/dev/null
sysctl -w net.ipv4.conf.br-neuro.bc_forwarding=1 >/dev/null

echo ""
echo "[SETUP] 5-node mesh ready. IPs:"
for ns in ALPHA BRAVO CHARLIE DELTA ECHO; do
    printf "  %-8s  %s\n" "$ns" "${IPS[$ns]}"
done
echo ""
echo "[SETUP] Tear down with:"
echo "  sudo ./tools/teardown_demo_net.sh"

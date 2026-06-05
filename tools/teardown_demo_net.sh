#!/usr/bin/env bash
# teardown_demo_net.sh — Destroy bridge + 5 netns.
# Order matters: veths attached to bridge MUST be deleted before the bridge.
set -euo pipefail

if [[ $EUID -ne 0 ]]; then
    echo "[FATAL] This script requires root. Run with: sudo ./tools/teardown_demo_net.sh"
    exit 1
fi

echo "[TEARDOWN] Killing agents..."
pkill -9 neuro_agent 2>/dev/null || true
sleep 1

# ── veths first (attached to bridge) ───────────────────────────────────
echo "[TEARDOWN] Removing veth pairs..."
for v in $(ip link show 2>/dev/null | grep -oP 'v(p)?-\w+' | sort -u); do
    ip link delete "$v" 2>/dev/null || true
done

# ── namespaces ─────────────────────────────────────────────────────────
echo "[TEARDOWN] Removing namespaces..."
for ns in ALPHA BRAVO CHARLIE DELTA ECHO; do
    ip netns delete "$ns" 2>/dev/null || true
done

# ── bridge ─────────────────────────────────────────────────────────────
echo "[TEARDOWN] Removing bridge..."
ip link delete br-neuro 2>/dev/null || true

# ── stale state ────────────────────────────────────────────────────────
rm -rf logs /tmp/neuro_mesh_* journal_*.log /sys/fs/bpf/neuro_mesh* keystore_* /tmp/neuro_mesh_token 2>/dev/null

echo "[TEARDOWN] Clean."

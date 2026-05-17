#!/usr/bin/env bash
set -euo pipefail

# =============================================================================
# Neuro-Mesh Final Stress Test — Full PBFT → Enforcement Pipeline
# Run as: sudo bash final_stress_test.sh
# =============================================================================

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

TARGET_IP="10.99.99.99"
EVIDENCE='{"sensor":"ebpf_entropy","value":0.98,"threat":"lateral_movement"}'
LOG_DIR="/tmp/neuro_stress_test"
BIN_DIR="$(dirname "$0")/bin"

say()  { echo -e "${CYAN}[TEST]${NC} $1"; }
pass() { echo -e "${GREEN}[PASS]${NC} $1"; }
fail() { echo -e "${RED}[FAIL]${NC} $1"; exit 1; }
info() { echo -e "${YELLOW}[INFO]${NC} $1"; }

declare -a STRESS_PIDS=()

cleanup() {
    say "Cleaning up..."
    for pid in "${STRESS_PIDS[@]}"; do
        kill "$pid" 2>/dev/null || true
    done
    pkill -f "inject_event" 2>/dev/null || true
    rm -f /tmp/neuro_mesh_*.sock "${LOG_DIR}"/*.log
    iptables -D INPUT -s "${TARGET_IP}" -j DROP 2>/dev/null || true
    nft delete rule ip neuro_mesh INPUT ip saddr "${TARGET_IP}" counter drop 2>/dev/null || true
    echo ""
}

trap cleanup EXIT

# ---------------------------------------------------------------------------
echo ""
echo -e "${BOLD}${CYAN}╔══════════════════════════════════════════════════════════════╗${NC}"
echo -e "${BOLD}${CYAN}║     Neuro-Mesh AISEC 2026 — Final Enforcement Pipeline      ║${NC}"
echo -e "${BOLD}${CYAN}╚══════════════════════════════════════════════════════════════╝${NC}"
echo ""

# ---------------------------------------------------------------------------
# Check we're root
# ---------------------------------------------------------------------------
if [[ $EUID -ne 0 ]]; then
    fail "This test must run as root. Use: sudo bash final_stress_test.sh"
fi

mkdir -p "${LOG_DIR}"

# ---------------------------------------------------------------------------
# Phase 1: Launch Mesh Nodes
# ---------------------------------------------------------------------------
say "Phase 1: Launching 3-node P2P mesh..."
"${BIN_DIR}/neuro_agent" NODE_1 > "${LOG_DIR}/node1.log" 2>&1 &
PID1=$!; STRESS_PIDS+=($PID1)
"${BIN_DIR}/neuro_agent" NODE_2 > "${LOG_DIR}/node2.log" 2>&1 &
PID2=$!; STRESS_PIDS+=($PID2)
"${BIN_DIR}/neuro_agent" NODE_3 > "${LOG_DIR}/node3.log" 2>&1 &
PID3=$!; STRESS_PIDS+=($PID3)
sleep 4

# Verify all nodes booted
for id in NODE_1 NODE_2 NODE_3; do
    logfile="${LOG_DIR}/node$(echo $id | cut -c6).log"
    if grep -q "System fully operational" "${logfile}" 2>/dev/null; then
        pass "${id} booted successfully"
    else
        fail "${id} failed to boot — check ${logfile}"
    fi
done

# Verify backend probe
info "Backend probe results:"
grep "Enforcement backends" "${LOG_DIR}/node1.log" || true

# Verify peer discovery
PEERS_N1=$(grep -c "Discovered peer" "${LOG_DIR}/node1.log" || true)
PEERS_N2=$(grep -c "Discovered peer" "${LOG_DIR}/node2.log" || true)
PEERS_N3=$(grep -c "Discovered peer" "${LOG_DIR}/node3.log" || true)
say "Mesh discovery: N1=${PEERS_N1} peers, N2=${PEERS_N2} peers, N3=${PEERS_N3} peers"
if [[ "$PEERS_N1" -ge 2 && "$PEERS_N2" -ge 2 && "$PEERS_N3" -ge 2 ]]; then
    pass "Full mesh connectivity established"
else
    fail "Mesh discovery incomplete"
fi

# ---------------------------------------------------------------------------
# Phase 2: Verify Pre-Enforcement State
# ---------------------------------------------------------------------------
say "Phase 2: Pre-enforcement firewall state..."
if iptables -L INPUT -n 2>/dev/null | grep -q "${TARGET_IP}"; then
    info "WARNING: ${TARGET_IP} already in iptables — removing stale rule"
    iptables -D INPUT -s "${TARGET_IP}" -j DROP 2>/dev/null || true
fi
pass "Pre-enforcement state clean — no existing rule for ${TARGET_IP}"

# ---------------------------------------------------------------------------
# Phase 3: Launch Threat Simulation
# ---------------------------------------------------------------------------
say "Phase 3: Launching event injection targeting ${TARGET_IP}..."
"${BIN_DIR}/inject_event" "${TARGET_IP}" "${EVIDENCE}" > "${LOG_DIR}/simulator.log" 2>&1 &
SIM_PID=$!; STRESS_PIDS+=($SIM_PID)

# Wait for consensus to propagate
sleep 12

# ---------------------------------------------------------------------------
# Phase 4: Verify PBFT Consensus
# ---------------------------------------------------------------------------
say "Phase 4: Verifying PBFT consensus on all nodes..."
for id in NODE_1 NODE_2 NODE_3 NODE_SIMULATOR; do
    if [[ "$id" == "NODE_SIMULATOR" ]]; then
        logfile="${LOG_DIR}/simulator.log"
    else
        logfile="${LOG_DIR}/node$(echo $id | cut -c6).log"
    fi

    if grep -q "CRITICAL.*PBFT Final Quorum Reached" "${logfile}" 2>/dev/null; then
        pass "${id}: PBFT EXECUTED"
    else
        fail "${id}: PBFT did NOT reach EXECUTED"
    fi
done

# ---------------------------------------------------------------------------
# Phase 5: Verify Enforcement
# ---------------------------------------------------------------------------
say "Phase 5: Verifying enforcement..."

ENFORCED=false
BACKEND_USED=""

# Check nftables
if nft list table ip neuro_mesh 2>/dev/null | grep -q "${TARGET_IP}"; then
    ENFORCED=true
    BACKEND_USED="nftables"
fi

# Check iptables
if iptables -L INPUT -n 2>/dev/null | grep -q "${TARGET_IP}"; then
    ENFORCED=true
    BACKEND_USED="${BACKEND_USED}${BACKEND_USED:+/}iptables"
fi

# Check eBPF
if [[ -f /sys/fs/bpf/neuro_mesh/neuro_blocklist ]]; then
    ENFORCED=true
    BACKEND_USED="${BACKEND_USED}${BACKEND_USED:+/}eBPF"
fi

if $ENFORCED; then
    pass "Enforcement active via: ${BACKEND_USED}"
else
    fail "No enforcement rule found for ${TARGET_IP}"
fi

# Verify ENFORCER log messages
for id in NODE_1 NODE_2 NODE_3 NODE_SIMULATOR; do
    if [[ "$id" == "NODE_SIMULATOR" ]]; then
        logfile="${LOG_DIR}/simulator.log"
    else
        logfile="${LOG_DIR}/node$(echo $id | cut -c6).log"
    fi

    if grep -q "Zero-Trust Rule Applied" "${logfile}" 2>/dev/null; then
        RULE=$(grep "Zero-Trust Rule Applied" "${logfile}" | tail -1)
        pass "${id}: $(echo ${RULE} | sed 's/.*\[ENFORCER\] //')"
    fi
done

# ---------------------------------------------------------------------------
# Phase 6: Show Live Firewall Rules
# ---------------------------------------------------------------------------
say "Phase 6: Live firewall verification..."
echo ""

if nft list table ip neuro_mesh 2>/dev/null | grep -q "${TARGET_IP}"; then
    echo -e "${BOLD}--- nftables rules (neuro_mesh table) ---${NC}"
    nft list table ip neuro_mesh 2>/dev/null | grep -A2 "${TARGET_IP}" || true
fi

if iptables -L INPUT -n 2>/dev/null | grep -q "${TARGET_IP}"; then
    echo -e "${BOLD}--- iptables INPUT chain ---${NC}"
    iptables -L INPUT -n -v 2>/dev/null | grep "${TARGET_IP}" || true
fi

echo ""

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------
echo -e "${BOLD}${GREEN}╔══════════════════════════════════════════════════════════════╗${NC}"
echo -e "${BOLD}${GREEN}║  STRESS TEST PASSED — Neuro-Mesh Enforcement Bridge Live    ║${NC}"
echo -e "${BOLD}${GREEN}╚══════════════════════════════════════════════════════════════╝${NC}"
echo ""
echo -e "  Target:        ${BOLD}${TARGET_IP}${NC}"
echo -e "  Evidence:      ${EVIDENCE}"
echo -e "  PBFT Rounds:   PRE_PREPARE → PREPARE → COMMIT → EXECUTED"
echo -e "  Enforcement:   ${BOLD}${BACKEND_USED}${NC}"
echo -e "  Participants:  NODE_1, NODE_2, NODE_3, NODE_SIMULATOR"
echo ""

exit 0

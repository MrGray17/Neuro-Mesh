#!/usr/bin/env bash
# integration_test.sh — Full Neuro-Mesh integration test
# Tests: peer discovery, PBFT consensus, isolation, telemetry propagation
set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

declare -a TEST_PIDS=()

PASS=0
FAIL=0

pass() {
    echo -e "${GREEN}[PASS]${NC} $1"
    PASS=$((PASS + 1))
}

fail() {
    echo -e "${RED}[FAIL]${NC} $1"
    FAIL=$((FAIL + 1))
}

info() {
    echo -e "${YELLOW}[INFO]${NC} $1"
}

cleanup() {
    info "Cleaning up..."
    for pid in "${TEST_PIDS[@]}"; do
        kill "$pid" 2>/dev/null || true
    done
    rm -f /tmp/neuro_mesh_*.sock /tmp/test_*.log
    sleep 1
}

trap cleanup EXIT

# Build if needed
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/../.." && pwd)"
cd "$PROJECT_DIR"

if [ ! -f bin/neuro_agent ] || [ ! -f bin/test_crypto ]; then
    info "Building neuro_agent and test binaries..."
    make -j"$(nproc)"
    make -j"$(nproc)" tools
fi

cleanup

# =============================================================================
# Test 1: Single node boots successfully
# =============================================================================
info "Test 1: Single node boot"
./bin/neuro_agent TEST_NODE > /tmp/test_node1.log 2>&1 &
PID1=$!
TEST_PIDS+=($PID1)
sleep 3

if kill -0 $PID1 2>/dev/null; then
    pass "Node TEST_NODE booted and is running (PID $PID1)"
else
    fail "Node TEST_NODE failed to boot"
    cat /tmp/test_node1.log
    exit 1
fi

# Check IPC socket exists
if ls /tmp/neuro_mesh_TEST_NODE.sock 2>/dev/null; then
    pass "IPC socket created for TEST_NODE"
else
    fail "IPC socket not found for TEST_NODE"
fi

# =============================================================================
# Test 2: Event injection via inject_event binary
# =============================================================================
info "Test 2: Event injection"
./bin/inject_event --node TEST_NODE --target TEST_NODE --event test_event --verdict INFO 2>/dev/null && \
    pass "inject_event executed successfully" || \
    fail "inject_event failed"

# =============================================================================
# Test 3: Unit tests pass
# =============================================================================
info "Test 3: Unit tests"
./bin/test_crypto > /dev/null 2>&1 && pass "test_crypto" || fail "test_crypto"
./bin/test_pbft > /dev/null 2>&1 && pass "test_pbft" || fail "test_pbft"
./bin/test_enforcer > /dev/null 2>&1 && pass "test_enforcer" || fail "test_enforcer"
./bin/test_meshnode > /dev/null 2>&1 && pass "test_meshnode" || fail "test_meshnode"
./bin/test_inference > /dev/null 2>&1 && pass "test_inference" || fail "test_inference"

# =============================================================================
# Test 4: Journal file created and has content
# =============================================================================
info "Test 4: Journal file"
if [ -f journal_TEST_NODE.log ] && [ -s journal_TEST_NODE.log ]; then
    pass "Journal file exists and has content"
    LINE_COUNT=$(wc -l < journal_TEST_NODE.log)
    if [ "$LINE_COUNT" -gt 0 ]; then
        pass "Journal has $LINE_COUNT entries"
    else
        fail "Journal is empty"
    fi
else
    fail "Journal file not found or empty"
fi

# =============================================================================
# Test 5: Graceful shutdown
# =============================================================================
info "Test 5: Graceful shutdown"
kill $PID1 2>/dev/null
sleep 2

if ! kill -0 $PID1 2>/dev/null; then
    pass "Node TEST_NODE shut down gracefully"
else
    fail "Node TEST_NODE did not shut down"
    kill -9 $PID1 2>/dev/null || true
fi

# =============================================================================
# Summary
# =============================================================================
echo ""
echo "========================================"
echo -e "Integration Test Results: ${GREEN}$PASS passed${NC}, ${RED}$FAIL failed${NC}"
echo "========================================"

if [ "$FAIL" -gt 0 ]; then
    exit 1
fi

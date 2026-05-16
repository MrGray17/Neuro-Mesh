#!/usr/bin/env bash
# start_demo.sh — Launch Neuro-Mesh demo with proper cleanup
set -euo pipefail

GREEN='\033[1;32m'
RED='\033[1;31m'
YELLOW='\033[1;33m'
NC='\033[0m'

# Track PIDs for clean shutdown
PIDS=()

cleanup() {
    echo -e "${YELLOW}[CLEANUP] Shutting down Neuro-Mesh...${NC}"
    for pid in "${PIDS[@]}"; do
        if kill -0 "$pid" 2>/dev/null; then
            kill "$pid" 2>/dev/null || true
        fi
    done
    wait 2>/dev/null || true
    rm -f /tmp/neuro_mesh_*.sock
    echo -e "${GREEN}[CLEANUP] Done.${NC}"
}

trap cleanup EXIT INT TERM

echo -e "${YELLOW}[1] Cleaning up residual sockets...${NC}"
rm -f /tmp/neuro_mesh_*.sock
sleep 1

echo -e "${YELLOW}[2] Building...${NC}"
make -j"$(nproc)"

echo -e "${YELLOW}[3] Launching 3-node mesh...${NC}"
mkdir -p logs
for i in 1 2 3; do
    ./bin/neuro_agent "NODE_${i}" > "logs/agent_${i}.log" 2>&1 &
    PIDS+=($!)
    sleep 0.5
done

echo -e "${GREEN}Neuro-Mesh Active. PIDs: ${PIDS[*]}${NC}"
echo -e "${GREEN}Dashboard: http://localhost:8080${NC}"

# Wait for all processes
wait

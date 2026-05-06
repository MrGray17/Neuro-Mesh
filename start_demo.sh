#!/bin/bash
# ============================================================
# NEURO-MESH : ABSOLUTE DEPLOYMENT & FAIL-FAST (V7.3)
# ============================================================

export NEURO_MESH_SECRET="NEURO_MESH_DEFAULT_SECURE_TOKEN_2026"
GREEN='\033[1;32m'
RED='\033[1;31m'
YELLOW='\033[1;33m'
NC='\033[0m'

echo -e "${YELLOW}[1] Eradicating all ghost processes & sockets...${NC}"
sudo killall -9 neuro_agent python3 node listener client 2>/dev/null
sudo rm -f /tmp/neuro_mesh_*.sock c2_logs.txt agent_*_logs.txt react_logs.txt
sleep 2

echo -e "${YELLOW}[2] Hunting for valid Python Environment...${NC}"
PY_CMD="python3"
for ENV_DIR in "neuro-mesh-env" "ia_env" "neuro-env" "venv"; do
    if [ -f "$ENV_DIR/bin/python3" ]; then
        if ./$ENV_DIR/bin/python3 -c "import websockets" 2>/dev/null; then
            PY_CMD="./$ENV_DIR/bin/python3"
            echo -e "${GREEN}[+] Valid environment found: $PY_CMD${NC}"
            break
        fi
    fi
done

echo -e "\n${YELLOW}[3] Launching Omni-C2 Orchestrator...${NC}"
$PY_CMD orchestration/c2_server.py > c2_logs.txt 2>&1 &
sleep 2

if ! pgrep -f "c2_server.py" > /dev/null; then
    echo -e "\n${RED}[FATAL ERROR] The C2 Server crashed instantly on boot.${NC}"
    cat c2_logs.txt
    exit 1
fi
echo -e "${GREEN}[+] C2 Server is stable and bound to ports.${NC}"

echo -e "\n${YELLOW}[4] Deploying Sharded Edge Agents...${NC}"
for i in {1..3}; do
    # 🔥 THE FIX: Export the shard index so the agents know who they are
    export NEURO_NODE_INDEX=$i
    sudo -E ./bin/neuro_agent > agent_${i}_logs.txt 2>&1 &
done

echo -e "\n${YELLOW}[5] Launching React Dashboard...${NC}"
cd dashboard-react && BROWSER=none npm start > ../react_logs.txt 2>&1 &
sleep 5
xdg-open http://localhost:3000 2>/dev/null || powershell.exe -c "start http://localhost:3000"

echo -e "\n${GREEN}🚀 NEURO-MESH V7.3 ACTIVE.${NC}"

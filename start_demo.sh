#!/bin/bash
# ============================================================
# NEURO-MESH : Deployment & Startup (V7.3)
# ============================================================

export NEURO_MESH_SECRET="NEURO_MESH_DEFAULT_SECURE_TOKEN_2026"
GREEN='\033[1;32m'
RED='\033[1;31m'
YELLOW='\033[1;33m'
NC='\033[0m'

echo -e "${YELLOW}[1] Cleaning up residual processes & sockets...${NC}"
sudo killall -9 neuro_agent python3 node listener client 2>/dev/null
sudo rm -f /tmp/neuro_mesh_*.sock ctrl_logs.txt agent_*_logs.txt react_logs.txt
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

echo -e "\n${YELLOW}[3] Launching Mesh Nodes (decentralized — no control plane needed)...${NC}"

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

echo -e "\n${GREEN}Neuro-Mesh V7.3 Active.${NC}"

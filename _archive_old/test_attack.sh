#!/bin/bash
# ============================================================
# NEURO-MESH : SYNTHETIC THREAT GENERATOR (V7.2)
# ============================================================

RED='\033[0;31m'
YELLOW='\033[1;33m'
GREEN='\033[0;32m'
NC='\033[0m'

echo -e "${RED}========================================${NC}"
echo -e "${RED}🔥 NEURO-MESH: TARGETED POSIX ATTACK${NC}"
echo -e "${RED}========================================${NC}"

AGENT_PIDS=$(pgrep -f "neuro_agent")

if [ -z "$AGENT_PIDS" ]; then
    echo -e "${RED}❌ ERROR: No agent running. Launch ./start_demo.sh first.${NC}"
    exit 1
fi

echo -e "${YELLOW}[*] Validating active Neuro-Mesh nodes...${NC}"

# 🔥 THE FIX: Use a payload name that triggers the C++ Inference Engine Blacklist
cp /bin/sleep /tmp/reverse_shell
chmod +x /tmp/reverse_shell

echo -e "${YELLOW}[*] Spawning hostile kernel process (reverse_shell)...${NC}"
/tmp/reverse_shell 5 &
ATTACK_PID=$!

echo -e "${RED}[!] Threat active with PID: $ATTACK_PID${NC}"
echo -e "${GREEN}👀 Watch the Command Center. The eBPF sensor will isolate this node instantly.${NC}"

sleep 6
rm -f /tmp/reverse_shell

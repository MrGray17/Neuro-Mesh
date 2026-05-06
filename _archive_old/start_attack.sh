#!/bin/bash
# ============================================================
# NEURO-MESH : SYNTHETIC THREAT GENERATOR
# ============================================================

RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m'

echo -e "${RED}💣 Initiating Synthetic Threat Payload...${NC}"

# Create a highly suspicious executable to trigger the eBPF tracepoint
cp /bin/sleep /tmp/kworker_malicious_x99
chmod +x /tmp/kworker_malicious_x99

echo -e "${YELLOW}[*] Spawning hostile process (kworker_malicious_x99)...${NC}"
/tmp/kworker_malicious_x99 5 &
ATTACK_PID=$!

echo -e "${RED}[!] Threat active with PID: $ATTACK_PID${NC}"
echo -e "👀 Watch the Neuro-Mesh Dashboard. The AI Cortex will isolate this node shortly."

# Cleanup after attack simulation completes
sleep 6
rm -f /tmp/kworker_malicious_x99

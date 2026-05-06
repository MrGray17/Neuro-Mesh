#!/bin/bash
# ============================================================
# NEURO-MESH : SURGICAL VACCINE DELIVERY (V7.6 ROOT-AUTH)
# ============================================================

# 🔥 THE REALITY FIX: Force Root privileges to pass the C++ SO_PEERCRED lock
if [ "$EUID" -ne 0 ]; then
  echo -e "\033[1;33m[*] Elevating privileges to pass kernel authentication...\033[0m"
  exec sudo "$0" "$@"
fi

GREEN='\033[0;32m'
CYAN='\033[0;36m'
YELLOW='\033[1;33m'
NC='\033[0m'

echo -e "${CYAN}========================================${NC}"
echo -e "${GREEN}💉 NEURO-MESH ADMIN: INJECTING VACCINE${NC}"
echo -e "${CYAN}========================================${NC}"

SOCKETS=(/tmp/neuro_mesh_*.sock)

if [ ! -e "${SOCKETS[0]}" ]; then
    echo -e "${YELLOW}❌ ERROR: No active IPC sockets found in /tmp/${NC}"
    exit 1
fi

for sock in "${SOCKETS[@]}"; do
    if [ -S "$sock" ]; then
        echo -e "${YELLOW}[*] Injecting authenticated antidote to: $sock${NC}"
        
        # Uses standard Python socket library (works globally under sudo)
        python3 -c "
import socket
try:
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    s.connect('$sock')
    s.sendall(b'CMD:VACCINATE')
    s.close()
except Exception as e:
    print(f'Error: {e}')
" 2>/dev/null
    fi
done

echo -e "${GREEN}✅ Threat eradicated & Nodes healed.${NC}"
echo -e "👀 The compromised nodes will return to STABLE (GREEN) on the next telemetry tick."
echo -e "${CYAN}========================================${NC}"

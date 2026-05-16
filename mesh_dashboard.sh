#!/usr/bin/env bash
# mesh_dashboard.sh — Launch 5-node mesh in a tmux grid
set -euo pipefail

SESSION="neuro_mesh"
NODES=("ALPHA" "BRAVO" "CHARLIE" "DELTA" "ECHO")

# Cleanup previous session
tmux kill-session -t "$SESSION" 2>/dev/null || true

# Build if needed
if [ ! -f bin/neuro_agent ]; then
    echo "[BUILD] Compiling neuro_agent..."
    make -j"$(nproc)"
fi

# Create session
tmux new-session -d -s "$SESSION"

# Create 5-pane grid
tmux split-window -h       # 0 | 1
tmux select-pane -t 0
tmux split-window -v       # 0 | 2
                           # 1 | 3
tmux select-pane -t 2
tmux split-window -v       # 0 | 2
                           # 3 | 3

# Launch nodes
for i in "${!NODES[@]}"; do
    tmux send-keys -t "$i" "./bin/neuro_agent ${NODES[$i]}" C-m
done

echo "[INFO] Neuro-Mesh launched in tmux session '$SESSION'"
echo "[INFO] Dashboard: http://localhost:8080"
tmux attach-session -t "$SESSION"

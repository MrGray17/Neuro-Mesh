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

# Create session with first pane (ALPHA)
tmux new-session -d -s "$SESSION"

# Create 4 more panes (total 5)
tmux split-window -v       # pane 0 | pane 1
tmux split-window -v       # pane 0 | pane 1 | pane 2
tmux select-pane -t 0
tmux split-window -h       # pane 0 | pane 3
                           # pane 1 | pane 2
tmux select-pane -t 3
tmux split-window -h       # pane 0 | pane 3 | pane 4
                           # pane 1 | pane 2

# Launch nodes (5 panes: 0-4)
for i in 0 1 2 3 4; do
    tmux send-keys -t "$SESSION:0.$i" "./bin/neuro_agent ${NODES[$i]}" C-m
done

echo "[INFO] Neuro-Mesh launched in tmux session '$SESSION'"
echo "[INFO] Dashboard: http://localhost:8080"
tmux attach-session -t "$SESSION"

#!/bin/bash

# 1. CLEANUP: Kill any existing nodes and tmux sessions to ensure a clean slate
killall neuro_agent 2>/dev/null
tmux kill-session -t neuro_mesh 2>/dev/null

SESSION="neuro_mesh"
tmux new-session -d -s $SESSION

# 2. ORCHESTRATE: Create a professional 5-pane grid
# Split vertically (Left/Right)
tmux split-window -h
# Split left side horizontally
tmux select-pane -t 0
tmux split-window -v
# Split right side horizontally
tmux select-pane -t 2
tmux split-window -v
# Create the 5th pane (Simulator Control)
tmux select-pane -t 3
tmux split-window -v

# 3. EXECUTE: Assign nodes to specific, dedicated panes
tmux send-keys -t 0 "./bin/neuro_agent NODE_1" C-m
tmux send-keys -t 1 "./bin/neuro_agent NODE_2" C-m
tmux send-keys -t 2 "./bin/neuro_agent NODE_3" C-m
tmux send-keys -t 3 "./bin/neuro_agent NODE_4" C-m
tmux send-keys -t 4 "echo '--- Neuro-Mesh Online ---'; echo 'Ready for event injection.'" C-m

# Attach to the session
tmux attach-session -t $SESSION

#!/bin/bash

echo "🚀 Launching Neuro-Mesh Full Stack..."

# 1. Start the Bridge in the background
./start_bridge.sh &
BRIDGE_PID=$!

# 2. Start the React UI in the background
cd dashboard-react && npm start &
REACT_PID=$!

# 3. Compile and Start the Agent (Requires Sudo)
cd ..
make clean && make
sudo ./bin/neuro_agent

# Cleanup background processes on exit
trap "kill $BRIDGE_PID $REACT_PID" EXIT

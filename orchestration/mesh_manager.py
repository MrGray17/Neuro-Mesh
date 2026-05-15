import subprocess
import time
import signal
import sys

nodes = ["ALPHA", "BRAVO", "CHARLIE", "DELTA", "ECHO"]
processes = []

def cleanup(sig, frame):
    print("\n[SYSTEM] Terminating Mesh...")
    for p in processes:
        p.terminate()
    sys.exit(0)

signal.signal(signal.SIGINT, cleanup)

print("[BOOT] Launching Neuro-Mesh...")
for node_id in nodes:
    p = subprocess.Popen(["./bin/neuro_agent", node_id])
    processes.append(p)
    time.sleep(0.5)

print("[BOOT] All nodes online. Monitoring telemetry...")

# Keep script alive
while True:
    time.sleep(1)

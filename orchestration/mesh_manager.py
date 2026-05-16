#!/usr/bin/env python3
"""Neuro-Mesh Process Manager — launches and monitors mesh nodes."""
import subprocess
import time
import signal
import sys
import os
from typing import Any

nodes = ["ALPHA", "BRAVO", "CHARLIE", "DELTA", "ECHO"]
processes: list[subprocess.Popen[Any]] = []
running = True


def cleanup(sig: int, frame: Any) -> None:
    global running
    print("\n[SYSTEM] Terminating Mesh...")
    running = False
    for p in processes:
        if p.poll() is None:
            p.terminate()
    # Wait up to 5 seconds for graceful shutdown
    deadline = time.time() + 5
    for p in processes:
        if p.poll() is None:
            try:
                p.wait(timeout=max(0, deadline - time.time()))
            except subprocess.TimeoutExpired:
                p.kill()
    sys.exit(0)


def monitor_nodes() -> None:
    """Restart any node that has crashed."""
    for i, (node_id, p) in enumerate(zip(nodes, processes)):
        if p.poll() is not None and running:
            print(f"[SYSTEM] Node {node_id} exited (code {p.returncode}), restarting...")
            log_file = open(f"logs/{node_id}.log", "a")
            new_p = subprocess.Popen(
                ["./bin/neuro_agent", node_id],
                stdout=log_file,
                stderr=subprocess.STDOUT,
            )
            processes[i] = new_p


signal.signal(signal.SIGINT, cleanup)
signal.signal(signal.SIGTERM, cleanup)

# Create logs directory
os.makedirs("logs", exist_ok=True)

print("[BOOT] Launching Neuro-Mesh...")
for node_id in nodes:
    log_file = open(f"logs/{node_id}.log", "a")
    p = subprocess.Popen(
        ["./bin/neuro_agent", node_id],
        stdout=log_file,
        stderr=subprocess.STDOUT,
    )
    processes.append(p)
    time.sleep(0.5)

print(f"[BOOT] All {len(nodes)} nodes online. Monitoring...")

while running:
    time.sleep(2)
    monitor_nodes()

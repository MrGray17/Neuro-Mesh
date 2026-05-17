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
log_files: list[Any] = []
restart_counts: dict[str, int] = {n: 0 for n in nodes}
MAX_RESTARTS = 5
RESTART_BACKOFF_BASE = 2
running = True


def cleanup(sig: int, frame: Any) -> None:
    global running
    print("\n[SYSTEM] Terminating Mesh...")
    running = False
    for p in processes:
        if p.poll() is None:
            p.terminate()
    deadline = time.time() + 5
    for p in processes:
        if p.poll() is None:
            try:
                p.wait(timeout=max(0, deadline - time.time()))
            except subprocess.TimeoutExpired:
                p.kill()
    for lf in log_files:
        try:
            lf.close()
        except Exception:
            pass
    sys.exit(0)


def restart_node(index: int, node_id: str) -> None:
    """Restart a crashed node with exponential backoff."""
    count = restart_counts.get(node_id, 0)
    if count >= MAX_RESTARTS:
        print(f"[SYSTEM] Node {node_id} exceeded max restarts ({MAX_RESTARTS}). Giving up.")
        return

    backoff = min(RESTART_BACKOFF_BASE ** count, 30)
    print(f"[SYSTEM] Node {node_id} exited, restarting in {backoff}s (attempt {count + 1}/{MAX_RESTARTS})...")
    time.sleep(backoff)

    if not running:
        return

    try:
        log_files[index].close()
    except Exception:
        pass

    log_file = open(f"logs/{node_id}.log", "a")
    log_files[index] = log_file
    new_p = subprocess.Popen(
        ["./bin/neuro_agent", node_id],
        stdout=log_file,
        stderr=subprocess.STDOUT,
    )
    processes[index] = new_p
    restart_counts[node_id] = count + 1


def monitor_nodes() -> None:
    """Restart any node that has crashed."""
    for i, (node_id, p) in enumerate(zip(nodes, processes)):
        if p.poll() is not None and running:
            restart_node(i, node_id)


signal.signal(signal.SIGINT, cleanup)
signal.signal(signal.SIGTERM, cleanup)

# Create logs directory
os.makedirs("logs", exist_ok=True)

print("[BOOT] Launching Neuro-Mesh...")
for i, node_id in enumerate(nodes):
    log_file = open(f"logs/{node_id}.log", "a")
    log_files.append(log_file)
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

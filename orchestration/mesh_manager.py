#!/usr/bin/env python3
"""Neuro-Mesh Process Manager — launches and monitors mesh nodes."""

import subprocess
import time
import signal
import sys
import os
import secrets
from typing import Any

nodes = ["ALPHA", "BRAVO", "CHARLIE", "DELTA", "ECHO"]

# Generate a random IPC auth token at boot. Each node reads it from the
# env var NEURO_IPC_TOKEN and refuses commands from clients that don't
# present it. The token is also written to IPC_TOKEN_FILE so external
# tools (inject_event) can read it.
IPC_TOKEN_FILE = "/tmp/neuro_mesh_token"
ipc_token = secrets.token_urlsafe(32)
with open(IPC_TOKEN_FILE, "w") as tf:
    tf.write(ipc_token)
os.chmod(IPC_TOKEN_FILE, 0o600)
print(f"[BOOT] IPC auth token written to {IPC_TOKEN_FILE} (mode 0600)")
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
    # Kill agents inside network namespaces first.  "ip netns exec" forks
    # the child, so terminating the ip process alone orphans the agent.
    # We must explicitly kill the agents inside each namespace.
    for node_id in nodes:
        ns_file = f"/run/netns/{node_id}"
        if os.path.exists(ns_file):
            subprocess.run(
                ["ip", "netns", "exec", node_id, "pkill", "-9", "neuro_agent"],
                capture_output=True, timeout=3
            )
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
    try:
        os.unlink(IPC_TOKEN_FILE)
    except FileNotFoundError:
        pass
    sys.exit(0)


def restart_node(index: int, node_id: str) -> None:
    """Restart a crashed node with exponential backoff."""
    count = restart_counts.get(node_id, 0)
    if count >= MAX_RESTARTS:
        print(
            f"[SYSTEM] Node {node_id} exceeded max restarts ({MAX_RESTARTS}). Giving up."
        )
        return

    backoff = min(RESTART_BACKOFF_BASE**count, 30)
    print(
        f"[SYSTEM] Node {node_id} exited, restarting in {backoff}s (attempt {count + 1}/{MAX_RESTARTS})..."
    )
    time.sleep(backoff)

    if not running:
        return

    try:
        log_files[index].close()
    except Exception:
        pass

    log_file = open(f"logs/{node_id}.log", "a", buffering=1)
    log_files[index] = log_file
    cmd = ["ip", "netns", "exec", node_id, "./bin/neuro_agent", node_id] if os.path.exists(f"/run/netns/{node_id}") else ["./bin/neuro_agent", node_id]
    new_p = subprocess.Popen(
        cmd,
        stdout=log_file,
        stderr=subprocess.STDOUT,
        env={**os.environ, "NEURO_IPC_TOKEN": ipc_token},
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
    log_file = open(f"logs/{node_id}.log", "a", buffering=1)
    log_files.append(log_file)
    cmd = ["ip", "netns", "exec", node_id, "./bin/neuro_agent", node_id] if os.path.exists(f"/run/netns/{node_id}") else ["./bin/neuro_agent", node_id]
    p = subprocess.Popen(
        cmd,
        stdout=log_file,
        stderr=subprocess.STDOUT,
        env={**os.environ, "NEURO_IPC_TOKEN": ipc_token},
    )
    processes.append(p)
    time.sleep(0.5)

print(f"[BOOT] All {len(nodes)} nodes online. Monitoring...")

while running:
    time.sleep(2)
    monitor_nodes()

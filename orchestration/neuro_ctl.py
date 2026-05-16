#!/usr/bin/env python3
"""NEURO-MESH : UNIFIED ORCHESTRATOR (IPC SECURE)

CLI tool to send commands to neuro_agent via IPC Unix socket.
"""
import socket
import sys
import os
import subprocess

IPC_SOCKET_DIR = "/tmp"
IPC_SOCKET_PREFIX = "neuro_mesh_"


def find_agent_socket() -> str | None:
    """Find the first available neuro_agent IPC socket."""
    for entry in os.listdir(IPC_SOCKET_DIR):
        if entry.startswith(IPC_SOCKET_PREFIX) and entry.endswith(".sock"):
            return os.path.join(IPC_SOCKET_DIR, entry)
    return None


def send_ipc_command(command: str, socket_path: str) -> bool:
    """Send a command to a neuro_agent via its Unix domain socket."""
    if not os.path.exists(socket_path):
        print(f"[ERROR] Agent socket not found at {socket_path}. Is Neuro-Mesh running?")
        return False

    try:
        client = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        client.settimeout(5)
        client.connect(socket_path)
        client.sendall(command.encode("utf-8"))
        client.close()
        return True
    except (ConnectionRefusedError, OSError) as e:
        print(f"[ERROR] IPC Communication failed: {e}")
        return False


def main() -> None:
    if len(sys.argv) < 2:
        print("Usage: ./neuro_ctl.py [reset | inject | shutdown]")
        sys.exit(1)

    action = sys.argv[1].lower()
    socket_path = find_agent_socket()

    if action == "reset":
        print("[+] Sending enforcement reset via IPC...")
        if socket_path and send_ipc_command("CMD:RESET", socket_path):
            print("Enforcement reset sent. Target node will stabilize.")

    elif action == "inject":
        print("[!] Simulating event by triggering synthetic process...")
        # Use subprocess instead of os.system — no shell injection risk
        subprocess.Popen(["sleep", "300"], start_new_session=True)
        print("Event injected into process tree.")

    elif action == "shutdown":
        print("[*] Sending graceful shutdown command to Agent...")
        if socket_path:
            send_ipc_command("CMD:SHUTDOWN", socket_path)

    else:
        print(f"[ERROR] Unknown command: {action}")
        print("Available commands: reset, inject, shutdown")


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
# ============================================================
# NEURO-MESH : UNIFIED ORCHESTRATOR (IPC SECURE)
# ============================================================
import socket
import sys
import os

IPC_SOCKET_PATH = "/tmp/neuro_mesh.sock"

def send_ipc_command(command):
    if not os.path.exists(IPC_SOCKET_PATH):
        print(f"\033[1;31m[ERROR]\033[0m Agent socket not found at {IPC_SOCKET_PATH}. Is Neuro-Mesh running?")
        sys.exit(1)

    try:
        # Connect via Unix Domain Socket
        client = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        client.connect(IPC_SOCKET_PATH)
        client.sendall(command.encode('utf-8'))
        client.close()
        return True
    except Exception as e:
        print(f"\033[1;31m[ERROR]\033[0m IPC Communication failed: {e}")
        return False

def main():
    if len(sys.argv) < 2:
        print("Usage: ./neuro_ctl.py [vaccinate | inject | shutdown]")
        sys.exit(1)

    action = sys.argv[1].lower()

    if action == "vaccinate":
        print("\033[1;32m[+] Delivering secure vaccine payload via IPC...\033[0m")
        if send_ipc_command("CMD:VACCINATE"):
            print("✅ Vaccine delivered. Target node will stabilize.")
            
    elif action == "inject":
        print("\033[1;33m[!] Simulating threat by triggering synthetic process...\033[0m")
        # Instead of sending a signal, we spawn a process matching the eBPF trace pattern
        # to properly test the kernel-to-AI pipeline natively.
        os.system("cp /bin/sleep /tmp/malicious_payload_x99 && /tmp/malicious_payload_x99 2 &")
        print("✅ Threat injected into process tree.")
        
    elif action == "shutdown":
        print("\033[1;35m[*] Sending graceful shutdown command to Agent...\033[0m")
        send_ipc_command("CMD:SHUTDOWN")
        
    else:
        print("\033[1;31m[ERROR]\033[0m Unknown command.")

if __name__ == "__main__":
    main()

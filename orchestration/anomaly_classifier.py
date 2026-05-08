#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# ============================================================
# Neuro-Mesh Anomaly Classifier (V5.0)
# ============================================================
import json
import time
import os
import socket
import threading

# Rule-based classifier — deterministic thresholds avoid ML false positives on loopback.

DATA_FILE = "control_plane_data.json"
REACT_FILE = "api.json"
CMD_FILE = "classifier_commands.txt"
SLEEP_INTERVAL = 1.0

live_p2p_nodes = {}
p2p_lock = threading.Lock()

def listen_p2p_telemetry():
    UDP_IP = "127.0.0.1"
    UDP_PORT = 9998
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    except AttributeError: pass
    sock.bind((UDP_IP, UDP_PORT))

    while True:
        try:
            data, _ = sock.recvfrom(65536)
            msg = data.decode('utf-8')
            if msg.startswith("TELEMETRY:"):
                node_data = json.loads(msg[10:])
                nid = node_data.get("ID")
                if nid:
                    with p2p_lock:
                        live_p2p_nodes[nid] = {
                            "id": nid,
                            "hostname": node_data.get("HOST", "UNKNOWN"),
                            "ram_mb": node_data.get("RAM_MB", 0),
                            "cpu_load": node_data.get("CPU_LOAD", 0.0),
                            "procs": node_data.get("PROCS", 1),
                            "net_out_bytes_s": node_data.get("NET_OUT", 0),
                            "status": "FLAGGED" if "SELF_ISOLATED" in str(node_data.get("STATUS", "")) else "STABLE",
                            "_last_seen": time.time()
                        }
        except Exception: pass

threading.Thread(target=listen_p2p_telemetry, daemon=True).start()

def write_command_safe(cmd):
    with open(CMD_FILE, 'a') as f:
        f.write(cmd + "\n")

def analyze_anomalies():
    current_time = time.time()
    nodes = []
    control_is_alive = False

    if os.path.exists(DATA_FILE):
        try:
            if current_time - os.path.getmtime(DATA_FILE) < 3.0:
                with open(DATA_FILE, 'r') as f: data = json.load(f)
                nodes = data.get('active_nodes', [])
                control_is_alive = True
        except: pass

    with p2p_lock:
        if not control_is_alive:
            dead_keys = [k for k, v in live_p2p_nodes.items() if current_time - v.get('_last_seen', current_time) > 10.0]
            for k in dead_keys: del live_p2p_nodes[k]
            nodes = list(live_p2p_nodes.values())
        else: live_p2p_nodes.clear()

    if not nodes: return

    for node in nodes:
        nid = node.get('id', 'UNKNOWN')
        if nid == 'UNKNOWN' or node.get('status') == "FLAGGED": continue

        ram = node.get('ram_mb', 0)
        cpu = node.get('cpu_load', 0.0)

        # Rule-based Override — node flags only if CPU > 85% or RAM > 14 GB.
        is_anomaly = False
        if cpu > 85.0 or ram > 14000:
            is_anomaly = True

        if is_anomaly:
            print(f"\033[1;41;37m[ALERT]\033[0m Anomaly detected on {nid}")
            write_command_safe(f"CMD:ISOLATE|{nid}")

def main():
    print("\033[1;36m[INFO]\033[0m Initializing Anomaly Classifier - V5.0")
    while True:
        analyze_anomalies()
        time.sleep(SLEEP_INTERVAL)

if __name__ == "__main__":
    main()

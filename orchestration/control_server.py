#!/usr/bin/env python3
# ============================================================
# Neuro-Mesh Control Plane
# ============================================================
import asyncio
import websockets
import json
import time
import socket
import os
import sys
import re


UDP_TELEMETRY_PORT = 9998
HTTP_API_PORT = 5000

nodes_db = {}
db_lock = asyncio.Lock()
logs = []

# Per-node cooldown state: tracks when entropy last spiked above 0.85.
# If entropy stays below 0.2 for COOLDOWN_SECONDS, status auto-resets to STABLE.
COOLDOWN_SECONDS = 10
_cooldown = {}  # nid → {"last_spike": timestamp, "was_flagged": bool}

def add_log(msg):
    log_entry = f"[{time.strftime('%H:%M:%S')}] {msg}"
    logs.append(log_entry)
    if len(logs) > 50: logs.pop(0)
    print(f"\033[1;36m[CTRL]\033[0m {log_entry}")

def send_ipc_command(node_id, command):
    pid = node_id.replace("NODE_", "")
    path = f"/tmp/neuro_mesh_{pid}.sock"
    if os.path.exists(path):
        try:
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as s:
                s.connect(path)
                s.sendall(command.encode('utf-8'))
        except: pass

class TelemetryProtocol(asyncio.DatagramProtocol):
    def datagram_received(self, data, addr):
        try:
            msg = data.decode('utf-8')
            if msg.startswith("TELEMETRY:"):
                payload = json.loads(msg[10:])
                nid = payload.get("ID")
                asyncio.create_task(self.update_node(nid, payload))
        except: pass

    async def update_node(self, nid, payload):
        async with db_lock:
            entropy = payload.get("entropy", 0.0)
            anomaly = payload.get("KERNEL_ANOMALY", "FALSE")
            reported_status = payload.get("STATUS", "STABLE")

            # ---- Cooldown logic: auto-reset FLAGGED → STABLE when entropy subsides ----
            now = time.time()
            cd = _cooldown.get(nid, {"last_spike": 0.0, "was_flagged": False})

            if entropy > 0.85:
                cd["last_spike"] = now
                cd["was_flagged"] = True
            elif entropy < 0.2 and cd["was_flagged"]:
                if now - cd["last_spike"] > COOLDOWN_SECONDS:
                    cd["was_flagged"] = False
                    reported_status = "STABLE"
                    anomaly = "FALSE"
                    add_log(f"COOLDOWN: {nid} status reset to STABLE (entropy={entropy:.4f})")

            _cooldown[nid] = cd

            # Resolve final status
            if anomaly == "TRUE" and entropy > 0.85:
                status = "FLAGGED"
            elif reported_status == "SELF_ISOLATED" and entropy > 0.85:
                status = "FLAGGED"
            else:
                status = "STABLE"

            nodes_db[nid] = {
                "id": nid,
                "hostname": payload.get("HOST", "Edge_Node"),
                "cpu_load": payload.get("CPU_LOAD", 0.0),
                "ram_mb": payload.get("RAM_MB", 0),
                "entropy": entropy,
                "kernel_anomaly": anomaly,
                "status": status,
                "mitre_attack": payload.get("mitre_attack", []),
                "last_seen": now
            }
            if anomaly == "TRUE" and entropy > 0.85:
                add_log(f"ALERT: eBPF anomaly verified on {nid}")
                send_ipc_command(nid, "CMD:ISOLATE")

async def http_api_handler(reader, writer):
    try:
        request = await reader.read(1024)
        async with db_lock:
            data = {
                "active_nodes": list(nodes_db.values()),
                "logs": logs,
                "system_status": "ONLINE" if not any(n['status'] == "FLAGGED" for n in nodes_db.values()) else "ALERT"
            }
        response = f"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nAccess-Control-Allow-Origin: *\r\n\r\n{json.dumps(data)}"
        writer.write(response.encode())
        await writer.drain()
    except: pass
    finally:
        writer.close()

async def ws_handler(websocket, path="/"):
    """Emit per-node dashboard-compatible events from the aggregated nodes_db."""
    sent_log_count = 0
    try:
        while True:
            async with db_lock:
                now = time.time()
                # Prune nodes that haven't sent telemetry in 5 seconds
                dead = [k for k, v in nodes_db.items() if now - v['last_seen'] > 5.0]
                for k in dead: del nodes_db[k]

                # Emit per-node heartbeat events from aggregated UDP telemetry
                for nid, node in nodes_db.items():
                    event = {
                        "event": "heartbeat",
                        "ID": nid,
                        "node": nid,
                        "cpu": node.get("cpu_load", 0.0),
                        "mem_mb": node.get("ram_mb", 0),
                        "entropy": node.get("entropy", 0.0),
                        "threat": "CRITICAL" if node.get("kernel_anomaly") == "TRUE" else "NOMINAL",
                        "status": node.get("status", "STABLE"),
                        "KERNEL_ANOMALY": node.get("kernel_anomaly", "FALSE"),
                        "mitre_attack": node.get("mitre_attack", [])
                    }
                    # Inject peer count from the total mesh size
                    event["peers"] = len(nodes_db) - 1
                    event["peer_list"] = [k for k in nodes_db.keys() if k != nid]
                    await websocket.send(json.dumps(event))

                # Emit new log entries as dashboard events
                while sent_log_count < len(logs):
                    log_msg = logs[sent_log_count]
                    sent_log_count += 1
                    if "eBPF anomaly verified on" in log_msg:
                        match = re.search(r'on (\S+)', log_msg)
                        nid = match.group(1) if match else "UNKNOWN"
                        real_entropy = nodes_db.get(nid, {}).get("entropy", 0.0)
                        if real_entropy > 0.85:
                            await websocket.send(json.dumps({
                                "event": "ebpf_entropy",
                                "sensor": "ebpf_entropy",
                                "ID": nid,
                                "node": nid,
                                "value": real_entropy,
                                "threshold": 0.85,
                                "mitre_attack": ["T1059", "T1021", "T1571"]
                            }))

            await asyncio.sleep(0.5)
    except websockets.exceptions.ConnectionClosed:
        pass
    except Exception as e:
        print(f"WS Handler Error: {e}", file=sys.stderr)


async def legacy_ws_handler(websocket, path="/"):
    """Legacy bulk-state handler for backward compatibility on 8080/8081."""
    try:
        while True:
            async with db_lock:
                now = time.time()
                dead = [k for k, v in nodes_db.items() if now - v['last_seen'] > 5.0]
                for k in dead: del nodes_db[k]

                state = {
                    "active_nodes": list(nodes_db.values()),
                    "logs": logs,
                    "system_status": "ONLINE" if not any(n['status'] == "FLAGGED" for n in nodes_db.values()) else "ALERT"
                }
            await websocket.send(json.dumps(state))
            await asyncio.sleep(0.5)
    except websockets.exceptions.ConnectionClosed:
        pass
    except Exception as e:
        print(f"WS Handler Error: {e}", file=sys.stderr)

async def main():
    print("\033[1;32mNeuro-Mesh Control Plane Starting...\033[0m")
    loop = asyncio.get_running_loop()

    # 1. Telemetry Listener (UDP from NodeAgent — host networking, SO_REUSEADDR for
    #    co-binding with MeshNode discovery on INADDR_ANY:9998)
    udp_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    udp_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    udp_sock.bind(('127.0.0.1', UDP_TELEMETRY_PORT))
    await loop.create_datagram_endpoint(lambda: TelemetryProtocol(), sock=udp_sock)

    # 2. HTTP Fallback Server
    await asyncio.start_server(http_api_handler, '0.0.0.0', HTTP_API_PORT)

    # 3. Per-node event WebSocket — wsbridge proxies :9001 → :9002
    await websockets.serve(ws_handler, "0.0.0.0", 9002)

    print("Control Plane Active. Listening on UDP:9998, HTTP:5000, WS:9002 (dashboard via wsbridge:9001)")
    await asyncio.Future()

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except Exception as e:
        print(f"Fatal Startup Error: {e}", file=sys.stderr)

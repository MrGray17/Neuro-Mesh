#!/usr/bin/env python3
# ============================================================
# NEURO-MESH : OMNI-C2 ORCHESTRATOR (ABSOLUTE RESOLUTION)
# ============================================================
import asyncio
import websockets
import json
import time
import socket
import os
import sys

# Force all fatal Python crashes to a log file so we are never blind
sys.stderr = open('c2_fatal_crash.log', 'w')

UDP_TELEMETRY_PORT = 9998
HTTP_API_PORT = 5000

nodes_db = {}
db_lock = asyncio.Lock()
logs = []

def add_log(msg):
    log_entry = f"[{time.strftime('%H:%M:%S')}] {msg}"
    logs.append(log_entry)
    if len(logs) > 50: logs.pop(0)
    print(f"\033[1;36m[C2]\033[0m {log_entry}")

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
            nodes_db[nid] = {
                "id": nid,
                "hostname": payload.get("HOST", "Edge_Node"),
                "cpu_load": payload.get("CPU_LOAD", 0.0),
                "ram_mb": payload.get("RAM_MB", 0),
                "status": "COMPROMIS" if payload.get("STATUS") == "SELF_ISOLATED" else "STABLE",
                "last_seen": time.time()
            }
            if payload.get("KERNEL_THREAT") == "TRUE":
                add_log(f"ALERT: eBPF Kernel Threat verified on {nid}")
                send_ipc_command(nid, "CMD:ISOLATE")

async def http_api_handler(reader, writer):
    try:
        request = await reader.read(1024)
        async with db_lock:
            data = {
                "active_nodes": list(nodes_db.values()),
                "logs": logs,
                "system_status": "ONLINE" if not any(n['status'] == "COMPROMIS" for n in nodes_db.values()) else "THREAT"
            }
        response = f"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nAccess-Control-Allow-Origin: *\r\n\r\n{json.dumps(data)}"
        writer.write(response.encode())
        await writer.drain()
    except: pass
    finally:
        writer.close()

# 🔥 THE FIX 1: Accepts 'path' to prevent older websockets libraries from crashing
async def ws_handler(websocket, path="/"):
    try:
        while True:
            async with db_lock:
                now = time.time()
                # Prune nodes that haven't sent telemetry in 5 seconds
                dead = [k for k, v in nodes_db.items() if now - v['last_seen'] > 5.0]
                for k in dead: del nodes_db[k]
                
                state = {
                    "active_nodes": list(nodes_db.values()),
                    "logs": logs,
                    "system_status": "ONLINE" if not any(n['status'] == "COMPROMIS" for n in nodes_db.values()) else "THREAT"
                }
            await websocket.send(json.dumps(state))
            await asyncio.sleep(0.5)
    except websockets.exceptions.ConnectionClosed:
        pass
    except Exception as e:
        print(f"WS Handler Error: {e}", file=sys.stderr)

async def main():
    print("\033[1;32m🚀 Neuro-Mesh Omni-C2 Orchestrator Starting...\033[0m")
    loop = asyncio.get_running_loop()
    
    # 1. Telemetry Listener
    await loop.create_datagram_endpoint(lambda: TelemetryProtocol(), local_addr=('127.0.0.1', UDP_TELEMETRY_PORT))
    
    # 2. HTTP Fallback Server
    await asyncio.start_server(http_api_handler, '0.0.0.0', HTTP_API_PORT)
    
    # 🔥 THE FIX 2: Bind to BOTH ports. React cannot miss the connection now.
    await websockets.serve(ws_handler, "0.0.0.0", 8080)
    await websockets.serve(ws_handler, "0.0.0.0", 8081)
    
    print("📡 Omni-Server Active. Listening on UDP:9998, HTTP:5000, WS:8080 & WS:8081")
    await asyncio.Future()

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except Exception as e:
        print(f"Fatal Startup Error: {e}", file=sys.stderr)

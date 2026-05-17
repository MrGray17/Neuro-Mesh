#!/usr/bin/env python3
"""Neuro-Mesh Control Plane — aggregates UDP telemetry, serves HTTP + WebSocket."""

import asyncio
import websockets
import json
import os
import time
import socket
import sys
from typing import Any

UDP_TELEMETRY_PORT = 9998
HTTP_API_PORT = 5000

nodes_db: dict[str, dict[str, Any]] = {}
db_lock = asyncio.Lock()
logs: list[str] = []

COOLDOWN_SECONDS = 10
_cooldown: dict[str, dict[str, Any]] = {}


def add_log(msg: str) -> None:
    log_entry = f"[{time.strftime('%H:%M:%S')}] {msg}"
    logs.append(log_entry)
    if len(logs) > 50:
        logs.pop(0)
    print(f"[CTRL] {log_entry}")


def send_ipc_command(node_id: str, command: str) -> None:
    pid = node_id.replace("NODE_", "")
    path = f"/tmp/neuro_mesh_{pid}.sock"
    if os.path.exists(path):
        try:
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as s:
                s.settimeout(2)
                s.connect(path)
                s.sendall(command.encode("utf-8"))
        except (ConnectionRefusedError, OSError) as e:
            add_log(f"IPC send failed for {node_id}: {e}")


class TelemetryProtocol(asyncio.DatagramProtocol):
    def datagram_received(self, data: bytes, addr: tuple[str, int]) -> None:
        try:
            msg = data.decode("utf-8")
            if msg.startswith("TELEMETRY|"):
                tokens = msg.split("|", 2)
                if len(tokens) < 3:
                    return
                payload = json.loads(tokens[2])
                nid = payload.get("ID")
                if nid:
                    asyncio.create_task(self.update_node(nid, payload))
        except (UnicodeDecodeError, json.JSONDecodeError, KeyError) as e:
            add_log(f"Telemetry parse error from {addr}: {e}")

    async def update_node(self, nid: str, payload: dict[str, Any]) -> None:
        async with db_lock:
            entropy = payload.get("entropy", 0.0)
            anomaly = payload.get("KERNEL_ANOMALY", "FALSE")
            reported_status = payload.get("STATUS", "STABLE")

            now = time.time()
            cd = _cooldown.get(nid, {"last_spike": 0.0, "was_flagged": False})

            if entropy > 0.65:
                cd["last_spike"] = now
                cd["was_flagged"] = True
            elif entropy < 0.2 and cd["was_flagged"]:
                if now - cd["last_spike"] > COOLDOWN_SECONDS:
                    cd["was_flagged"] = False
                    reported_status = "STABLE"
                    anomaly = "FALSE"
                    add_log(
                        f"COOLDOWN: {nid} status reset to STABLE (entropy={entropy:.4f})"
                    )

            _cooldown[nid] = cd

            if anomaly == "TRUE" and entropy > 0.65:
                status = "FLAGGED"
            elif reported_status == "SELF_ISOLATED" and entropy > 0.65:
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
                "last_seen": now,
            }
            if anomaly == "TRUE" and entropy > 0.65:
                add_log(f"ALERT: eBPF anomaly verified on {nid}")


async def http_api_handler(
    reader: asyncio.StreamReader, writer: asyncio.StreamWriter
) -> None:
    try:
        await reader.read(1024)
        async with db_lock:
            flagged = any(n.get("status") == "FLAGGED" for n in nodes_db.values())
            data = {
                "active_nodes": list(nodes_db.values()),
                "logs": logs,
                "system_status": "ALERT" if flagged else "ONLINE",
            }
        response = (
            f"HTTP/1.1 200 OK\r\n"
            f"Content-Type: application/json\r\n"
            f"Access-Control-Allow-Origin: *\r\n\r\n"
            f"{json.dumps(data)}"
        )
        writer.write(response.encode())
        await writer.drain()
    except (ConnectionResetError, BrokenPipeError):
        pass
    finally:
        writer.close()


async def ws_handler(
    websocket: websockets.WebSocketServerProtocol, path: str = "/"
) -> None:
    """Emit per-node dashboard-compatible events from the aggregated nodes_db."""
    sent_log_count = 0
    try:
        while True:
            async with db_lock:
                now = time.time()
                dead = [
                    k for k, v in nodes_db.items() if now - v.get("last_seen", 0) > 5.0
                ]
                for k in dead:
                    del nodes_db[k]

                for nid, node in nodes_db.items():
                    event = {
                        "event": "heartbeat",
                        "ID": nid,
                        "node": nid,
                        "cpu": node.get("cpu_load", 0.0),
                        "mem_mb": node.get("ram_mb", 0),
                        "entropy": node.get("entropy", 0.0),
                        "threat": "CRITICAL"
                        if node.get("kernel_anomaly") == "TRUE"
                        else "NOMINAL",
                        "status": node.get("status", "STABLE"),
                        "KERNEL_ANOMALY": node.get("kernel_anomaly", "FALSE"),
                        "mitre_attack": node.get("mitre_attack", []),
                        "peers": len(nodes_db) - 1,
                        "peer_list": [k for k in nodes_db if k != nid],
                    }
                    await websocket.send(json.dumps(event))

                while sent_log_count < len(logs):
                    log_msg = logs[sent_log_count]
                    sent_log_count += 1
                    if "eBPF anomaly verified on" in log_msg:
                        import re

                        match = re.search(r"on (\S+)", log_msg)
                        nid = match.group(1) if match else "UNKNOWN"
                        real_entropy = nodes_db.get(nid, {}).get("entropy", 0.0)
                        if real_entropy > 0.65:
                            await websocket.send(
                                json.dumps(
                                    {
                                        "event": "ebpf_entropy",
                                        "sensor": "ebpf_entropy",
                                        "ID": nid,
                                        "node": nid,
                                        "value": real_entropy,
                                        "threshold": 0.65,
                                        "mitre_attack": ["T1059", "T1021", "T1571"],
                                    }
                                )
                            )

            await asyncio.sleep(0.5)
    except websockets.exceptions.ConnectionClosed:
        pass


async def legacy_ws_handler(
    websocket: websockets.WebSocketServerProtocol, path: str = "/"
) -> None:
    """Legacy bulk-state handler for backward compatibility on 8080/8081."""
    try:
        while True:
            async with db_lock:
                now = time.time()
                dead = [
                    k for k, v in nodes_db.items() if now - v.get("last_seen", 0) > 5.0
                ]
                for k in dead:
                    del nodes_db[k]

                flagged = any(n.get("status") == "FLAGGED" for n in nodes_db.values())
                state = {
                    "active_nodes": list(nodes_db.values()),
                    "logs": logs,
                    "system_status": "ALERT" if flagged else "ONLINE",
                }
            await websocket.send(json.dumps(state))
            await asyncio.sleep(0.5)
    except websockets.exceptions.ConnectionClosed:
        pass


async def main() -> None:
    print("Neuro-Mesh Control Plane Starting...")
    loop = asyncio.get_running_loop()

    udp_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    udp_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    udp_sock.bind(("127.0.0.1", UDP_TELEMETRY_PORT))
    await loop.create_datagram_endpoint(lambda: TelemetryProtocol(), sock=udp_sock)

    await asyncio.start_server(http_api_handler, "0.0.0.0", HTTP_API_PORT)
    await websockets.serve(ws_handler, "0.0.0.0", 9002)

    print(
        "Control Plane Active. "
        f"Listening on UDP:{UDP_TELEMETRY_PORT}, "
        f"HTTP:{HTTP_API_PORT}, WS:9002"
    )
    await asyncio.Future()


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\nControl Plane shutting down.")
    except Exception as e:
        print(f"Fatal Startup Error: {e}", file=sys.stderr)
        sys.exit(1)

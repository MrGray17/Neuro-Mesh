"""Read-only WebSocket proxy for Neuro-Mesh telemetry.

The proxy connects browsers to the first available local TelemetryBridge.
It deliberately relays data in one direction only: node -> browser. Control
commands belong on the authenticated Unix IPC channel, never WebSocket.
"""

import asyncio
import os
import sys

import websockets

LISTEN_HOST = os.environ.get("NEURO_WS_PROXY_BIND", "127.0.0.1")
LISTEN_PORT = int(os.environ.get("NEURO_WS_PROXY_PORT", "9001"))
HOST_IP = os.environ.get("NEURO_HOST_IP", "127.0.0.1")
BACKEND_PORTS = [9000, 9010, 9020, 9030, 9040]
BACKENDS = [f"ws://{HOST_IP}:{port}" for port in BACKEND_PORTS]
MAX_MESSAGE_SIZE = 1024 * 1024


async def connect_to_backend():
    """Return the first reachable telemetry backend."""
    for url in BACKENDS:
        try:
            ws = await asyncio.wait_for(
                websockets.connect(url, max_size=MAX_MESSAGE_SIZE), timeout=3.0
            )
            print(f"[WS-PROXY] Connected to backend: {url}", flush=True)
            return ws
        except (asyncio.TimeoutError, OSError, websockets.WebSocketException):
            continue
    return None


async def proxy(peer_sock, path="/"):
    """Relay telemetry from one mesh node to one browser connection."""
    del path
    peer_addr = peer_sock.remote_address
    print(f"[WS-PROXY] Client connected: {peer_addr}", flush=True)

    backend = await connect_to_backend()
    if backend is None:
        print(
            f"[WS-PROXY] No backend available — rejecting client {peer_addr}",
            flush=True,
        )
        await peer_sock.close(code=1013, reason="Telemetry backend unavailable")
        return

    try:
        async for message in backend:
            await peer_sock.send(message)
    except websockets.ConnectionClosed:
        pass
    except (OSError, asyncio.TimeoutError, websockets.WebSocketException) as exc:
        print(f"[WS-PROXY] Relay error: {exc}", file=sys.stderr, flush=True)
    finally:
        print(f"[WS-PROXY] Client disconnected: {peer_addr}", flush=True)
        try:
            await backend.close()
        except websockets.WebSocketException as exc:
            print(f"[WS-PROXY] Backend close warning: {exc}", file=sys.stderr, flush=True)


async def main() -> None:
    backends_str = ", ".join(BACKENDS)
    print(
        f"[WS-PROXY] Listening on {LISTEN_HOST}:{LISTEN_PORT} -> {backends_str}",
        flush=True,
    )
    async with websockets.serve(
        proxy,
        LISTEN_HOST,
        LISTEN_PORT,
        max_size=MAX_MESSAGE_SIZE,
    ):
        await asyncio.Future()


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\n[WS-PROXY] Shutting down.", flush=True)

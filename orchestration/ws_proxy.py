#!/usr/bin/env python3
"""Stateless WebSocket proxy — bridges browser to any mesh node's TelemetryBridge.

Each C++ node runs its own TelemetryBridge WebSocket on ports 9000-9040.
This proxy tries each backend in order — if one node is down, it fails over
to the next. In a real deployment (physical machines, K8s with Pod networking),
the browser connects directly to nodes and this proxy is unnecessary.
"""

import asyncio
import os
import websockets
import sys

LISTEN_PORT = 9001
# Configurable via env var — defaults to Docker bridge gateway.
# On native Linux, set NEURO_HOST_IP=127.0.0.1
HOST_IP = os.environ.get("NEURO_HOST_IP", "172.18.0.1")
BACKEND_PORTS = [9000, 9010, 9020, 9030, 9040]
BACKENDS = [f"ws://{HOST_IP}:{p}" for p in BACKEND_PORTS]

MAX_MESSAGE_SIZE = 1024 * 1024  # 1MB limit


async def connect_to_backend():
    """Try each backend in order, return the first that connects."""
    for url in BACKENDS:
        try:
            ws = await asyncio.wait_for(websockets.connect(url), timeout=3.0)
            print(f"[WS-PROXY] Connected to backend: {url}", flush=True)
            return ws, url
        except (asyncio.TimeoutError, OSError):
            continue
    return None, None


async def proxy(peer_sock, path="/"):
    """Accept a browser WebSocket connection and relay to a node backend."""
    peer_addr = peer_sock.remote_address
    print(f"[WS-PROXY] Client connected: {peer_addr}", flush=True)

    backend, backend_url = await connect_to_backend()
    if backend is None:
        print(
            f"[WS-PROXY] No backend available — rejecting client {peer_addr}",
            flush=True,
        )
        await peer_sock.close()
        return

    try:

        async def forward():
            """Browser → Backend"""
            async for msg in peer_sock:
                await backend.send(msg)

        async def backward():
            """Backend → Browser"""
            async for msg in backend:
                await peer_sock.send(msg)

        done, pending = await asyncio.wait(
            [asyncio.create_task(forward()), asyncio.create_task(backward())],
            return_when=asyncio.FIRST_COMPLETED,
        )
        for task in pending:
            task.cancel()
            try:
                await task
            except (asyncio.CancelledError, websockets.ConnectionClosed):
                pass
    except websockets.ConnectionClosed:
        pass
    except Exception as e:
        print(f"[WS-PROXY] Error: {e}", file=sys.stderr, flush=True)
    finally:
        print(f"[WS-PROXY] Client disconnected: {peer_addr}", flush=True)
        try:
            await backend.close()
        except Exception:
            pass


async def main() -> None:
    backends_str = ", ".join(BACKENDS)
    print(
        f"[WS-PROXY] Listening on 0.0.0.0:{LISTEN_PORT} → backends: {backends_str}",
        flush=True,
    )
    async with websockets.serve(
        proxy,
        "0.0.0.0",
        LISTEN_PORT,
        max_size=MAX_MESSAGE_SIZE,
    ):
        await asyncio.Future()


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\n[WS-PROXY] Shutting down.", flush=True)

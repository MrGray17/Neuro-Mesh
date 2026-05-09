#!/usr/bin/env python3
"""WebSocket proxy — relays browser WS connections to control_server port 9002.

Replaces the alpine/socat wsbridge container with a proper asyncio proxy
that handles WebSocket framing correctly and logs connection events.
"""

import asyncio
import websockets
import sys

LISTEN_PORT = 9001
BACKEND_WS = "ws://172.18.0.1:9002"


async def proxy(peer_sock, path="/"):
    """Accept a browser WebSocket connection and relay to the backend."""
    peer_addr = peer_sock.remote_address
    print(f"[WS-PROXY] Client connected: {peer_addr}", flush=True)
    try:
        async with websockets.connect(BACKEND_WS) as backend:
            print(f"[WS-PROXY] Backend connected to {BACKEND_WS}", flush=True)

            async def forward():
                """Browser → Backend"""
                async for msg in peer_sock:
                    await backend.send(msg)

            async def backward():
                """Backend → Browser"""
                async for msg in backend:
                    await peer_sock.send(msg)

            # Run both directions concurrently — first side to exit cancels the other
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


async def main():
    print(f"[WS-PROXY] Listening on 0.0.0.0:{LISTEN_PORT} → {BACKEND_WS}", flush=True)
    async with websockets.serve(proxy, "0.0.0.0", LISTEN_PORT):
        await asyncio.Future()


if __name__ == "__main__":
    asyncio.run(main())

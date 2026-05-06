import asyncio
import websockets
import json

# Thread-safe set of connected React UI clients
connected_clients = set()

async def register_client(websocket):
    """Registers a new React dashboard connection."""
    connected_clients.add(websocket)
    try:
        await websocket.wait_closed()
    finally:
        connected_clients.remove(websocket)

class TelemetryReceiver(asyncio.DatagramProtocol):
    """Listens for high-speed UDP packets from the C++ agent."""
    def __init__(self):
        # 🔥 THE FIX: Prevent OutOfMemory by tracking background asyncio tasks.
        self.active_tasks = set() 

    def connection_made(self, transport):
        self.transport = transport

    def datagram_received(self, data, addr):
        message = data.decode('utf-8')
        if connected_clients:
            task = asyncio.create_task(self.broadcast(message))
            self.active_tasks.add(task)
            # Self-cleaning callback ensures task is evicted the moment it finishes.
            task.add_done_callback(self.active_tasks.discard)

    async def broadcast(self, message):
        """Fan-out the JSON log to all WebSockets safely."""
        try:
            websockets.broadcast(connected_clients, message)
        except Exception:
            # Drop silently to prevent unhandled exceptions breaking the loop
            pass

async def main():
    print("🚀 Neuro-Mesh Bridge API Online (Memory-Safe Edition).")
    
    # 1. Start WebSocket server for React (Port 8080)
    async with websockets.serve(register_client, "localhost", 8080):
        print("📡 WebSocket Server listening on ws://localhost:8080")
        
        # 2. Start UDP listener for C++ agent (Port 50052)
        loop = asyncio.get_running_loop()
        transport, protocol = await loop.create_datagram_endpoint(
            lambda: TelemetryReceiver(),
            local_addr=('127.0.0.1', 50052)
        )
        print("🔌 Internal UDP Listener bound to 127.0.0.1:50052")
        
        await asyncio.Future()

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\n[Shutting down Bridge API]")

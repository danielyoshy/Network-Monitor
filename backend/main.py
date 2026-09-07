"""FastAPI server: owns the aggregation clock and fans snapshots out to clients.

Two long-lived tasks run for the life of the process:

  1. The sniffer daemon thread (blocking libpcap loop) fills the FlowTable.
  2. An asyncio aggregator ticks every EMIT_INTERVAL, calls FlowTable.tick()
     to roll the 1-second window, and broadcasts the snapshot to every
     connected WebSocket.

Decoupling capture (thread) from aggregation/serving (event loop) means a slow
or disconnected client can never stall packet capture.
"""
import asyncio
import threading
from contextlib import asynccontextmanager

from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.staticfiles import StaticFiles

from backend import config, detectors
from backend.flows import flow_table
from backend.sniffer import start_sniffing


class ConnectionManager:
    """Tracks connected dashboards and broadcasts each snapshot to all of them."""

    def __init__(self):
        self._clients: set[WebSocket] = set()
        self._lock = asyncio.Lock()

    async def connect(self, ws: WebSocket):
        await ws.accept()
        async with self._lock:
            self._clients.add(ws)

    async def disconnect(self, ws: WebSocket):
        async with self._lock:
            self._clients.discard(ws)

    async def broadcast(self, message: dict):
        async with self._lock:
            targets = list(self._clients)
        for ws in targets:
            try:
                await ws.send_json(message)
            except Exception:
                await self.disconnect(ws)


manager = ConnectionManager()


async def _aggregation_loop():
    """Roll the FlowTable once per window and push the snapshot to all clients."""
    while True:
        await asyncio.sleep(config.EMIT_INTERVAL)
        # Both calls briefly hold a lock but do no I/O, so they're safe inline.
        snapshot = flow_table.tick(config.EMIT_INTERVAL)
        snapshot["alerts"] = detectors.engine.evaluate() if detectors.engine else []
        await manager.broadcast(snapshot)


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Start the capture thread and the aggregation task; tear the task down on exit."""
    threading.Thread(target=start_sniffing, daemon=True).start()
    aggregator = asyncio.create_task(_aggregation_loop())
    try:
        yield
    finally:
        aggregator.cancel()


app = FastAPI(title="Network Traffic Monitor API", lifespan=lifespan)


@app.websocket("/ws/packets")
async def websocket_endpoint(websocket: WebSocket):
    """Register the client and keep the socket open; all data is pushed by the broadcaster."""
    await manager.connect(websocket)
    try:
        while True:
            # We don't expect inbound messages, but awaiting keeps the socket
            # alive and surfaces disconnects promptly.
            await websocket.receive_text()
    except WebSocketDisconnect:
        await manager.disconnect(websocket)
    except Exception:
        await manager.disconnect(websocket)


# Frontend is mounted last so it doesn't shadow the WebSocket route.
app.mount("/", StaticFiles(directory="frontend", html=True), name="frontend")

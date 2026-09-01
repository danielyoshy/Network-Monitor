import asyncio
import threading
from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from backend.sniffer import start_sniffing, packet_queue

app = FastAPI(title="Network Traffic Monitor API")

@app.on_event("startup")
def startup_event():
    """Launch packet sniffer in a background daemon thread on server startup."""
    sniffer_thread = threading.Thread(target=start_sniffing, daemon=True)
    sniffer_thread.start()

@app.websocket("/ws/packets")
async def websocket_endpoint(websocket: WebSocket):
    """Streams captured network packet metadata over WebSocket."""
    await websocket.accept()
    try:
        while True:
            if not packet_queue.empty():
                packet_data = packet_queue.get()
                await websocket.send_json(packet_data)
            else:
                # Yield execution to allow non-blocking event loop execution
                await asyncio.sleep(0.01)
    except WebSocketDisconnect:
        print("Client disconnected from WebSocket stream.")
        
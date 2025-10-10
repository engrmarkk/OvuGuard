from fastapi import WebSocket
from typing import Dict, List
from logger import logger


class WebSocketConnectionManager:
    def __init__(self):
        self.rooms: Dict[str, List[WebSocket]] = {}

    async def connect(self, websocket: WebSocket, room: str):
        # await websocket.accept()
        if room not in self.rooms:
            self.rooms[room] = []
        self.rooms[room].append(websocket)

    def disconnect(self, websocket: WebSocket, room: str):
        if room in self.rooms:
            self.rooms[room].remove(websocket)
            if not self.rooms[room]:
                del self.rooms[room]

    async def send_message(self, room: str, message: dict):
        if room in self.rooms:
            for websocket in self.rooms[room]:
                await websocket.send_json(message)

    async def emit_error(self, websocket: WebSocket, error_message: str):
        try:
            await websocket.send_json({"error": error_message})
        except Exception as e:
            logger.error(f"Error sending message: {e}")

    def room_exists(self, room: str) -> bool:
        return room in self.rooms and bool(self.rooms[room])

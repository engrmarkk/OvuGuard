from fastapi import APIRouter

websocket_router = APIRouter(prefix="/ws")

from sockets.messages import websocket_router

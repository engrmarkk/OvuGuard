from connections.websocket_connection import WebSocketConnectionManager
from fastapi import WebSocket, WebSocketDisconnect
from sockets import websocket_router
from sockets.utils import decode_token
from logger import logger

websocket_manager = WebSocketConnectionManager()


# connect
@websocket_router.websocket("/connect/{receiver_id}")
async def websocket_endpoint(websocket: WebSocket, receiver_id: str):
    token = websocket.query_params.get("token")
    await websocket.accept()

    if not token:
        await websocket_manager.emit_error(websocket, "Token is required")
        await websocket.close()
        return

    user_id = decode_token(token)
    if not user_id:
        await websocket_manager.emit_error(websocket, "Invalid or expired token")
        await websocket.close()
        return

    logger.info(f"User {user_id} connected to receiver {receiver_id}")
    room = ":".join(sorted([user_id, receiver_id]))
    await websocket_manager.connect(websocket, room)

    try:
        while True:
            data = await websocket.receive_json()
            await websocket_manager.send_message(room, data)
    except WebSocketDisconnect:
        websocket_manager.disconnect(websocket, room)

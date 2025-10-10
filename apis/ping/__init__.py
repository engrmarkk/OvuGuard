from fastapi import APIRouter, status
from logger import logger


ping_router = APIRouter(prefix="/ping", tags=["Ping"])


@ping_router.get("", status_code=status.HTTP_200_OK)
async def ping_server():
    logger.info("pong")
    return {"detail": "pong"}

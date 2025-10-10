import time
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse
from fastapi import status
from connections import redis_conn
from environmentals import RATE_LIMIT, WINDOW_SECONDS


class RateLimitMiddleware(BaseHTTPMiddleware):
    # noinspection PyMethodMayBeStatic
    async def dispatch(self, request: Request, call_next):
        ip = request.client.host
        key = f"ratelimit:{ip}"
        await redis_conn.init_connection()
        current = await redis_conn.get(key)

        if current and int(current) >= RATE_LIMIT:
            return JSONResponse(
                {"detail": "Too many requests"},
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            )

        pipe = redis_conn.pipeline()
        pipe.incr(key, 1)
        pipe.expire(key, WINDOW_SECONDS)
        await pipe.execute()

        return await call_next(request)

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import JSONResponse
from environmentals import MAINTENANCE_MODE


class MaintenanceMiddleware(BaseHTTPMiddleware):
    # noinspection PyMethodMayBeStatic
    async def dispatch(self, request, call_next):
        if MAINTENANCE_MODE:
            return JSONResponse(
                {"detail": "Service temporarily unavailable due to maintenance"},
                status_code=503,
            )
        return await call_next(request)

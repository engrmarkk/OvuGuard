from fastapi import FastAPI, Request, HTTPException, status
from apis import ping_router, auth_router, scan_router, user_router
from sockets import websocket_router
from database import engine, Base
from fastapi.middleware.cors import CORSMiddleware
from middlewares import MaintenanceMiddleware, RateLimitMiddleware
from starlette.middleware.sessions import SessionMiddleware
from dotenv import load_dotenv
from utils.rate_limit import limiter
from slowapi.errors import RateLimitExceeded
from environmentals import (
    ALLOWED_ORIGINS,
    ALLOWED_METHODS,
    ALLOWED_HEADERS,
    SECRET_KEY,
    API_VERSION,
    EXCEPTION_MESSAGE,
)
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse

# noinspection PyProtectedMember
from slowapi import _rate_limit_exceeded_handler
from logger import logger
from starlette.exceptions import HTTPException as StarletteHTTPException

load_dotenv()

app = FastAPI(
    title="OvuGuard MVP - B2B AI Fraud Platform",
    # description="OvuGuard MVP - B2B AI Fraud Platform",
    version="1.0.0",
)


def create_app():
    # noinspection PyTypeChecker
    app.add_middleware(MaintenanceMiddleware)
    # noinspection PyTypeChecker
    app.add_middleware(RateLimitMiddleware)
    # noinspection PyTypeChecker
    app.add_middleware(
        CORSMiddleware,
        allow_origins=ALLOWED_ORIGINS.split(","),
        # Example: "http://localhost:3000,https://example.com"
        allow_credentials=True,
        allow_methods=ALLOWED_METHODS.split(","),
        allow_headers=ALLOWED_HEADERS.split(","),
    )

    # noinspection PyTypeChecker
    app.add_middleware(SessionMiddleware, secret_key=SECRET_KEY)

    # noinspection PyUnresolvedReferences
    app.state.limiter = limiter

    # noinspection PyTypeChecker
    app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

    @app.exception_handler(HTTPException)
    async def custom_http_exception_handler(request: Request, exc: HTTPException):
        return JSONResponse(
            status_code=exc.status_code,
            content={"msg": exc.detail},
        )

    @app.exception_handler(RequestValidationError)
    async def validation_exception_handler(
        request: Request, exc: RequestValidationError
    ):
        # Extract first error message or customize
        errors = exc.errors()
        first_error = (
            f"{errors[0]['loc'][1]} {errors[0]['msg']}" if errors else "Invalid request"
        )
        return JSONResponse(status_code=422, content={"msg": first_error})

    @app.exception_handler(StarletteHTTPException)
    async def custom_starlette_http_exception_handler(
        request: Request, exc: StarletteHTTPException
    ):
        return JSONResponse(
            status_code=exc.status_code,
            content={"msg": exc.detail},  # replace "detail" with "msg"
        )

    @app.exception_handler(RateLimitExceeded)
    async def custom_rate_limit_exceeded_handler(
        request: Request, exc: RateLimitExceeded
    ):
        logger.error(exc.detail)
        raise HTTPException(status_code=429, detail="Too many requests")

    @app.exception_handler(Exception)
    async def global_exception_handler(request: Request, exc: Exception):
        logger.error(f"Path: {request.url.path}, Exception: {exc}")
        return JSONResponse(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            content={"msg": EXCEPTION_MESSAGE},
        )

    Base.metadata.create_all(engine)

    app.include_router(ping_router)
    app.include_router(auth_router, prefix=f"/{API_VERSION}")
    app.include_router(scan_router, prefix=f"/{API_VERSION}")
    app.include_router(user_router, prefix=f"/{API_VERSION}")
    app.include_router(websocket_router)
    return app

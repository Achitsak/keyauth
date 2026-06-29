from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse

from .db import init_db
from .envelope import ApiError, envelope
from .routers import client


@asynccontextmanager
async def _lifespan(app: FastAPI):
    # Startup: create tables/settings, then seed the admin account if none exists.
    init_db()
    from .cli import seed_admin
    seed_admin()
    yield


def create_app() -> FastAPI:
    app = FastAPI(
        title="KeyAuth License Server",
        openapi_url="/api/v1/openapi.json",
        lifespan=_lifespan,
    )

    @app.exception_handler(ApiError)
    async def _api_error_handler(request: Request, exc: ApiError):
        return JSONResponse(
            status_code=exc.status_code,
            content=envelope(False, exc.code, None, exc.message),
        )

    @app.exception_handler(RequestValidationError)
    async def _validation_handler(request: Request, exc: RequestValidationError):
        # Malformed/invalid client requests get the uniform envelope, not FastAPI's default 422 shape.
        return JSONResponse(
            status_code=400,
            content=envelope(False, "invalid_request", None, "invalid request"),
        )

    @app.exception_handler(Exception)
    async def _unhandled_handler(request: Request, exc: Exception):
        # 24/7: no request may crash the process; never leak internals.
        return JSONResponse(
            status_code=500,
            content=envelope(False, "internal_error", None, "internal error"),
        )

    app.include_router(client.router)
    return app


app = create_app()

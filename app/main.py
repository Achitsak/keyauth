from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

from .db import init_db
from .envelope import ApiError, envelope
from .routers import client


def create_app() -> FastAPI:
    app = FastAPI(title="KeyAuth License Server", openapi_url="/api/v1/openapi.json")

    @app.on_event("startup")
    def _startup():
        init_db()
        from .cli import seed_admin
        seed_admin()

    @app.exception_handler(ApiError)
    async def _api_error_handler(request: Request, exc: ApiError):
        return JSONResponse(
            status_code=exc.status_code,
            content=envelope(False, exc.code, None, exc.message),
        )

    app.include_router(client.router)
    return app


app = create_app()

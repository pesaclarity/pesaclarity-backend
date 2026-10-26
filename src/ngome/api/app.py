"""Application factory. Run with ``uvicorn ngome.api.app:create_app --factory``."""

import time
from collections.abc import AsyncIterator, Awaitable, Callable
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request, Response

from ngome import __version__
from ngome.api.routes import account, health
from ngome.auth import router as auth_router
from ngome.auth.providers import build_google_verifier, build_sms_sender
from ngome.core.config import Settings, get_settings
from ngome.core.logging import configure_logging, get_logger
from ngome.db.session import create_engine, create_sessionmaker
from ngome.vault import router as vault_router
from ngome.vault.storage import build_blob_store

log = get_logger("ngome.http")


def _route_template(request: Request) -> str:
    # Log the template ("/v1/vault/backups/{backup_id}"), never the concrete path.
    route = request.scope.get("route")
    return str(getattr(route, "path", "unmatched"))


def create_app(settings: Settings | None = None) -> FastAPI:
    settings = settings or get_settings()
    configure_logging(settings.log_level, json=settings.log_json)
    engine = create_engine(settings.database_url)
    sessionmaker = create_sessionmaker(engine)
    blob_store = build_blob_store(settings, sessionmaker)

    @asynccontextmanager
    async def lifespan(_: FastAPI) -> AsyncIterator[None]:
        yield
        await blob_store.aclose()
        await engine.dispose()

    app = FastAPI(
        title="Pesa Clarity server (ngome)",
        version=__version__,
        lifespan=lifespan,
        docs_url=None if settings.environment == "production" else "/docs",
        redoc_url=None,
        openapi_url=None if settings.environment == "production" else "/openapi.json",
    )
    app.state.settings = settings
    app.state.engine = engine
    app.state.sessionmaker = sessionmaker
    app.state.blob_store = blob_store
    app.state.sms_sender = build_sms_sender(settings)
    app.state.google_verifier = build_google_verifier(settings)

    @app.middleware("http")
    async def access_log(
        request: Request, call_next: Callable[[Request], Awaitable[Response]]
    ) -> Response:
        started = time.perf_counter()
        response = await call_next(request)
        log.info(
            "http.request",
            method=request.method,
            route=_route_template(request),
            status=response.status_code,
            duration_ms=round((time.perf_counter() - started) * 1000, 1),
        )
        return response

    app.include_router(health.router)
    app.include_router(auth_router.router)
    app.include_router(account.router)
    app.include_router(vault_router.router)
    return app

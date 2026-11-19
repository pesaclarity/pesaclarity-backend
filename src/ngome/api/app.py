"""Application factory. Run with ``uvicorn ngome.api.app:create_app --factory``."""

import time
from collections.abc import AsyncIterator, Awaitable, Callable
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request, Response
from fastapi.staticfiles import StaticFiles

from ngome import __version__
from ngome.admin import router as admin_router
from ngome.admin.downloads import HttpDownloadsSource
from ngome.admin.web import ICON_CACHE, ICON_PATHS
from ngome.api.routes import account, health
from ngome.appstatus import router as app_status_router
from ngome.appstatus.signing import AppStatusSigner
from ngome.auth import router as auth_router
from ngome.auth.google import build_google_verifier
from ngome.auth.providers import build_email_sender
from ngome.core.config import Settings, get_settings
from ngome.core.logging import configure_logging, get_logger
from ngome.counting.country import build_country_lookup
from ngome.counting.service import FloodGate
from ngome.crashes import router as crashes_router
from ngome.db.migrate import upgrade_to_head
from ngome.db.session import create_engine, create_sessionmaker
from ngome.integrity import router as integrity_router
from ngome.integrity.apple import build_app_attest_policy, load_root_ca
from ngome.integrity.play import build_integrity_verifier
from ngome.privacy import router as privacy_router
from ngome.vault import router as vault_router
from ngome.vault.storage import build_blob_store

log = get_logger("ngome.http")

# The dashboard's headers (ADR 0024): its own files only, never framed, never cached.
ADMIN_HEADERS = {
    "Content-Security-Policy": (
        "default-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'"
    ),
    "Cache-Control": "no-store",
    "Referrer-Policy": "no-referrer",
    "X-Content-Type-Options": "nosniff",
}


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
        # Before the port opens, so Cloud Run sends no traffic to a revision until its
        # schema is in place, and keeps the old revision serving if a migration fails.
        if settings.migrate_on_start:
            revision = await upgrade_to_head(engine, settings.alembic_config)
            get_logger("ngome.db").info("db.migrated", revision=revision)
        yield
        await blob_store.aclose()
        await engine.dispose()

    if settings.admin_origin is not None and not settings.admin_sign_in_ready:
        # Fail safe: the server runs, and the dashboard refuses sign-in with this message.
        log.warning(
            "admin.sign_in_not_configured",
            missing=[
                n for n in ("admin_email", "admin_secret_key") if getattr(settings, n) is None
            ],
        )

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
    app.state.email_sender = build_email_sender(settings)
    app.state.google_verifier = build_google_verifier(settings)
    app.state.integrity_verifier = build_integrity_verifier(settings)
    app.state.app_attest_policy = build_app_attest_policy(settings)
    app.state.app_attest_root = load_root_ca()
    seed = settings.app_status_signing_seed
    app.state.app_status_signer = (
        AppStatusSigner.from_base64(seed.get_secret_value()) if seed else None
    )
    app.state.count_gate = FloodGate(settings.counting_max_new_per_hour)
    app.state.country_lookup = build_country_lookup(settings)
    app.state.downloads_source = (
        HttpDownloadsSource(settings.downloads_csv_url) if settings.downloads_csv_url else None
    )

    @app.middleware("http")
    async def access_log(
        request: Request, call_next: Callable[[Request], Awaitable[Response]]
    ) -> Response:
        started = time.perf_counter()
        response = await call_next(request)
        if request.url.path == "/admin" or request.url.path.startswith("/admin/"):
            response.headers.update(ADMIN_HEADERS)
        if request.url.path in ICON_PATHS and response.status_code == 200:
            response.headers["Cache-Control"] = ICON_CACHE
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
    app.include_router(integrity_router.router)
    app.include_router(privacy_router.router)
    app.include_router(app_status_router.router)
    app.include_router(app_status_router.admin_router)
    app.include_router(crashes_router.router)
    app.include_router(admin_router.web)
    app.include_router(admin_router.api)
    if settings.admin_origin is not None:
        app.mount(
            "/admin/static",
            StaticFiles(packages=[("ngome.admin", "static")]),
            name="admin-static",
        )
    return app

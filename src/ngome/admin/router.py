"""The dashboard's pages and CSVs under ``/admin``, and the admin-token routes under
``/v1/admin``: the starter command, the address check, and listing or removing passkeys.

The dashboard is off (every route 404) until ``NGOME_ADMIN_ORIGIN`` is set. Pages need a
completed sign-in (ADR 0025); CSVs also need a fresh second factor. Sign-in itself is in
:mod:`ngome.admin.signin`, the Security page in :mod:`ngome.admin.security`.
"""

import asyncio
import csv
import io
import uuid
from datetime import datetime, timedelta
from typing import Annotated, Any, cast

from fastapi import APIRouter, Depends, HTTPException, Request, status
from fastapi.responses import HTMLResponse, Response
from pydantic import BaseModel, ConfigDict, Field

from ngome.admin import accounts, audit, passkeys, security, signin, views
from ngome.admin.downloads import DownloadsSource, summarise
from ngome.admin.filters import Filters
from ngome.admin.filters import parse as parse_filters
from ngome.admin.web import (
    COOKIE,
    SIGN_IN,
    STATIC,
    Fresh,
    Me,
    dashboard_on,
    mail_of,
    shell_context,
    templates,
)
from ngome.api.deps import SessionDep, SettingsDep
from ngome.appstatus.router import AdminDep
from ngome.core.client import client_address
from ngome.core.logging import get_logger
from ngome.core.security import utcnow
from ngome.fl.config import FLSettings

__all__ = ["COOKIE", "SIGN_IN", "api", "templates", "web"]

log = get_logger(__name__)
On = Depends(dashboard_on)

web = APIRouter(include_in_schema=False)
web.include_router(signin.router)
web.include_router(security.router)


@web.get("/favicon.ico", dependencies=[On])
async def favicon() -> Response:
    """The dashboard's icon at the site root, where browsers look for it unasked."""
    icon = (STATIC / "favicon.ico").read_bytes()
    return Response(icon, media_type="image/vnd.microsoft.icon")


pages = APIRouter(prefix="/admin", include_in_schema=False)
api = APIRouter(prefix="/v1/admin", tags=["admin"])


def _page(request: Request, name: str, **context: Any) -> HTMLResponse:
    return templates.TemplateResponse(request, name, context)


# Pages.


def _downloads_source(request: Request) -> DownloadsSource | None:
    return cast(DownloadsSource | None, request.app.state.downloads_source)


async def _shell(session: SessionDep, settings: SettingsDep, me: Me) -> dict[str, Any]:
    """What every signed-in page's frame shows: the count of new crash groups beside
    Crashes, whether the country lookup is on (for "How it's counted"), and how this
    session signed in and when it ends."""
    return {
        "new_crash_groups": await views.new_groups(session, utcnow().date()),
        "country_on": settings.country_lookup_enabled,
        **shell_context(me, settings),
    }


Shell = Annotated[dict[str, Any], Depends(_shell)]


def _filters(request: Request, **options: Any) -> Filters:
    return parse_filters(request.query_params, **options)


@pages.get("", dependencies=[On])
async def overview_page(
    request: Request, session: SessionDep, settings: SettingsDep, shell: Shell
) -> HTMLResponse:
    source = _downloads_source(request)
    # Read the snapshot while the database is queried, so a slow GitHub does not add to it.
    fetch = asyncio.create_task(source.csv_text()) if source else None
    filters = _filters(request, default_days=30, day_choices=views.OVERVIEW_DAYS)
    text = await fetch if fetch else None
    # The page's one "up to" day is yesterday (UTC); downloads end on the same day.
    downloads = summarise(text, until=utcnow().date() - timedelta(days=1)) if text else None
    data = await views.overview(
        session,
        settings,
        today=utcnow().date(),
        filters=filters,
        downloads=downloads,
        downloads_state="off" if source is None else "ok" if downloads else "unread",
    )
    return _page(request, "overview.html", nav="overview", data=data, **shell)


@pages.get("/downloads", dependencies=[On])
async def downloads_page(request: Request, shell: Shell) -> HTMLResponse:
    source = _downloads_source(request)
    text = await source.csv_text() if source else None
    yesterday = utcnow().date() - timedelta(days=1)
    downloads = summarise(text, until=yesterday) if text else None
    q = (request.query_params.get("q") or "").strip()[:64]
    data = views.download_list(
        downloads,
        q=q,
        sort=request.query_params.get("sort") or "downloads",
        zeros=request.query_params.get("zeros") == "1",
    )
    return _page(
        request,
        "downloads.html",
        nav="overview",
        data=data,
        as_of=views.short_day(yesterday),
        state="off" if source is None else "ok" if downloads else "unread",
        **shell,
    )


@pages.get("/installs", dependencies=[On])
async def installs_page(
    request: Request, session: SessionDep, settings: SettingsDep, shell: Shell
) -> HTMLResponse:
    data = await views.installs(session, settings, today=utcnow().date(), filters=_filters(request))
    return _page(request, "installs.html", nav="installs", data=data, **shell)


@pages.get("/crashes", dependencies=[On])
async def crashes_page(request: Request, session: SessionDep, shell: Shell) -> HTMLResponse:
    filters = _filters(request, default_days=30, day_choices=views.CRASH_DAYS)
    data = await views.crashes(session, today=utcnow().date(), filters=filters)
    return _page(request, "crashes.html", nav="crashes", data=data, **shell)


@pages.get("/crashes/{group_id}", dependencies=[On])
async def crash_page(
    request: Request, group_id: uuid.UUID, session: SessionDep, shell: Shell
) -> HTMLResponse:
    filters = _filters(
        request, default_days=None, allow_all_days=True, day_choices=views.DETAIL_DAYS
    )
    data = await views.crash_group(session, group_id, today=utcnow().date(), filters=filters)
    if data is None:
        response = _page(request, "missing.html", nav="crashes", **shell)
        response.status_code = status.HTTP_404_NOT_FOUND
        return response
    return _page(request, "crash.html", nav="crashes", data=data, **shell)


@pages.get("/notices", dependencies=[On])
async def notices_page(request: Request, session: SessionDep, shell: Shell) -> HTMLResponse:
    data = await views.notices_page(session, today=utcnow().date())
    return _page(request, "notices.html", nav="notices", notices=data, **shell)


@pages.get("/learning", dependencies=[On])
async def learning_page(request: Request, shell: Shell) -> HTMLResponse:
    return _page(
        request,
        "learning.html",
        nav="learning",
        fl_min_cohort=FLSettings().min_cohort_size,
        **shell,
    )


# CSV: exactly what the pages show, with "<10" and "hidden" in place of small cells.


def _csv(name: str, rows: list[list[str]]) -> Response:
    buffer = io.StringIO()
    writer = csv.writer(buffer)
    for row in rows:
        # A spreadsheet must not read a cell as a formula.
        writer.writerow(["'" + c if c[:1] in ("=", "+", "-", "@") else c for c in row])
    return Response(
        buffer.getvalue(),
        media_type="text/csv; charset=utf-8",
        headers={"Content-Disposition": f'attachment; filename="{name}"'},
    )


@pages.get("/installs.csv", dependencies=[On])
async def installs_csv(
    request: Request, session: SessionDep, settings: SettingsDep, me: Fresh
) -> Response:
    data = await views.installs(session, settings, today=utcnow().date(), filters=_filters(request))
    return _csv(f"installs-{data.dim}-{data.month:%Y-%m}.csv", views.installs_csv(data))


@pages.get("/adoption.csv", dependencies=[On])
async def adoption_csv(
    request: Request, session: SessionDep, settings: SettingsDep, me: Fresh
) -> Response:
    data = await views.installs(session, settings, today=utcnow().date(), filters=_filters(request))
    return _csv(f"versions-to-{data.month:%Y-%m}.csv", views.adoption_csv(data))


@pages.get("/monthly.csv", dependencies=[On])
async def monthly_csv(
    request: Request, session: SessionDep, settings: SettingsDep, me: Fresh
) -> Response:
    data = await views.overview(
        session,
        settings,
        today=utcnow().date(),
        filters=_filters(request),
        downloads=None,
        downloads_state="off",
    )
    return _csv(f"monthly-installs-to-{data.month:%Y-%m}.csv", views.monthly_csv(data))


# The admin token's routes, from a terminal.


class StarterCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")
    username: str = Field(min_length=3, max_length=32)
    reset: bool = False


class StarterOut(BaseModel):
    username: str
    temporary_password: str
    expires_at: datetime
    sign_in_url: str


class PasskeyOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: uuid.UUID
    label: str
    created_at: datetime
    last_used_at: datetime | None


@api.post("/starter-user", status_code=status.HTTP_201_CREATED, dependencies=[AdminDep, On])
async def starter_user(
    request: Request, body: StarterCreate, session: SessionDep, settings: SettingsDep
) -> StarterOut:
    """Make the admin user with a random temporary password, shown only in this answer and
    good for one sign-in within ``admin_starter_hours``. Once a real password is set, this is
    refused (409) unless ``reset`` is true, which also wipes the authenticator, the recovery
    codes and every session (passkeys stay). The owner is emailed either way."""
    if not settings.admin_sign_in_ready:
        raise HTTPException(
            status.HTTP_503_SERVICE_UNAVAILABLE,
            "Set NGOME_ADMIN_EMAIL and NGOME_ADMIN_SECRET_KEY first (docs/deploying.md)",
        )
    try:
        made = await accounts.make_starter(
            session, settings, username=body.username, reset=body.reset
        )
    except accounts.AdminError as exc:
        conflict = "already set" in str(exc)
        raise HTTPException(
            status.HTTP_409_CONFLICT if conflict else status.HTTP_422_UNPROCESSABLE_CONTENT,
            str(exc),
        ) from None
    kind = "starter_reset" if made.reset else "starter_made"
    await audit.record(session, None, kind, ok=True)
    await session.commit()
    await audit.alert(
        session,
        settings,
        mail_of(request),
        "starter",
        detail="Reset: the authenticator, recovery codes and sessions were wiped."
        if made.reset
        else "A temporary password was made for the first sign-in.",
        now=utcnow(),
    )
    log.info("admin.starter_user", reset=made.reset)
    return StarterOut(
        username=made.username,
        temporary_password=made.password,
        expires_at=made.expires_at,
        sign_in_url=f"{settings.admin_origin}/admin/sign-in",
    )


@api.get("/client-address", dependencies=[AdminDep, On])
async def seen_address(request: Request, settings: SettingsDep) -> dict[str, str | None]:
    """The address limits and the audit log use for this request: send a made-up
    ``X-Forwarded-For`` and check that your real address comes back (``NGOME_PROXY_HOPS``)."""
    return {"address": client_address(request, settings.proxy_hops)}


@api.get("/passkeys", dependencies=[AdminDep, On])
async def list_passkeys(session: SessionDep) -> list[PasskeyOut]:
    return [PasskeyOut.model_validate(p) for p in await passkeys.list_passkeys(session)]


@api.delete(
    "/passkeys/{passkey_id}", status_code=status.HTTP_204_NO_CONTENT, dependencies=[AdminDep, On]
)
async def remove_passkey(passkey_id: uuid.UUID, session: SessionDep) -> Response:
    """Take a passkey off the list of second factors."""
    if not await passkeys.remove_passkey(session, passkey_id):
        raise HTTPException(status.HTTP_404_NOT_FOUND, "No such passkey")
    return Response(status_code=status.HTTP_204_NO_CONTENT)


web.include_router(pages)

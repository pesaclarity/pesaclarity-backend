"""``GET /v1/app-status`` for the app, and the admin routes that manage notices.

App status needs no account and sets no cookie. Neither the caller's address nor the query
is logged or stored: the access log records only the route template and status
(``ngome.api.app``), and Uvicorn's own access log is off.

The check-in may carry the app's random monthly ``Count-Token`` header (ADR 0024), which
``ngome.counting`` counts once a day and once a month as a keyed digest. It is a header so
that request logs, which record the URL, never hold it. The address is used only to look up
the country while answering, when that is on, and is then dropped.
"""

import uuid
from datetime import datetime, timedelta
from typing import Annotated, Any, cast

from fastapi import APIRouter, Depends, Header, HTTPException, Query, Request, status
from fastapi.responses import JSONResponse
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy.exc import SQLAlchemyError

from ngome.admin import audit, throttle
from ngome.api.deps import SessionDep, SettingsDep
from ngome.appstatus import service
from ngome.appstatus.schemas import Build, NoticeCreate, NoticeOut, Platform
from ngome.appstatus.signing import AppStatusSigner
from ngome.appstatus.versions import MAX_VERSION_LENGTH, VERSION_PATTERN
from ngome.core.client import client_address
from ngome.core.logging import get_logger
from ngome.core.security import constant_time_equals, utcnow
from ngome.counting import service as counting
from ngome.counting.country import CountryLookup

router = APIRouter(prefix="/v1", tags=["app status"])
admin_router = APIRouter(prefix="/v1/admin", tags=["admin"])

_admin_bearer = HTTPBearer(auto_error=False)
log = get_logger(__name__)


def get_app_status_signer(request: Request) -> AppStatusSigner | None:
    return cast(AppStatusSigner | None, request.app.state.app_status_signer)


@router.get("/app-status")
async def app_status(
    request: Request,
    session: SessionDep,
    settings: SettingsDep,
    signer: Annotated[AppStatusSigner | None, Depends(get_app_status_signer)],
    version: Annotated[str, Query(max_length=MAX_VERSION_LENGTH, pattern=VERSION_PATTERN)],
    build: Build,
    platform: Platform,
    count_token: Annotated[str | None, Header(alias="Count-Token", max_length=64)] = None,
) -> JSONResponse:
    """The newest version for this build and its active notices, signed with Ed25519.

    The body is ``{"alg", "payload", "signature"}``: ``payload`` is base64 of the JSON the
    app reads, and ``signature`` covers ``SIGNING_CONTEXT`` followed by those bytes.
    """
    if signer is None:
        raise HTTPException(status.HTTP_503_SERVICE_UNAVAILABLE, "App status is not set up")
    now = utcnow()
    payload = await service.app_status(
        session, version=version, build=build, platform=platform, now=now
    )
    await _count(request, session, settings, payload, token=count_token, now=now)
    max_age = settings.app_status_cache_seconds
    return JSONResponse(
        signer.envelope(payload),
        headers={"Cache-Control": f"public, max-age={max_age}" if max_age else "no-store"},
    )


async def _count(
    request: Request,
    session: SessionDep,
    settings: SettingsDep,
    payload: dict[str, Any],
    *,
    token: str | None,
    now: datetime,
) -> None:
    """Count the check-in and the notices it got. A failure here never fails the answer."""
    try:
        await counting.record_reach(
            session, (uuid.UUID(n["id"]) for n in payload["notices"]), now.date()
        )
        if token is None:
            return
        lookup = cast(CountryLookup | None, request.app.state.country_lookup)
        country = None
        if lookup is not None:
            country = lookup.country(client_address(request, settings.proxy_hops))
        await counting.record_check_in(
            session,
            settings,
            request.app.state.count_gate,
            token=token,
            build=payload["build"],
            version=payload["version"],
            country=country,
            now=now,
        )
    except SQLAlchemyError:
        await session.rollback()
        log.warning("counting.failed")


async def require_admin(
    request: Request,
    session: SessionDep,
    settings: SettingsDep,
    credentials: Annotated[HTTPAuthorizationCredentials | None, Depends(_admin_bearer)],
) -> None:
    """The admin token, compared in constant time. Wrong tokens count by client address:
    ``admin_address_max_failures`` an hour, then that address is refused for an hour."""
    expected = settings.admin_token
    if expected is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Not Found")
    now = utcnow()
    address = audit.address_key(settings, client_address(request, settings.proxy_hops))
    bucket = throttle.bucket(settings, "token-address", address)
    if await throttle.paused_until(session, bucket, now) is not None:
        raise HTTPException(status.HTTP_429_TOO_MANY_REQUESTS, "Too many tries. Try again later.")
    if credentials is None or not constant_time_equals(
        credentials.credentials, expected.get_secret_value()
    ):
        rule = throttle.Rule(
            settings.admin_address_max_failures, timedelta(hours=1), timedelta(hours=1)
        )
        await throttle.fail(session, bucket, rule, now)
        await session.commit()
        raise HTTPException(
            status.HTTP_401_UNAUTHORIZED,
            "Not authorised",
            headers={"WWW-Authenticate": "Bearer"},
        )


AdminDep = Depends(require_admin)


@admin_router.post("/app-notices", status_code=status.HTTP_201_CREATED, dependencies=[AdminDep])
async def create_notice(body: NoticeCreate, session: SessionDep) -> NoticeOut:
    """Send a notice: an update (with ``latest_version``, and ``min_version`` plus
    ``required_reason: "amounts_wrong"`` to block older builds) or news (``info``)."""
    return NoticeOut.model_validate(await service.create_notice(session, body))


@admin_router.get("/app-notices", dependencies=[AdminDep])
async def list_notices(session: SessionDep) -> list[NoticeOut]:
    return [NoticeOut.model_validate(n) for n in await service.list_notices(session)]


@admin_router.post("/app-notices/{notice_id}/disable", dependencies=[AdminDep])
async def disable_notice(notice_id: uuid.UUID, session: SessionDep) -> NoticeOut:
    """Stop showing a notice. It stays listed, with ``disabled_at`` set."""
    try:
        notice = await service.disable_notice(session, notice_id)
    except service.NoticeNotFoundError:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "No such notice") from None
    return NoticeOut.model_validate(notice)

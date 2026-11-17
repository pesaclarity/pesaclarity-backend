"""``GET /v1/app-status`` for the app, and the admin routes that manage notices.

App status needs no account and sets no cookie. Neither the caller's address nor the query
is logged or stored: the access log records only the route template and status
(``ngome.api.app``), and Uvicorn's own access log is off.
"""

import uuid
from typing import Annotated, cast

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from fastapi.responses import JSONResponse
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from ngome.api.deps import SessionDep, SettingsDep
from ngome.appstatus import service
from ngome.appstatus.schemas import Build, NoticeCreate, NoticeOut, Platform
from ngome.appstatus.signing import AppStatusSigner
from ngome.appstatus.versions import MAX_VERSION_LENGTH, VERSION_PATTERN
from ngome.core.security import constant_time_equals

router = APIRouter(prefix="/v1", tags=["app status"])
admin_router = APIRouter(prefix="/v1/admin", tags=["admin"])

_admin_bearer = HTTPBearer(auto_error=False)


def get_app_status_signer(request: Request) -> AppStatusSigner | None:
    return cast(AppStatusSigner | None, request.app.state.app_status_signer)


@router.get("/app-status")
async def app_status(
    session: SessionDep,
    settings: SettingsDep,
    signer: Annotated[AppStatusSigner | None, Depends(get_app_status_signer)],
    version: Annotated[str, Query(max_length=MAX_VERSION_LENGTH, pattern=VERSION_PATTERN)],
    build: Build,
    platform: Platform,
) -> JSONResponse:
    """The newest version for this build and its active notices, signed with Ed25519.

    The body is ``{"alg", "payload", "signature"}``: ``payload`` is base64 of the JSON the
    app reads, and ``signature`` covers ``SIGNING_CONTEXT`` followed by those bytes.
    """
    if signer is None:
        raise HTTPException(status.HTTP_503_SERVICE_UNAVAILABLE, "App status is not set up")
    payload = await service.app_status(session, version=version, build=build, platform=platform)
    max_age = settings.app_status_cache_seconds
    return JSONResponse(
        signer.envelope(payload),
        headers={"Cache-Control": f"public, max-age={max_age}" if max_age else "no-store"},
    )


async def require_admin(
    settings: SettingsDep,
    credentials: Annotated[HTTPAuthorizationCredentials | None, Depends(_admin_bearer)],
) -> None:
    expected = settings.admin_token
    if expected is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Not Found")
    if credentials is None or not constant_time_equals(
        credentials.credentials, expected.get_secret_value()
    ):
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

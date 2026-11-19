"""The dashboard's pages and passkey ceremonies under ``/admin``, and the admin-token routes
that enrol and remove passkeys under ``/v1/admin``.

The dashboard is off (every route 404) until ``NGOME_ADMIN_ORIGIN`` is set. Pages need a
session cookie from a passkey sign-in; every POST also checks ``Origin``.
"""

import uuid
from datetime import datetime
from importlib import resources
from typing import Annotated, Any, cast

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse, Response
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel, ConfigDict, Field

from ngome.admin import passkeys, views
from ngome.admin.downloads import DownloadsSource, summarise
from ngome.api.deps import SessionDep, SettingsDep
from ngome.appstatus.router import AdminDep
from ngome.appstatus.schemas import Build
from ngome.core.logging import get_logger
from ngome.core.security import utcnow
from ngome.counting.country import ATTRIBUTION, ATTRIBUTION_URL

COOKIE = "__Host-ngome_admin"
SIGN_IN = "/admin/sign-in"

log = get_logger(__name__)
templates = Jinja2Templates(directory=str(resources.files("ngome.admin") / "templates"))
templates.env.globals.update(
    number=views.number,
    month_name=views.month_name,
    attribution=ATTRIBUTION,
    attribution_url=ATTRIBUTION_URL,
)

web = APIRouter(prefix="/admin", include_in_schema=False)
api = APIRouter(prefix="/v1/admin", tags=["admin"])


def dashboard_on(settings: SettingsDep) -> None:
    if settings.admin_origin is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Not Found")


def same_origin(request: Request, settings: SettingsDep) -> None:
    """State-changing requests must come from the dashboard's own pages."""
    if request.headers.get("origin") != settings.admin_origin:
        raise HTTPException(status.HTTP_403_FORBIDDEN, "Wrong origin")


async def signed_in(request: Request, session: SessionDep) -> None:
    if not await passkeys.session_is_valid(session, request.cookies.get(COOKIE)):
        raise HTTPException(status.HTTP_303_SEE_OTHER, headers={"Location": SIGN_IN})


On = Depends(dashboard_on)
SameOrigin = Depends(same_origin)
SignedIn = Depends(signed_in)


def _page(request: Request, name: str, **context: Any) -> HTMLResponse:
    return templates.TemplateResponse(request, name, context)


def _set_session(response: Response, session_id: str, expires: datetime) -> None:
    response.set_cookie(
        COOKIE,
        session_id,
        max_age=round((expires - utcnow()).total_seconds()),
        path="/",
        secure=True,
        httponly=True,
        samesite="strict",
    )


class CeremonyStart(BaseModel):
    model_config = ConfigDict(extra="forbid")
    token: str | None = Field(default=None, max_length=128)


class CeremonyFinish(BaseModel):
    model_config = ConfigDict(extra="forbid")
    challenge_id: str = Field(max_length=128)
    credential: dict[str, Any]
    token: str | None = Field(default=None, max_length=128)


_FAILED = HTTPException(status.HTTP_400_BAD_REQUEST, "That passkey did not work")


# Sign-in and enrolment.


@web.get("/sign-in", dependencies=[On])
async def sign_in_page(request: Request) -> HTMLResponse:
    return _page(request, "sign_in.html")


@web.post("/sign-in/options", dependencies=[On, SameOrigin])
async def sign_in_options(session: SessionDep, settings: SettingsDep) -> JSONResponse:
    try:
        ceremony = await passkeys.sign_in_options(session, settings)
    except passkeys.PasskeyError:
        raise HTTPException(status.HTTP_429_TOO_MANY_REQUESTS, "Try again shortly") from None
    return JSONResponse({"challenge_id": ceremony.challenge_id, "options": ceremony.options})


@web.post("/sign-in/verify", dependencies=[On, SameOrigin])
async def sign_in_verify(
    body: CeremonyFinish, session: SessionDep, settings: SettingsDep
) -> JSONResponse:
    try:
        passkey = await passkeys.sign_in(
            session, settings, challenge_id=body.challenge_id, credential=body.credential
        )
    except passkeys.PasskeyError:
        log.warning("admin.sign_in_failed")
        raise _FAILED from None
    session_id, expires = await passkeys.start_session(session, settings, passkey)
    log.info("admin.signed_in")
    response = JSONResponse({"next": "/admin"})
    _set_session(response, session_id, expires)
    return response


@web.get("/enrol/{token}", dependencies=[On])
async def enrol_page(request: Request, token: str, session: SessionDep) -> HTMLResponse:
    is_open = await passkeys.enrolment_is_open(session, token)
    return _page(request, "enrol.html", token=token if is_open else None)


@web.post("/enrol/options", dependencies=[On, SameOrigin])
async def enrol_options(
    body: CeremonyStart, session: SessionDep, settings: SettingsDep
) -> JSONResponse:
    try:
        ceremony = await passkeys.registration_options(session, settings, body.token or "")
    except passkeys.PasskeyError:
        raise _FAILED from None
    return JSONResponse({"challenge_id": ceremony.challenge_id, "options": ceremony.options})


@web.post("/enrol/verify", dependencies=[On, SameOrigin])
async def enrol_verify(
    body: CeremonyFinish, session: SessionDep, settings: SettingsDep
) -> JSONResponse:
    try:
        passkey = await passkeys.register(
            session,
            settings,
            token=body.token or "",
            challenge_id=body.challenge_id,
            credential=body.credential,
        )
    except passkeys.PasskeyError:
        log.warning("admin.enrol_failed")
        raise _FAILED from None
    session_id, expires = await passkeys.start_session(session, settings, passkey)
    log.info("admin.passkey_enrolled")
    response = JSONResponse({"next": "/admin"})
    _set_session(response, session_id, expires)
    return response


@web.post("/sign-out", dependencies=[On, SameOrigin])
async def sign_out(request: Request, session: SessionDep) -> Response:
    await passkeys.end_session(session, request.cookies.get(COOKIE))
    response = RedirectResponse(SIGN_IN, status_code=status.HTTP_303_SEE_OTHER)
    response.delete_cookie(COOKIE, path="/", secure=True, httponly=True, samesite="strict")
    return response


# Pages.


def _downloads_source(request: Request) -> DownloadsSource | None:
    return cast(DownloadsSource | None, request.app.state.downloads_source)


@web.get("", dependencies=[On, SignedIn])
async def overview_page(
    request: Request,
    session: SessionDep,
    settings: SettingsDep,
    month: Annotated[str | None, Query(max_length=7)] = None,
) -> HTMLResponse:
    source = _downloads_source(request)
    text = await source.csv_text() if source else None
    data = await views.overview(
        session,
        settings,
        today=utcnow().date(),
        month_param=month,
        downloads=summarise(text) if text else None,
    )
    return _page(request, "overview.html", nav="overview", data=data)


@web.get("/installs", dependencies=[On, SignedIn])
async def installs_page(
    request: Request,
    session: SessionDep,
    settings: SettingsDep,
    month: Annotated[str | None, Query(max_length=7)] = None,
) -> HTMLResponse:
    data = await views.installs(session, settings, today=utcnow().date(), month_param=month)
    return _page(request, "installs.html", nav="installs", data=data)


CRASH_WINDOWS = (7, 30, 90)


@web.get("/crashes", dependencies=[On, SignedIn])
async def crashes_page(
    request: Request,
    session: SessionDep,
    days: Annotated[int, Query()] = 30,
    build: Annotated[Build | None, Query()] = None,
) -> HTMLResponse:
    if days not in CRASH_WINDOWS:
        days = 30
    data = await views.crashes(session, today=utcnow().date(), days=days, build=build)
    return _page(
        request,
        "crashes.html",
        nav="crashes",
        data=data,
        windows=CRASH_WINDOWS,
        builds=views.BUILD_NAMES,
    )


@web.get("/crashes/{group_id}", dependencies=[On, SignedIn])
async def crash_page(request: Request, group_id: uuid.UUID, session: SessionDep) -> HTMLResponse:
    data = await views.crash_group(session, group_id, today=utcnow().date())
    if data is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "No such crash group")
    return _page(request, "crash.html", nav="crashes", data=data)


# The admin token's routes: enrolling and removing passkeys from a terminal.


class EnrolmentCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")
    label: str = Field(min_length=1, max_length=64)


class EnrolmentOut(BaseModel):
    url: str
    expires_at: datetime


class PasskeyOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: uuid.UUID
    label: str
    created_at: datetime
    last_used_at: datetime | None


@api.post(
    "/passkey-enrolments",
    status_code=status.HTTP_201_CREATED,
    dependencies=[AdminDep, On],
)
async def create_enrolment(
    body: EnrolmentCreate, session: SessionDep, settings: SettingsDep
) -> EnrolmentOut:
    """A single-use link that registers one passkey, valid for ``admin_enrolment_minutes``.
    Open it in the browser that holds the passkey (or on the phone whose screen lock is it)."""
    enrolment = await passkeys.mint_enrolment(session, settings, body.label)
    return EnrolmentOut(
        url=f"{settings.admin_origin}/admin/enrol/{enrolment.token}",
        expires_at=enrolment.expires_at,
    )


@api.get("/passkeys", dependencies=[AdminDep, On])
async def list_passkeys(session: SessionDep) -> list[PasskeyOut]:
    return [PasskeyOut.model_validate(p) for p in await passkeys.list_passkeys(session)]


@api.delete(
    "/passkeys/{passkey_id}", status_code=status.HTTP_204_NO_CONTENT, dependencies=[AdminDep, On]
)
async def remove_passkey(passkey_id: uuid.UUID, session: SessionDep) -> Response:
    """Take a passkey off the allow-list; its sessions end with it."""
    if not await passkeys.remove_passkey(session, passkey_id):
        raise HTTPException(status.HTTP_404_NOT_FOUND, "No such passkey")
    return Response(status_code=status.HTTP_204_NO_CONTENT)

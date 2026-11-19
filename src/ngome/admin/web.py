"""What every dashboard route shares: templates, cookies, who is asking, and the checks that a
page is on, signed in and (for CSVs and sign-in changes) freshly confirmed."""

from datetime import datetime
from importlib import resources
from typing import Annotated, Any, cast
from urllib.parse import parse_qs, quote

from fastapi import Depends, HTTPException, Request, status
from fastapi.responses import HTMLResponse, RedirectResponse, Response
from fastapi.templating import Jinja2Templates

from ngome.admin import accounts, audit, views
from ngome.admin.accounts import FACTOR_NAMES, Stage
from ngome.admin.audit import Caller
from ngome.admin.filters import (
    BUILD_ITEMS,
    BUILD_NAMES,
    PLATFORM_ITEMS,
    PLATFORM_NAMES,
    month_items,
    options,
)
from ngome.admin.models import AdminSession
from ngome.api.deps import SessionDep, SettingsDep
from ngome.auth.providers import EmailSender
from ngome.core.client import client_address
from ngome.core.security import utcnow
from ngome.counting.country import ATTRIBUTION, ATTRIBUTION_URL, CountryLookup

COOKIE = "__Host-ngome_admin"
PENDING = "__Host-ngome_admin_pending"
DEVICE = "__Host-ngome_admin_device"
SIGN_IN = "/admin/sign-in"
DEVICE_DAYS = 400
_MAX_FORM = 8 * 1024

STAGE_PAGES = {
    Stage.PASSWORD.value: "/admin/first/password",
    Stage.AUTHENTICATOR.value: "/admin/first/authenticator",
    Stage.RECOVERY_CODES.value: "/admin/first/recovery-codes",
}

templates = Jinja2Templates(directory=str(resources.files("ngome.admin") / "templates"))
templates.env.globals.update(
    number=views.number,
    month_name=views.month_name,
    short_day=views.short_day,
    delta=views.delta,
    build_names=BUILD_NAMES,
    platform_names=PLATFORM_NAMES,
    options=options,
    build_items=BUILD_ITEMS,
    platform_items=PLATFORM_ITEMS,
    month_items=month_items,
    attribution=ATTRIBUTION,
    attribution_url=ATTRIBUTION_URL,
)


def page(request: Request, name: str, status_code: int = 200, **context: Any) -> HTMLResponse:
    return templates.TemplateResponse(request, name, context, status_code=status_code)


def see_other(location: str) -> RedirectResponse:
    return RedirectResponse(location, status_code=status.HTTP_303_SEE_OTHER)


def dashboard_on(settings: SettingsDep) -> None:
    if settings.admin_origin is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Not Found")


def same_origin(request: Request, settings: SettingsDep) -> None:
    """State-changing requests must come from the dashboard's own pages, on one of its
    origins (``Settings.admin_origins``).

    Scripted requests carry the page's ``Origin``. A plain form post from a page served with
    ``Referrer-Policy: no-referrer`` carries ``Origin: null`` instead, so that is accepted
    only with ``Sec-Fetch-Site: same-origin``, a header pages cannot set themselves.
    """
    origin = request.headers.get("origin")
    if origin is not None and origin in settings.admin_origins:
        return
    if origin in (None, "null") and request.headers.get("sec-fetch-site") == "same-origin":
        return
    raise HTTPException(status.HTTP_403_FORBIDDEN, "Wrong origin")


def ceremony_origin(request: Request, settings: SettingsDep) -> str:
    """A passkey ceremony's origin: the page's own, one of the dashboard's. Its host is the
    relying party, so a passkey works only on the address it was added on."""
    origin = request.headers.get("origin")
    if origin is None or origin not in settings.admin_origins:
        raise HTTPException(status.HTTP_403_FORBIDDEN, "Wrong origin")
    return origin


OriginDep = Annotated[str, Depends(ceremony_origin)]


def mail_of(request: Request) -> EmailSender:
    return cast(EmailSender, request.app.state.email_sender)


async def form(request: Request) -> dict[str, str]:
    """A small urlencoded form, without a multipart parser."""
    kind = request.headers.get("content-type", "").split(";")[0].strip()
    body = await request.body()
    if not body:
        return {}
    if kind != "application/x-www-form-urlencoded" or len(body) > _MAX_FORM:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Unexpected form")
    parsed = parse_qs(body.decode("utf-8", "replace"), keep_blank_values=True)
    return {k: v[0] for k, v in parsed.items()}


async def get_caller(request: Request, session: SessionDep, settings: SettingsDep) -> Caller:
    address = client_address(request, settings.proxy_hops)
    key = audit.address_key(settings, address)
    lookup = cast(CountryLookup | None, request.app.state.country_lookup)
    country = lookup.country(address) if lookup is not None and address else None
    device = await accounts.known_device(session, request.cookies.get(DEVICE))
    return Caller(
        address_key=key,
        address_hash=key[:16] if address else None,
        country=None if country in (None, "ZZ") else country,
        browser=audit.browser_of(request.headers.get("user-agent", ""))[:48],
        device_hash=device,
        known_browser=device is not None,
    )


CallerDep = Annotated[Caller, Depends(get_caller)]


async def current(
    request: Request, session: SessionDep, settings: SettingsDep
) -> AdminSession | None:
    return await accounts.load_session(session, settings, request.cookies.get(COOKIE))


async def signed_in(
    row: Annotated[AdminSession | None, Depends(current)],
) -> AdminSession:
    """A completed sign-in. A first sign-in still owing a step is sent to that step, from
    every page, CSV and form."""
    if row is None:
        raise HTTPException(status.HTTP_303_SEE_OTHER, headers={"Location": SIGN_IN})
    if row.stage != Stage.FULL.value:
        raise HTTPException(
            status.HTTP_303_SEE_OTHER, headers={"Location": STAGE_PAGES.get(row.stage, SIGN_IN)}
        )
    return row


Me = Annotated[AdminSession, Depends(signed_in)]


def _confirm(request: Request, strong: bool) -> HTTPException:
    target = request.url.path + (f"?{request.url.query}" if request.url.query else "")
    if request.method != "GET":
        target = "/admin/security"
    kind = "&for=settings" if strong else ""
    return HTTPException(
        status.HTTP_303_SEE_OTHER,
        headers={"Location": f"/admin/confirm?next={quote(target, safe='')}{kind}"},
    )


async def fresh(request: Request, me: Me) -> AdminSession:
    """A second factor within ``admin_reauth_minutes`` (any factor: CSV downloads)."""
    if not accounts.is_fresh(me, strong=False):
        raise _confirm(request, strong=False)
    return me


async def fresh_strong(request: Request, me: Me) -> AdminSession:
    """A recent authenticator code or passkey (not an email code): sign-in changes."""
    if not accounts.is_fresh(me, strong=True):
        raise _confirm(request, strong=True)
    return me


Fresh = Annotated[AdminSession, Depends(fresh)]
FreshStrong = Annotated[AdminSession, Depends(fresh_strong)]


def set_cookie(response: Response, name: str, value: str, expires: datetime) -> None:
    response.set_cookie(
        name,
        value,
        max_age=max(1, round((expires - utcnow()).total_seconds())),
        path="/",
        secure=True,
        httponly=True,
        samesite="strict",
    )


def drop_cookie(response: Response, name: str) -> None:
    response.delete_cookie(name, path="/", secure=True, httponly=True, samesite="strict")


def shell_context(me: AdminSession, settings: Any) -> dict[str, Any]:
    return {
        "me_factor": FACTOR_NAMES.get(me.factor, me.factor),
        "me_ends": f"{me.expires_at:%H:%M}",
        "me_idle": settings.admin_idle_minutes,
    }


def safe_next(target: str | None, default: str = "/admin") -> str:
    """Only the dashboard's own paths, never another site."""
    if not target or not target.startswith("/admin") or target.startswith("//") or "\\" in target:
        return default
    return target

"""The Security page (ADR 0025 §5): the password, second factors, recovery codes,
signed-in browsers and recent activity. Every change needs a fresh authenticator code or
passkey, and each one emails the owner."""

import uuid
from datetime import datetime
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Request, status
from fastapi.responses import HTMLResponse, JSONResponse, Response
from sqlalchemy import delete

from ngome.admin import accounts, audit, passkeys, passwords, views
from ngome.admin.accounts import FACTOR_NAMES
from ngome.admin.models import AdminEvent, AdminSession, AdminUser
from ngome.admin.signin import (
    WRONG_CODE,
    CeremonyFinish,
    authenticator_context,
    check_new_password,
    user_of,
)
from ngome.admin.web import (
    COOKIE,
    CallerDep,
    FreshStrong,
    Me,
    OriginDep,
    dashboard_on,
    form,
    mail_of,
    page,
    same_origin,
    see_other,
    shell_context,
)
from ngome.api.deps import SessionDep, SettingsDep
from ngome.core.config import Settings
from ngome.core.security import utcnow

router = APIRouter(
    prefix="/admin/security", include_in_schema=False, dependencies=[Depends(dashboard_on)]
)
SameOrigin = Depends(same_origin)

EVENT_WORDS = {
    "password": ("Password", "Wrong password"),
    "second_factor": ("Signed in", "Wrong second check"),
    "email_code_sent": ("Email code sent", "Email code not sent"),
    "paused": ("Sign-in paused", "Sign-in paused"),
    "starter_made": ("Starter user made", ""),
    "starter_reset": ("Sign-in reset with the admin token", ""),
    "password_changed": ("Password changed", ""),
    "authenticator_added": ("Authenticator added", ""),
    "authenticator_replaced": ("Authenticator replaced", ""),
    "recovery_codes_made": ("Recovery codes made", ""),
    "passkey_added": ("Passkey added", ""),
    "passkey_removed": ("Passkey removed", ""),
    "session_ended": ("Signed out a browser", ""),
    "signed_out": ("Signed out", ""),
    "reauth": ("Confirmed it\u2019s you", ""),
}
CHANGES = {
    "password_changed",
    "authenticator_added",
    "authenticator_replaced",
    "recovery_codes_made",
    "passkey_added",
    "passkey_removed",
    "starter_made",
    "starter_reset",
    "session_ended",
}


def _day(value: datetime | None) -> str:
    return f"{value:%-d %b %Y}" if value else ""


def _when(value: datetime) -> str:
    today = utcnow().date()
    label = "Today" if value.date() == today else f"{value:%-d %b}"
    return f"{label} {value:%H:%M}"


def _event(e: AdminEvent) -> dict[str, str]:
    good, bad = EVENT_WORDS.get(e.kind, (e.kind, e.kind))
    what = good if e.ok else bad or good
    if e.kind == "second_factor" and e.ok and e.factor:
        what = f"Signed in · {FACTOR_NAMES.get(e.factor, e.factor)}"
    if not e.browser and e.address_hash is None:
        parts = ["From a terminal, with the admin token"]
    else:
        parts = [e.browser or "A browser", e.country or "unknown country"]
        if not e.known_browser:
            parts.insert(0, "New browser")
    if e.kind == "paused":
        tone, badge = "red", "Paused"
    elif e.kind in CHANGES:
        tone, badge = "", "Change"
    elif e.ok:
        tone, badge = "ok", "OK"
    else:
        tone, badge = "", "Failed"
    return {
        "when": _when(e.at),
        "what": what,
        "where": " · ".join(parts),
        "tone": tone,
        "badge": badge,
    }


async def _data(session: SessionDep, settings: Settings, me: AdminSession) -> dict[str, Any]:
    user = await user_of(session, me.user_id)
    left, total = await accounts.recovery_left(session)
    rows = []
    for s in await accounts.sessions(session):
        this = s.id_hash == me.id_hash
        active = "active now" if this else f"active {s.last_seen_at:%H:%M}"
        rows.append(
            {
                "handle": s.id_hash[:16],
                "this": this,
                "browser": s.browser or "A browser",
                "desc": f"{s.country or 'Unknown country'} · {FACTOR_NAMES.get(s.factor, s.factor)}"
                f" · since {s.created_at:%H:%M} · {active}",
            }
        )
    return {
        "username": user.username,
        "password_changed": _day(user.password_changed_at),
        "codes_left": left,
        "codes_total": total or accounts.RECOVERY_CODES,
        "codes_made": _day(user.recovery_made_at),
        "passkeys": [
            {
                "id": p.id,
                "label": p.label,
                "added": _day(p.created_at),
                "used": _day(p.last_used_at),
            }
            for p in await passkeys.list_passkeys(session)
        ],
        "totp_added": _day(user.totp_added_at),
        "totp_used": _day(user.totp_used_at),
        "email": accounts.mask_email(settings.admin_email),
        "sessions": rows,
        "hours": settings.admin_session_hours,
        "idle": settings.admin_idle_minutes,
        "events": [_event(e) for e in await audit.recent(session)],
    }


async def _page(
    request: Request,
    session: SessionDep,
    settings: Settings,
    me: AdminSession,
    message: str = "",
) -> HTMLResponse:
    return page(
        request,
        "security.html",
        nav="security",
        page_title="Security",
        message=message,
        data=await _data(session, settings, me),
        new_crash_groups=await views.new_groups(session, utcnow().date()),
        **shell_context(me, settings),
    )


async def _changed(
    request: Request, session: SessionDep, settings: Settings, caller: CallerDep, kind: str
) -> None:
    await audit.record(session, caller, kind, ok=True)
    await session.commit()
    good, _ = EVENT_WORDS[kind]
    await audit.alert(
        session,
        settings,
        mail_of(request),
        "changed",
        detail=f"{good}. From: {caller.browser}, {caller.country or 'unknown'}.",
        now=utcnow(),
    )


@router.get("")
async def security_page(
    request: Request, me: Me, session: SessionDep, settings: SettingsDep
) -> HTMLResponse:
    done = {
        "password": "Password changed. Other browsers were signed out.",
        "authenticator": "Authenticator replaced.",
        "passkey": "Passkey removed.",
        "session": "Signed out.",
    }.get(request.query_params.get("done", ""), "")
    return await _page(request, session, settings, me, done)


@router.get("/password")
async def password_page(request: Request, me: FreshStrong, session: SessionDep) -> Response:
    user = await session.get(AdminUser, me.user_id)
    return page(
        request,
        "password.html",
        first=False,
        action="/admin/security/password",
        username=user.username if user else "",
    )


@router.post("/password", dependencies=[SameOrigin])
async def change_password(
    request: Request,
    me: FreshStrong,
    session: SessionDep,
    settings: SettingsDep,
    caller: CallerDep,
) -> Response:
    user = await user_of(session, me.user_id)
    fields = await form(request)
    if not await passwords.verify_password(user.password_hash, fields.get("current", "")[:256]):
        why: str | None = "The current password is wrong."
    else:
        why = await check_new_password(session, settings, user, fields)
    if why is not None:
        return page(
            request,
            "password.html",
            status_code=400,
            first=False,
            action="/admin/security/password",
            username=user.username,
            error=why,
        )
    await accounts.end_other_sessions(session, me)
    await _changed(request, session, settings, caller, "password_changed")
    return see_other("/admin/security?done=password")


@router.get("/authenticator")
async def authenticator_page(
    request: Request, me: FreshStrong, session: SessionDep, settings: SettingsDep
) -> Response:
    user = await user_of(session, me.user_id)
    context = await authenticator_context(session, settings, user)
    return page(
        request,
        "authenticator.html",
        first=False,
        action="/admin/security/authenticator",
        **context,
    )


@router.post("/authenticator", dependencies=[SameOrigin])
async def replace_authenticator(
    request: Request,
    me: FreshStrong,
    session: SessionDep,
    settings: SettingsDep,
    caller: CallerDep,
) -> Response:
    user = await user_of(session, me.user_id)
    code = (await form(request)).get("code", "")[:32]
    if not await accounts.totp_confirm(session, settings, user, code):
        context = await authenticator_context(session, settings, user)
        return page(
            request,
            "authenticator.html",
            status_code=400,
            first=False,
            action="/admin/security/authenticator",
            error=WRONG_CODE,
            **context,
        )
    await _changed(request, session, settings, caller, "authenticator_replaced")
    return see_other("/admin/security?done=authenticator")


@router.post("/recovery-codes", dependencies=[SameOrigin])
async def remake_codes(
    request: Request,
    me: FreshStrong,
    session: SessionDep,
    settings: SettingsDep,
    caller: CallerDep,
) -> Response:
    user = await user_of(session, me.user_id)
    codes = await accounts.new_recovery_codes(session, settings, user)
    await _changed(request, session, settings, caller, "recovery_codes_made")
    return page(
        request,
        "recovery_codes.html",
        first=False,
        codes=codes,
        action="/admin/security/recovery-codes/done",
    )


@router.post("/recovery-codes/done", dependencies=[SameOrigin])
async def codes_done(me: Me) -> Response:
    return see_other("/admin/security")


@router.post("/passkeys/options", dependencies=[SameOrigin])
async def add_passkey_options(
    me: FreshStrong,
    session: SessionDep,
    origin: OriginDep,
) -> JSONResponse:
    user = await user_of(session, me.user_id)
    try:
        ceremony = await passkeys.registration_options(
            session, origin, owner_hash=me.id_hash, username=user.username
        )
    except passkeys.PasskeyError:
        raise HTTPException(status.HTTP_429_TOO_MANY_REQUESTS, "Try again shortly") from None
    return JSONResponse({"challenge_id": ceremony.challenge_id, "options": ceremony.options})


@router.post("/passkeys/verify", dependencies=[SameOrigin])
async def add_passkey(
    request: Request,
    body: CeremonyFinish,
    me: FreshStrong,
    session: SessionDep,
    settings: SettingsDep,
    caller: CallerDep,
    origin: OriginDep,
) -> JSONResponse:
    label = (body.label or "").strip()[:64] or caller.browser
    try:
        await passkeys.register(
            session,
            origin,
            owner_hash=me.id_hash,
            challenge_id=body.challenge_id,
            credential=body.credential,
            label=label,
        )
    except passkeys.PasskeyError:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "That passkey did not work") from None
    await _changed(request, session, settings, caller, "passkey_added")
    return JSONResponse({"next": "/admin/security"})


@router.post("/passkeys/{passkey_id}/remove", dependencies=[SameOrigin])
async def remove_passkey(
    request: Request,
    passkey_id: uuid.UUID,
    me: FreshStrong,
    session: SessionDep,
    settings: SettingsDep,
    caller: CallerDep,
) -> Response:
    if not await passkeys.remove_passkey(session, passkey_id):
        raise HTTPException(status.HTTP_404_NOT_FOUND, "No such passkey")
    await _changed(request, session, settings, caller, "passkey_removed")
    return see_other("/admin/security?done=passkey")


@router.post("/sessions/end-others", dependencies=[SameOrigin])
async def end_others(
    request: Request,
    me: FreshStrong,
    session: SessionDep,
    settings: SettingsDep,
    caller: CallerDep,
) -> Response:
    await accounts.end_other_sessions(session, me)
    await _changed(request, session, settings, caller, "session_ended")
    return see_other("/admin/security?done=session")


@router.post("/sessions/{handle}/end", dependencies=[SameOrigin])
async def end_one(
    request: Request,
    handle: str,
    me: FreshStrong,
    session: SessionDep,
    settings: SettingsDep,
    caller: CallerDep,
) -> Response:
    if (
        len(handle) != 16
        or not all(c in "0123456789abcdef" for c in handle)
        or (me.id_hash.startswith(handle))
    ):
        raise HTTPException(status.HTTP_404_NOT_FOUND, "No such session")
    await session.execute(delete(AdminSession).where(AdminSession.id_hash.startswith(handle)))
    await _changed(request, session, settings, caller, "session_ended")
    return see_other("/admin/security?done=session")


__all__ = ["COOKIE", "router"]

"""Sign-in pages (ADR 0025): the password, the second factor, the first sign-in's forced
steps, and the fresh check before CSVs and sign-in changes.

Forms post as plain HTML; only passkeys need the page's script. Every POST checks ``Origin``.
"""

from datetime import timedelta
from typing import Annotated, Any
from urllib.parse import quote

from fastapi import APIRouter, Depends, HTTPException, Request, status
from fastapi.responses import HTMLResponse, JSONResponse, Response
from markupsafe import Markup
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import func, select

from ngome.admin import accounts, audit, passkeys, totp
from ngome.admin.accounts import Factor, Paused, Stage
from ngome.admin.models import AdminEmailCode, AdminPending, AdminSession, AdminUser
from ngome.admin.web import (
    COOKIE,
    DEVICE,
    DEVICE_DAYS,
    PENDING,
    SIGN_IN,
    STAGE_PAGES,
    CallerDep,
    OriginDep,
    current,
    dashboard_on,
    drop_cookie,
    form,
    mail_of,
    page,
    safe_next,
    same_origin,
    see_other,
    set_cookie,
)
from ngome.api.deps import SessionDep, SettingsDep
from ngome.core.config import Settings
from ngome.core.logging import get_logger
from ngome.core.security import utcnow

log = get_logger(__name__)
On = Depends(dashboard_on)
SameOrigin = Depends(same_origin)
router = APIRouter(prefix="/admin", include_in_schema=False, dependencies=[On])

WRONG_SIGN_IN = "That username and password don\u2019t match. Check both and try again."
WRONG_CODE = "That code didn\u2019t work. Check it and try again."
STARTED_OVER = "Too many wrong codes. Sign in again from the start."


class CeremonyFinish(BaseModel):
    model_config = ConfigDict(extra="forbid")
    challenge_id: str = Field(max_length=128)
    credential: dict[str, Any]
    next: str | None = Field(default=None, max_length=512)
    label: str | None = Field(default=None, max_length=64)


def not_ready(request: Request) -> HTMLResponse:
    """Deployed before NGOME_ADMIN_EMAIL and NGOME_ADMIN_SECRET_KEY were set: refuse sign-in
    and say what is missing, rather than fail the whole server."""
    return page(
        request, "sign_in.html", status_code=status.HTTP_503_SERVICE_UNAVAILABLE, not_ready=True
    )


def locked(request: Request, paused: Paused) -> HTMLResponse:
    left = max(0, int((paused.until - utcnow()).total_seconds()))
    return page(
        request,
        "locked.html",
        status_code=status.HTTP_429_TOO_MANY_REQUESTS,
        minutes=left // 60,
        seconds=left % 60,
        until=f"{paused.until:%H:%M}",
    )


async def _pending(request: Request, session: SessionDep) -> AdminPending | None:
    return await accounts.get_pending(session, request.cookies.get(PENDING))


PendingDep = Annotated[AdminPending | None, Depends(_pending)]


async def _user(session: SessionDep) -> AdminUser:
    user = await accounts.the_user(session)
    if user is None:
        raise HTTPException(status.HTTP_303_SEE_OTHER, headers={"Location": SIGN_IN})
    return user


def _owner(request: Request, name: str) -> str:
    return accounts.digest(request.cookies.get(name) or "-")


async def _wait(session: SessionDep, owner_hash: str) -> int:
    last = await session.scalar(
        select(func.max(AdminEmailCode.created_at)).where(AdminEmailCode.owner_hash == owner_hash)
    )
    if last is None:
        return 0
    return max(0, int((last + timedelta(seconds=60) - utcnow()).total_seconds()))


async def _complete(
    request: Request,
    session: SessionDep,
    settings: Settings,
    caller: CallerDep,
    user: AdminUser,
    factor: str,
    *,
    json_next: bool = False,
) -> Response:
    """The second factor passed: open a session and leave the sign-in in progress."""
    session_id, expires, device = await accounts.start_session(
        session, settings, mail_of(request), caller, user=user, stage=Stage.FULL, factor=factor
    )
    response: Response = JSONResponse({"next": "/admin"}) if json_next else see_other("/admin")
    set_cookie(response, COOKIE, session_id, expires)
    drop_cookie(response, PENDING)
    if device is not None:
        set_cookie(response, DEVICE, device, utcnow() + timedelta(days=DEVICE_DAYS))
    log.info("admin.signed_in", factor=factor)
    return response


# Step one.


@router.get("/sign-in")
async def sign_in_page(
    request: Request,
    session: SessionDep,
    settings: SettingsDep,
    row: Annotated[AdminSession | None, Depends(current)],
) -> Response:
    if not settings.admin_sign_in_ready:
        return not_ready(request)
    if row is not None:
        return see_other(STAGE_PAGES.get(row.stage, "/admin"))
    user = await accounts.the_user(session)
    return page(
        request,
        "sign_in.html",
        set_up=user is not None,
        first=user is not None and user.password_temporary,
    )


@router.post("/sign-in", dependencies=[SameOrigin])
async def sign_in(
    request: Request, session: SessionDep, settings: SettingsDep, caller: CallerDep
) -> Response:
    if not settings.admin_sign_in_ready:
        return not_ready(request)
    fields = await form(request)
    try:
        result = await accounts.check_password(
            session,
            settings,
            mail_of(request),
            caller,
            username=fields.get("username", "")[:64],
            password=fields.get("password", "")[:256],
        )
    except Paused as paused:
        return locked(request, paused)
    if result is None:
        user = await accounts.the_user(session)
        return page(
            request,
            "sign_in.html",
            status_code=status.HTTP_401_UNAUTHORIZED,
            set_up=True,
            first=user is not None and user.password_temporary,
            error=WRONG_SIGN_IN,
        )
    pending_id = await accounts.start_pending(
        session, settings, result.user, starter=result.starter
    )
    pending = await accounts.get_pending(session, pending_id)
    target = "/admin/sign-in/code"
    if result.starter:
        await accounts.send_email_code(
            session,
            settings,
            mail_of(request),
            caller,
            owner_hash=accounts.digest(pending_id),
            pending=pending,
        )
        target = "/admin/first/email"
    response = see_other(target)
    set_cookie(
        response, PENDING, pending_id, utcnow() + timedelta(minutes=settings.admin_pending_minutes)
    )
    return response


# Step two.


def _needs_pending(pending: AdminPending | None, *, starter: bool) -> AdminPending:
    if pending is None or pending.starter != starter:
        raise HTTPException(status.HTTP_303_SEE_OTHER, headers={"Location": SIGN_IN})
    return pending


async def user_of(session: SessionDep, user_id: Any) -> AdminUser:
    user = await session.get(AdminUser, user_id)
    if user is None:
        raise HTTPException(status.HTTP_303_SEE_OTHER, headers={"Location": SIGN_IN})
    return user


@router.get("/sign-in/code")
async def code_page(request: Request, pending: PendingDep) -> HTMLResponse:
    _needs_pending(pending, starter=False)
    return page(
        request, "code.html", title="Authenticator code", kind="totp", action="/admin/sign-in/code"
    )


@router.get("/sign-in/another")
async def another_page(
    request: Request, session: SessionDep, settings: SettingsDep, pending: PendingDep
) -> HTMLResponse:
    _needs_pending(pending, starter=False)
    return page(
        request,
        "another.html",
        has_passkeys=bool(await passkeys.list_passkeys(session)),
        masked=accounts.mask_email(settings.admin_email),
    )


@router.get("/sign-in/email")
async def email_page(
    request: Request, session: SessionDep, settings: SettingsDep, pending: PendingDep
) -> HTMLResponse:
    _needs_pending(pending, starter=False)
    return page(
        request,
        "code.html",
        title="Email code",
        kind="email",
        action="/admin/sign-in/email",
        resend="/admin/sign-in/email/send",
        masked=accounts.mask_email(settings.admin_email),
        host=accounts.host(settings),
        wait=await _wait(session, _owner(request, PENDING)),
    )


@router.get("/sign-in/recovery")
async def recovery_page(request: Request, pending: PendingDep) -> HTMLResponse:
    _needs_pending(pending, starter=False)
    return page(
        request,
        "code.html",
        title="Recovery code",
        kind="recovery",
        action="/admin/sign-in/recovery",
    )


async def _send(
    request: Request,
    session: SessionDep,
    settings: Settings,
    caller: CallerDep,
    pending: AdminPending,
) -> None:
    await accounts.send_email_code(
        session,
        settings,
        mail_of(request),
        caller,
        owner_hash=_owner(request, PENDING),
        pending=pending,
    )


@router.post("/sign-in/email/send", dependencies=[SameOrigin])
async def email_send(
    request: Request,
    session: SessionDep,
    settings: SettingsDep,
    caller: CallerDep,
    pending: PendingDep,
) -> Response:
    pending = _needs_pending(pending, starter=False)
    await _send(request, session, settings, caller, pending)
    return see_other("/admin/sign-in/email")


async def _second(
    request: Request,
    session: SessionDep,
    settings: Settings,
    caller: CallerDep,
    pending: AdminPending | None,
    factor: Factor,
    template: dict[str, Any],
) -> Response:
    pending = _needs_pending(pending, starter=False)
    user = await session.get(AdminUser, pending.user_id)
    if user is None:
        return see_other(SIGN_IN)
    code = (await form(request)).get("code", "")[:32]
    try:
        ok = await accounts.check_code(
            session,
            settings,
            mail_of(request),
            caller,
            user=user,
            factor=factor,
            code=code,
            owner_hash=_owner(request, PENDING),
            pending=pending,
        )
    except Paused as paused:
        return locked(request, paused)
    if ok:
        return await _complete(request, session, settings, caller, user, factor.value)
    if await accounts.get_pending(session, request.cookies.get(PENDING)) is None:
        response = page(
            request, "sign_in.html", status_code=401, set_up=True, first=False, error=STARTED_OVER
        )
        drop_cookie(response, PENDING)
        return response
    return page(request, "code.html", status_code=401, error=WRONG_CODE, **template)


@router.post("/sign-in/code", dependencies=[SameOrigin])
async def code_verify(
    request: Request,
    session: SessionDep,
    settings: SettingsDep,
    caller: CallerDep,
    pending: PendingDep,
) -> Response:
    return await _second(
        request,
        session,
        settings,
        caller,
        pending,
        Factor.TOTP,
        {"title": "Authenticator code", "kind": "totp", "action": "/admin/sign-in/code"},
    )


@router.post("/sign-in/email", dependencies=[SameOrigin])
async def email_verify(
    request: Request,
    session: SessionDep,
    settings: SettingsDep,
    caller: CallerDep,
    pending: PendingDep,
) -> Response:
    return await _second(
        request,
        session,
        settings,
        caller,
        pending,
        Factor.EMAIL,
        {
            "title": "Email code",
            "kind": "email",
            "action": "/admin/sign-in/email",
            "resend": "/admin/sign-in/email/send",
            "masked": accounts.mask_email(settings.admin_email),
            "host": accounts.host(settings),
            "wait": 0,
        },
    )


@router.post("/sign-in/recovery", dependencies=[SameOrigin])
async def recovery_verify(
    request: Request,
    session: SessionDep,
    settings: SettingsDep,
    caller: CallerDep,
    pending: PendingDep,
) -> Response:
    return await _second(
        request,
        session,
        settings,
        caller,
        pending,
        Factor.RECOVERY,
        {"title": "Recovery code", "kind": "recovery", "action": "/admin/sign-in/recovery"},
    )


@router.post("/sign-in/passkey/options", dependencies=[SameOrigin])
async def passkey_options(
    request: Request,
    session: SessionDep,
    settings: SettingsDep,
    pending: PendingDep,
    origin: OriginDep,
) -> JSONResponse:
    if pending is None or pending.starter:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Sign in with the password first")
    try:
        ceremony = await passkeys.assertion_options(
            session, origin, purpose="sign_in", owner_hash=_owner(request, PENDING)
        )
    except passkeys.PasskeyError:
        raise HTTPException(status.HTTP_429_TOO_MANY_REQUESTS, "Try again shortly") from None
    return JSONResponse({"challenge_id": ceremony.challenge_id, "options": ceremony.options})


@router.post("/sign-in/passkey/verify", dependencies=[SameOrigin])
async def passkey_verify(
    request: Request,
    body: CeremonyFinish,
    session: SessionDep,
    settings: SettingsDep,
    caller: CallerDep,
    pending: PendingDep,
    origin: OriginDep,
) -> Response:
    if pending is None or pending.starter:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Sign in with the password first")
    user = await user_of(session, pending.user_id)
    try:
        await passkeys.verify_assertion(
            session,
            origin,
            purpose="sign_in",
            owner_hash=_owner(request, PENDING),
            challenge_id=body.challenge_id,
            credential=body.credential,
        )
    except passkeys.PasskeyError:
        await audit.record(session, caller, "second_factor", ok=False, factor="passkey")
        await session.commit()
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "That passkey did not work") from None
    await audit.record(session, caller, "second_factor", ok=True, factor="passkey")
    await session.delete(pending)
    await session.commit()
    return await _complete(request, session, settings, caller, user, "passkey", json_next=True)


# The first sign-in: email check, then the forced steps.


@router.get("/first/email")
async def first_email_page(
    request: Request, session: SessionDep, settings: SettingsDep, pending: PendingDep
) -> HTMLResponse:
    _needs_pending(pending, starter=True)
    return page(
        request,
        "code.html",
        title="Confirm your email",
        kind="email",
        first=True,
        action="/admin/first/email",
        resend="/admin/first/email/send",
        masked=accounts.mask_email(settings.admin_email),
        host=accounts.host(settings),
        wait=await _wait(session, _owner(request, PENDING)),
    )


@router.post("/first/email/send", dependencies=[SameOrigin])
async def first_email_send(
    request: Request,
    session: SessionDep,
    settings: SettingsDep,
    caller: CallerDep,
    pending: PendingDep,
) -> Response:
    pending = _needs_pending(pending, starter=True)
    await _send(request, session, settings, caller, pending)
    return see_other("/admin/first/email")


@router.post("/first/email", dependencies=[SameOrigin])
async def first_email_verify(
    request: Request,
    session: SessionDep,
    settings: SettingsDep,
    caller: CallerDep,
    pending: PendingDep,
) -> Response:
    pending = _needs_pending(pending, starter=True)
    user = await session.get(AdminUser, pending.user_id)
    if user is None or not user.password_temporary:
        return see_other(SIGN_IN)
    code = (await form(request)).get("code", "")[:32]
    try:
        ok = await accounts.check_code(
            session,
            settings,
            mail_of(request),
            caller,
            user=user,
            factor=Factor.EMAIL,
            code=code,
            owner_hash=_owner(request, PENDING),
            pending=pending,
        )
    except Paused as paused:
        return locked(request, paused)
    if not ok:
        if await accounts.get_pending(session, request.cookies.get(PENDING)) is None:
            response: Response = page(
                request,
                "sign_in.html",
                status_code=401,
                set_up=True,
                first=True,
                error=STARTED_OVER,
            )
            drop_cookie(response, PENDING)
            return response
        return page(
            request,
            "code.html",
            status_code=401,
            title="Confirm your email",
            kind="email",
            first=True,
            action="/admin/first/email",
            resend="/admin/first/email/send",
            masked=accounts.mask_email(settings.admin_email),
            host=accounts.host(settings),
            wait=await _wait(session, _owner(request, PENDING)),
            error=WRONG_CODE,
        )
    # The temporary password is used up: from here on, only this session goes on.
    user.temporary_until = utcnow()
    await session.commit()
    session_id, expires, _ = await accounts.start_session(
        session,
        settings,
        mail_of(request),
        caller,
        user=user,
        stage=Stage.PASSWORD,
        factor="email",
    )
    response = see_other("/admin/first/password")
    set_cookie(response, COOKIE, session_id, expires)
    drop_cookie(response, PENDING)
    return response


async def staged(
    row: Annotated[AdminSession | None, Depends(current)], stage: Stage
) -> AdminSession:
    if row is None:
        raise HTTPException(status.HTTP_303_SEE_OTHER, headers={"Location": SIGN_IN})
    if row.stage != stage.value:
        raise HTTPException(
            status.HTTP_303_SEE_OTHER, headers={"Location": STAGE_PAGES.get(row.stage, "/admin")}
        )
    return row


async def _at_password(row: Annotated[AdminSession | None, Depends(current)]) -> AdminSession:
    return await staged(row, Stage.PASSWORD)


async def _at_authenticator(
    row: Annotated[AdminSession | None, Depends(current)],
) -> AdminSession:
    return await staged(row, Stage.AUTHENTICATOR)


async def _at_codes(row: Annotated[AdminSession | None, Depends(current)]) -> AdminSession:
    return await staged(row, Stage.RECOVERY_CODES)


AtPassword = Annotated[AdminSession, Depends(_at_password)]
AtAuthenticator = Annotated[AdminSession, Depends(_at_authenticator)]
AtCodes = Annotated[AdminSession, Depends(_at_codes)]


@router.get("/first/password")
async def first_password_page(request: Request, row: AtPassword, session: SessionDep) -> Response:
    user = await session.get(AdminUser, row.user_id)
    return page(
        request,
        "password.html",
        first=True,
        action="/admin/first/password",
        username=user.username if user else "",
    )


async def check_new_password(
    session: SessionDep, settings: Settings, user: AdminUser, fields: dict[str, str]
) -> str | None:
    new = fields.get("new_password", "")[:256]
    if new != fields.get("confirm", "")[:256]:
        return "The two passwords don\u2019t match."
    return await accounts.set_password(session, settings, user, new)


@router.post("/first/password", dependencies=[SameOrigin])
async def first_password(
    request: Request,
    row: AtPassword,
    session: SessionDep,
    settings: SettingsDep,
    caller: CallerDep,
) -> Response:
    user = await user_of(session, row.user_id)
    why = await check_new_password(session, settings, user, await form(request))
    if why is not None:
        return page(
            request,
            "password.html",
            status_code=400,
            first=True,
            action="/admin/first/password",
            username=user.username,
            error=why,
        )
    await audit.record(session, caller, "password_changed", ok=True)
    await session.commit()
    session_id, expires, _ = await accounts.advance(session, settings, row, Stage.AUTHENTICATOR)
    response = see_other("/admin/first/authenticator")
    set_cookie(response, COOKIE, session_id, expires)
    return response


async def authenticator_context(
    session: SessionDep, settings: Settings, user: AdminUser
) -> dict[str, Any]:
    secret = await accounts.totp_setup(session, settings, user)
    return {
        "qr": Markup(totp.qr_svg(totp.provisioning_uri(secret, user.username))),  # noqa: S704
        "key": totp.spaced(totp.key_text(secret)),
        "username": user.username,
    }


@router.get("/first/authenticator")
async def first_authenticator_page(
    request: Request, row: AtAuthenticator, session: SessionDep, settings: SettingsDep
) -> Response:
    user = await user_of(session, row.user_id)
    context = await authenticator_context(session, settings, user)
    return page(
        request, "authenticator.html", first=True, action="/admin/first/authenticator", **context
    )


@router.post("/first/authenticator", dependencies=[SameOrigin])
async def first_authenticator(
    request: Request,
    row: AtAuthenticator,
    session: SessionDep,
    settings: SettingsDep,
    caller: CallerDep,
) -> Response:
    user = await user_of(session, row.user_id)
    code = (await form(request)).get("code", "")[:32]
    if not await accounts.totp_confirm(session, settings, user, code):
        context = await authenticator_context(session, settings, user)
        return page(
            request,
            "authenticator.html",
            status_code=400,
            first=True,
            action="/admin/first/authenticator",
            error=WRONG_CODE,
            **context,
        )
    await audit.record(session, caller, "authenticator_added", ok=True)
    await session.commit()
    session_id, expires, _ = await accounts.advance(session, settings, row, Stage.RECOVERY_CODES)
    response = see_other("/admin/first/recovery-codes")
    set_cookie(response, COOKIE, session_id, expires)
    return response


@router.get("/first/recovery-codes")
async def first_codes_page(
    request: Request, row: AtCodes, session: SessionDep, settings: SettingsDep
) -> Response:
    # Shown once: each visit makes a new set, and only the last one shown works.
    user = await user_of(session, row.user_id)
    codes = await accounts.new_recovery_codes(session, settings, user)
    await session.commit()
    return page(
        request,
        "recovery_codes.html",
        first=True,
        codes=codes,
        action="/admin/first/recovery-codes",
    )


@router.post("/first/recovery-codes", dependencies=[SameOrigin])
async def first_codes_done(
    request: Request,
    row: AtCodes,
    session: SessionDep,
    settings: SettingsDep,
    caller: CallerDep,
) -> Response:
    if (await form(request)).get("saved") != "yes":
        return see_other("/admin/first/recovery-codes")
    await audit.record(session, caller, "recovery_codes_made", ok=True)
    await session.commit()
    session_id, expires, full = await accounts.advance(session, settings, row, Stage.FULL)
    # Opening the dashboard needed the authenticator just now: it counts as fresh.
    full.factor = "totp"
    await accounts.mark_fresh(session, settings, full, "totp")
    device = await accounts.remember_device(session, settings, mail_of(request), caller, full)
    response = see_other("/admin")
    set_cookie(response, COOKIE, session_id, expires)
    if device is not None:
        set_cookie(response, DEVICE, device, utcnow() + timedelta(days=DEVICE_DAYS))
    return response


@router.post("/sign-out", dependencies=[SameOrigin])
async def sign_out(request: Request, session: SessionDep, caller: CallerDep) -> Response:
    await accounts.end_session(session, request.cookies.get(COOKIE))
    await audit.record(session, caller, "signed_out", ok=True)
    await session.commit()
    response = see_other(SIGN_IN)
    drop_cookie(response, COOKIE)
    drop_cookie(response, PENDING)
    return response


# The fresh check before CSVs and sign-in changes.


def _is_csv(target: str) -> bool:
    return target.split("?", maxsplit=1)[0].endswith(".csv")


def _confirm_context(request: Request, settings: Settings, has_passkeys: bool) -> dict[str, Any]:
    target = safe_next(request.query_params.get("next"))
    strong = request.query_params.get("for") == "settings" or not _is_csv(target)
    return {
        "next": target,
        "strong": strong,
        "what": target.split("?")[0].rsplit("/", 1)[-1],
        "minutes": settings.admin_reauth_minutes,
        "has_passkeys": has_passkeys,
        "cancel": "/admin/security" if strong else "/admin",
    }


async def _full(row: Annotated[AdminSession | None, Depends(current)]) -> AdminSession:
    return await staged(row, Stage.FULL)


Full = Annotated[AdminSession, Depends(_full)]


@router.get("/confirm")
async def confirm_page(
    request: Request, me: Full, session: SessionDep, settings: SettingsDep
) -> HTMLResponse:
    context = _confirm_context(request, settings, bool(await passkeys.list_passkeys(session)))
    sent = request.query_params.get("sent") == "1" and not context["strong"]
    return page(request, "confirm.html", email_sent=sent, **context)


async def _confirmed(
    request: Request,
    session: SessionDep,
    settings: Settings,
    caller: CallerDep,
    me: AdminSession,
    factor: Factor,
    fields: dict[str, str],
) -> Response:
    user = await user_of(session, me.user_id)
    target = safe_next(fields.get("next"))
    try:
        ok = await accounts.check_code(
            session,
            settings,
            mail_of(request),
            caller,
            user=user,
            factor=factor,
            code=fields.get("code", "")[:32],
            owner_hash=me.id_hash,
        )
    except Paused as paused:
        return locked(request, paused)
    if not ok:
        has = bool(await passkeys.list_passkeys(session))
        context = _confirm_context(request, settings, has)
        context.update(next=target, strong=not _is_csv(target))
        context["what"] = target.split("?")[0].rsplit("/", 1)[-1]
        return page(
            request,
            "confirm.html",
            status_code=401,
            error=WRONG_CODE,
            email_sent=factor is Factor.EMAIL,
            **context,
        )
    await audit.record(session, caller, "reauth", ok=True, factor=factor.value)
    await accounts.mark_fresh(session, settings, me, factor.value)
    return see_other(target)


@router.post("/confirm", dependencies=[SameOrigin])
async def confirm(
    request: Request, me: Full, session: SessionDep, settings: SettingsDep, caller: CallerDep
) -> Response:
    return await _confirmed(
        request, session, settings, caller, me, Factor.TOTP, await form(request)
    )


@router.post("/confirm/email/send", dependencies=[SameOrigin])
async def confirm_email_send(
    request: Request, me: Full, session: SessionDep, settings: SettingsDep, caller: CallerDep
) -> Response:
    target = safe_next((await form(request)).get("next"))
    await accounts.send_email_code(
        session, settings, mail_of(request), caller, owner_hash=me.id_hash
    )
    return see_other(f"/admin/confirm?sent=1&next={quote(target, safe='')}")


@router.post("/confirm/email", dependencies=[SameOrigin])
async def confirm_email(
    request: Request, me: Full, session: SessionDep, settings: SettingsDep, caller: CallerDep
) -> Response:
    fields = await form(request)
    if not _is_csv(safe_next(fields.get("next"))):
        # An emailed code never opens sign-in changes.
        return see_other("/admin/security")
    return await _confirmed(request, session, settings, caller, me, Factor.EMAIL, fields)


@router.post("/confirm/passkey/options", dependencies=[SameOrigin])
async def confirm_passkey_options(
    me: Full,
    session: SessionDep,
    origin: OriginDep,
) -> JSONResponse:
    try:
        ceremony = await passkeys.assertion_options(
            session, origin, purpose="reauth", owner_hash=me.id_hash
        )
    except passkeys.PasskeyError:
        raise HTTPException(status.HTTP_429_TOO_MANY_REQUESTS, "Try again shortly") from None
    return JSONResponse({"challenge_id": ceremony.challenge_id, "options": ceremony.options})


@router.post("/confirm/passkey/verify", dependencies=[SameOrigin])
async def confirm_passkey_verify(
    body: CeremonyFinish,
    me: Full,
    session: SessionDep,
    settings: SettingsDep,
    caller: CallerDep,
    origin: OriginDep,
) -> JSONResponse:
    try:
        await passkeys.verify_assertion(
            session,
            origin,
            purpose="reauth",
            owner_hash=me.id_hash,
            challenge_id=body.challenge_id,
            credential=body.credential,
        )
    except passkeys.PasskeyError:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "That passkey did not work") from None
    await audit.record(session, caller, "reauth", ok=True, factor="passkey")
    await accounts.mark_fresh(session, settings, me, "passkey")
    return JSONResponse({"next": safe_next(body.next)})

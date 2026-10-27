"""Auth endpoints: email and Google sign-in, token refresh, sign-out and devices."""

import uuid
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, status

from ngome.api.deps import (
    PrincipalDep,
    SessionDep,
    SettingsDep,
    get_email_sender,
    get_google_verifier,
)
from ngome.auth import service
from ngome.auth.models import AuthEventKind
from ngome.auth.providers import EmailSender, GoogleVerifier, InvalidGoogleTokenError
from ngome.auth.schemas import (
    DeviceOut,
    EmailStartRequest,
    EmailStartResponse,
    EmailVerifyRequest,
    GoogleSignInRequest,
    RefreshRequest,
    TokenPair,
)

router = APIRouter(prefix="/v1/auth", tags=["auth"])


def _token_pair(tokens: service.IssuedTokens) -> TokenPair:
    return TokenPair(
        access_token=tokens.access_token,
        refresh_token=tokens.refresh_token,
        expires_in=tokens.expires_in,
        account_id=tokens.account_id,
        device_id=tokens.device_id,
    )


@router.post("/email/start", status_code=status.HTTP_202_ACCEPTED)
async def email_start(
    body: EmailStartRequest,
    session: SessionDep,
    settings: SettingsDep,
    mail: Annotated[EmailSender, Depends(get_email_sender)],
) -> EmailStartResponse:
    try:
        challenge = await service.start_email_sign_in(session, settings, mail, body.email)
    except service.InvalidEmailError:
        raise HTTPException(
            status.HTTP_422_UNPROCESSABLE_CONTENT, "That email address is not valid"
        ) from None
    except service.RateLimitedError:
        raise HTTPException(
            status.HTTP_429_TOO_MANY_REQUESTS, "Too many codes requested. Try again later."
        ) from None
    return EmailStartResponse(challenge_id=challenge.id, expires_in=settings.otp_ttl_seconds)


@router.post("/email/verify")
async def email_verify(
    body: EmailVerifyRequest, session: SessionDep, settings: SettingsDep
) -> TokenPair:
    try:
        tokens = await service.verify_email_sign_in(
            session, settings, body.challenge_id, body.code, body.device_name
        )
    except service.InvalidCodeError:
        raise HTTPException(
            status.HTTP_401_UNAUTHORIZED, "That code is wrong or has expired"
        ) from None
    return _token_pair(tokens)


@router.post("/google")
async def google(
    body: GoogleSignInRequest,
    session: SessionDep,
    settings: SettingsDep,
    verifier: Annotated[GoogleVerifier, Depends(get_google_verifier)],
) -> TokenPair:
    """Google sign-in for the Play Store build; the F-Droid build never calls this."""
    if not settings.google_sign_in_enabled:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Google sign-in is not enabled")
    try:
        identity = await verifier.verify(body.id_token)
    except InvalidGoogleTokenError:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Google sign-in failed") from None
    tokens = await service.google_sign_in(session, settings, identity.subject, body.device_name)
    return _token_pair(tokens)


@router.post("/refresh")
async def refresh(body: RefreshRequest, session: SessionDep, settings: SettingsDep) -> TokenPair:
    try:
        tokens = await service.refresh_tokens(session, settings, body.refresh_token)
    except service.InvalidRefreshTokenError:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Sign in again") from None
    return _token_pair(tokens)


@router.post("/sign-out", status_code=status.HTTP_204_NO_CONTENT)
async def sign_out(principal: PrincipalDep, session: SessionDep) -> None:
    await service.revoke_device(
        session, principal.account_id, principal.device_id, kind=AuthEventKind.SIGN_OUT
    )


@router.get("/devices")
async def devices(principal: PrincipalDep, session: SessionDep) -> list[DeviceOut]:
    return [
        DeviceOut(
            id=d.id,
            name=d.name,
            created_at=d.created_at,
            last_seen_at=d.last_seen_at,
            current=d.id == principal.device_id,
        )
        for d in await service.list_devices(session, principal.account_id)
    ]


@router.delete("/devices/{device_id}", status_code=status.HTTP_204_NO_CONTENT)
async def revoke_device(device_id: uuid.UUID, principal: PrincipalDep, session: SessionDep) -> None:
    """Remote sign-out: the device loses backup access on its very next request."""
    try:
        await service.revoke_device(session, principal.account_id, device_id)
    except service.DeviceNotFoundError:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Device not found") from None

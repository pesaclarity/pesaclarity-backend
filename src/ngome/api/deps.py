"""FastAPI dependencies shared by every router."""

import uuid
from collections.abc import AsyncIterator
from dataclasses import dataclass
from typing import Annotated, cast

from fastapi import Depends, HTTPException, Request, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from ngome.auth.models import Device
from ngome.auth.providers import EmailSender, GoogleVerifier
from ngome.core.config import Settings
from ngome.core.security import InvalidTokenError, decode_access_token
from ngome.vault.storage import BlobStore

_bearer = HTTPBearer(auto_error=False)


def get_settings(request: Request) -> Settings:
    return cast(Settings, request.app.state.settings)


async def get_session(request: Request) -> AsyncIterator[AsyncSession]:
    maker = cast(async_sessionmaker[AsyncSession], request.app.state.sessionmaker)
    async with maker() as session:
        yield session


def get_email_sender(request: Request) -> EmailSender:
    return cast(EmailSender, request.app.state.email_sender)


def get_google_verifier(request: Request) -> GoogleVerifier:
    return cast(GoogleVerifier, request.app.state.google_verifier)


def get_blob_store(request: Request) -> BlobStore:
    return cast(BlobStore, request.app.state.blob_store)


SettingsDep = Annotated[Settings, Depends(get_settings)]
SessionDep = Annotated[AsyncSession, Depends(get_session)]
BlobStoreDep = Annotated[BlobStore, Depends(get_blob_store)]


@dataclass(frozen=True, slots=True)
class Principal:
    account_id: uuid.UUID
    device_id: uuid.UUID


_UNAUTHORISED = HTTPException(
    status_code=status.HTTP_401_UNAUTHORIZED,
    detail="Not signed in",
    headers={"WWW-Authenticate": "Bearer"},
)


async def get_principal(
    settings: SettingsDep,
    session: SessionDep,
    credentials: Annotated[HTTPAuthorizationCredentials | None, Depends(_bearer)],
) -> Principal:
    """Resolve the bearer token, rejecting tokens from devices that have been signed out."""
    if credentials is None:
        raise _UNAUTHORISED
    try:
        claims = decode_access_token(settings, credentials.credentials)
    except InvalidTokenError:
        raise _UNAUTHORISED from None
    device = await session.get(Device, claims.device_id)
    if device is None or device.account_id != claims.account_id or device.revoked_at is not None:
        raise _UNAUTHORISED
    return Principal(account_id=claims.account_id, device_id=claims.device_id)


PrincipalDep = Annotated[Principal, Depends(get_principal)]

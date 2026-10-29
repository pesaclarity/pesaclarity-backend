"""App Attest key registration for iPhone installs."""

from typing import Annotated, cast

from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel, Field

from ngome.api.deps import PrincipalDep, SessionDep, SettingsDep
from ngome.core.logging import get_logger
from ngome.integrity import service
from ngome.integrity.apple import AppAttestPolicy
from ngome.integrity.play import IntegrityFailedError

log = get_logger(__name__)

router = APIRouter(prefix="/v1/integrity/app-attest", tags=["integrity"])


def get_app_attest_policy(request: Request) -> AppAttestPolicy:
    policy = cast(AppAttestPolicy | None, request.app.state.app_attest_policy)
    if policy is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "App Attest is not enabled")
    return policy


AppAttestPolicyDep = Annotated[AppAttestPolicy, Depends(get_app_attest_policy)]


class ChallengeOut(BaseModel):
    challenge: str


class KeyIn(BaseModel):
    key_id: str = Field(max_length=64)
    attestation: str = Field(max_length=16 * 1024)
    challenge: str = Field(max_length=64)


@router.post("/challenges", status_code=status.HTTP_201_CREATED)
async def new_challenge(
    principal: PrincipalDep,
    session: SessionDep,
    settings: SettingsDep,
    _: AppAttestPolicyDep,
) -> ChallengeOut:
    """A one-time challenge for registering a key."""
    challenge = await service.issue_challenge(
        session, principal.account_id, settings.app_attest_challenge_seconds
    )
    return ChallengeOut(challenge=challenge)


@router.post("/keys", status_code=status.HTTP_204_NO_CONTENT)
async def register_key(
    body: KeyIn,
    request: Request,
    principal: PrincipalDep,
    session: SessionDep,
    policy: AppAttestPolicyDep,
) -> None:
    """Register a key with Apple's attestation of it over a challenge from this server."""
    try:
        await service.register_key(
            session,
            principal.account_id,
            key_id=body.key_id,
            attestation=body.attestation,
            challenge=body.challenge,
            policy=policy,
            root=request.app.state.app_attest_root,
        )
    except IntegrityFailedError as exc:
        log.info("app_attest.refused", reason=exc.reason)
        raise HTTPException(
            status.HTTP_403_FORBIDDEN, "This install could not be verified"
        ) from None

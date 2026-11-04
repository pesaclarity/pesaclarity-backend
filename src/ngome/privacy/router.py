"""Endpoint for emailing a copy of the privacy policy."""

from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field

from ngome.api.deps import PrincipalDep, SessionDep, SettingsDep, get_email_sender
from ngome.auth.providers import EmailSender
from ngome.auth.service import InvalidEmailError
from ngome.privacy import service

router = APIRouter(prefix="/v1/privacy", tags=["privacy"])


class PolicyCopyRequest(BaseModel):
    email: str = Field(max_length=320)
    # The policy exactly as the app ships it (Markdown).
    policy: str = Field(max_length=2_000_000)


@router.post("/copy", status_code=status.HTTP_202_ACCEPTED)
async def send_copy(
    body: PolicyCopyRequest,
    principal: PrincipalDep,
    session: SessionDep,
    settings: SettingsDep,
    mail: Annotated[EmailSender, Depends(get_email_sender)],
) -> None:
    """Email the signed-in person a copy of the privacy policy, as text and a PDF.

    The address is used for this send only and is never stored or logged. Only approved
    versions of the policy (``NGOME_PRIVACY_POLICY_SHA256``) are sent.
    """
    if len(body.policy.encode("utf-8")) > settings.privacy_policy_max_bytes:
        raise HTTPException(status.HTTP_413_CONTENT_TOO_LARGE, "That policy is too long")
    try:
        await service.send_copy(
            session, settings, mail, principal.account_id, body.email, body.policy
        )
    except service.PolicyCopyOffError:
        raise HTTPException(
            status.HTTP_503_SERVICE_UNAVAILABLE, "Emailed copies are not available yet"
        ) from None
    except service.UnknownPolicyError:
        raise HTTPException(
            status.HTTP_422_UNPROCESSABLE_CONTENT, "That is not a current privacy policy"
        ) from None
    except InvalidEmailError:
        raise HTTPException(
            status.HTTP_422_UNPROCESSABLE_CONTENT, "That email address is not valid"
        ) from None
    except service.TooManyCopiesError:
        raise HTTPException(
            status.HTTP_429_TOO_MANY_REQUESTS, "You have had today's copies. Try again tomorrow."
        ) from None

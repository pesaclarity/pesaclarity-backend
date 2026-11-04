"""Emailing a copy of the privacy policy, as text and a PDF."""

import hashlib
import uuid
from datetime import timedelta

from sqlalchemy import delete, func, select
from sqlalchemy.ext.asyncio import AsyncSession

from ngome.auth.providers import Attachment, EmailSender
from ngome.auth.service import normalise_email
from ngome.core.config import Settings
from ngome.core.logging import get_logger
from ngome.core.security import utcnow
from ngome.privacy.models import PolicyCopy
from ngome.privacy.pdf import text_to_pdf

log = get_logger(__name__)

_WINDOW = timedelta(days=1)


class PolicyCopyOffError(Exception):
    """No approved policy is configured."""


class UnknownPolicyError(Exception):
    """The text is not an approved version of the policy."""


class TooManyCopiesError(Exception):
    """The account has had its copies for today."""


def policy_digest(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def plain_text(markdown: str) -> str:
    """The policy as readable plain text: headings in capitals, no Markdown marks."""
    lines = []
    for line in markdown.splitlines():
        stripped = line.strip()
        if stripped.startswith("#"):
            lines.append(stripped.lstrip("#").strip().upper())
            continue
        lines.append(line.replace("**", "").replace("__", "").replace("`", ""))
    return "\n".join(lines).strip() + "\n"


async def send_copy(
    session: AsyncSession,
    settings: Settings,
    mail: EmailSender,
    account_id: uuid.UUID,
    raw_email: str,
    policy: str,
) -> None:
    """Mail [policy] to [raw_email] as text and a PDF.

    Only an approved policy is sent, and the address is used for this send only: it is never
    stored or logged.
    """
    allowed = {d.lower() for d in settings.privacy_policy_sha256}
    if not allowed:
        raise PolicyCopyOffError
    if policy_digest(policy) not in allowed:
        raise UnknownPolicyError
    email = normalise_email(raw_email)

    now = utcnow()
    await session.execute(delete(PolicyCopy).where(PolicyCopy.sent_at < now - _WINDOW))
    sent_today = await session.scalar(
        select(func.count())
        .select_from(PolicyCopy)
        .where(PolicyCopy.account_id == account_id, PolicyCopy.sent_at >= now - _WINDOW)
    )
    if (sent_today or 0) >= settings.privacy_copy_max_per_day:
        await session.commit()
        raise TooManyCopiesError

    text = plain_text(policy)
    pdf = text_to_pdf(text, title=settings.privacy_copy_subject)
    await mail.send(
        email,
        settings.privacy_copy_subject,
        text,
        (Attachment("pesa-clarity-privacy-policy.pdf", "application/pdf", pdf),),
    )
    session.add(PolicyCopy(account_id=account_id, sent_at=now))
    await session.commit()
    log.info("privacy.copy_sent", account_id=str(account_id))

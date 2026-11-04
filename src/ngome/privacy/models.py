"""What we keep about policy copies: only that one was sent, for the daily limit."""

import uuid
from datetime import datetime

from sqlalchemy import ForeignKey, Uuid
from sqlalchemy.orm import Mapped, mapped_column

from ngome.core.security import utcnow
from ngome.db.base import Base, UTCDateTime


class PolicyCopy(Base):
    """One copy sent. No address is kept; rows older than a day are removed."""

    __tablename__ = "policy_copies"

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    account_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("accounts.id", ondelete="CASCADE"), index=True
    )
    sent_at: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow, index=True)

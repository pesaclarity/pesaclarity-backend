"""Notices the team sends to the app: an update, or news such as a bank changing its
messages. Nothing about who reads them is stored."""

import uuid
from datetime import date, datetime

from sqlalchemy import JSON, Date, String, Uuid
from sqlalchemy.orm import Mapped, mapped_column

from ngome.core.security import utcnow
from ngome.db.base import Base, UTCDateTime


class AppNotice(Base):
    __tablename__ = "app_notices"

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    # "update" or "info".
    kind: Mapped[str] = mapped_column(String(16))
    title: Mapped[str] = mapped_column(String(80))
    body: Mapped[str] = mapped_column(String(500))
    latest_version: Mapped[str | None] = mapped_column(String(64), nullable=True)
    min_version: Mapped[str | None] = mapped_column(String(64), nullable=True)
    # "amounts_wrong" is the only reason that may block the app.
    required_reason: Mapped[str | None] = mapped_column(String(32), nullable=True)
    # Which builds see it: any of "play", "foss", "ios", "website".
    builds: Mapped[list[str]] = mapped_column(JSON)
    # Asks the app to read its messages again from this day.
    reread_from: Mapped[date | None] = mapped_column(Date, nullable=True)
    starts_at: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow)
    ends_at: Mapped[datetime | None] = mapped_column(UTCDateTime, nullable=True)
    created_at: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow)
    disabled_at: Mapped[datetime | None] = mapped_column(UTCDateTime, nullable=True)

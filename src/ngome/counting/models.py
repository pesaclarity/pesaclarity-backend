"""Tables for counting. None of them holds a token, an address or a time of day."""

import uuid
from datetime import date, datetime

from sqlalchemy import Date, ForeignKey, Integer, LargeBinary, String, Uuid
from sqlalchemy.orm import Mapped, mapped_column

from ngome.db.base import Base, UTCDateTime

# A period is a day or a month; a month is stored as its first day.
DAY = "day"
MONTH = "month"


class CountKey(Base):
    """One random key per open period. Deleted when the period closes, after which nothing
    can link a past token to its digest."""

    __tablename__ = "count_keys"

    kind: Mapped[str] = mapped_column(String(8), primary_key=True)
    period: Mapped[date] = mapped_column(Date, primary_key=True)
    key: Mapped[bytes] = mapped_column(LargeBinary(32))


class CountSeen(Base):
    """A token seen in a period: the first 16 bytes of HMAC-SHA-256 of the token under that
    period's key, and nothing else."""

    __tablename__ = "count_seen"

    kind: Mapped[str] = mapped_column(String(8), primary_key=True)
    period: Mapped[date] = mapped_column(Date, primary_key=True)
    digest: Mapped[bytes] = mapped_column(LargeBinary(16), primary_key=True)


class CountTotal(Base):
    """How many tokens a period saw, one dimension per row: ``all``, ``build``, ``version``
    and, for months only, ``country``."""

    __tablename__ = "count_totals"

    kind: Mapped[str] = mapped_column(String(8), primary_key=True)
    period: Mapped[date] = mapped_column(Date, primary_key=True)
    dimension: Mapped[str] = mapped_column(String(16), primary_key=True)
    value: Mapped[str] = mapped_column(String(64), primary_key=True)
    n: Mapped[int] = mapped_column(Integer, default=0)


class CountFlood(Base):
    """An hour in which an instance hit the ceiling on new tokens, and how many it left
    uncounted."""

    __tablename__ = "count_floods"

    hour: Mapped[datetime] = mapped_column(UTCDateTime, primary_key=True)
    dropped: Mapped[int] = mapped_column(Integer, default=0)


class NoticeReach(Base):
    """How many check-ins got a notice on a day. Never who."""

    __tablename__ = "notice_reach"

    notice_id: Mapped[uuid.UUID] = mapped_column(
        Uuid, ForeignKey("app_notices.id", ondelete="CASCADE"), primary_key=True
    )
    day: Mapped[date] = mapped_column(Date, primary_key=True)
    n: Mapped[int] = mapped_column(Integer, default=0)

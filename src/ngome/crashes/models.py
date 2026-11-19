"""Crash reports and their groups. A report keeps the day it arrived, never the time."""

import uuid
from datetime import date

from sqlalchemy import JSON, Date, ForeignKey, Integer, String, Uuid
from sqlalchemy.orm import Mapped, mapped_column

from ngome.db.base import Base


class CrashGroup(Base):
    """Reports with the same error and first frames. It outlives its reports: once they are
    deleted it keeps only its counts and dates."""

    __tablename__ = "crash_groups"

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    fingerprint: Mapped[str] = mapped_column(String(64), unique=True)
    error: Mapped[str] = mapped_column(String(32))
    # The first frames as received (offsets in an obfuscated build).
    frames: Mapped[list[str]] = mapped_column(JSON)
    # Set by the decode job once the release's symbols are uploaded: the first frame in our
    # code, such as "InsightsController._monthTotals" and "insights_controller.dart:212".
    decoded_function: Mapped[str | None] = mapped_column(String(160), nullable=True)
    decoded_location: Mapped[str | None] = mapped_column(String(160), nullable=True)
    first_seen: Mapped[date] = mapped_column(Date)
    last_seen: Mapped[date] = mapped_column(Date, index=True)
    reports: Mapped[int] = mapped_column(Integer, default=0)


class CrashGroupDay(Base):
    """How many reports a group got on a day; kept as long as the group."""

    __tablename__ = "crash_group_days"

    group_id: Mapped[uuid.UUID] = mapped_column(
        Uuid, ForeignKey("crash_groups.id", ondelete="CASCADE"), primary_key=True
    )
    day: Mapped[date] = mapped_column(Date, primary_key=True, index=True)
    n: Mapped[int] = mapped_column(Integer, default=0)


class CrashReportRow(Base):
    """One report, exactly the fields received. Deleted after 90 days."""

    __tablename__ = "crash_reports"

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    group_id: Mapped[uuid.UUID] = mapped_column(
        Uuid, ForeignKey("crash_groups.id", ondelete="CASCADE"), index=True
    )
    received_on: Mapped[date] = mapped_column(Date, index=True)
    app: Mapped[str] = mapped_column(String(64))
    build_number: Mapped[int] = mapped_column(Integer)
    build: Mapped[str] = mapped_column(String(16))
    os: Mapped[str] = mapped_column(String(16))
    cpu: Mapped[str] = mapped_column(String(16))
    error: Mapped[str] = mapped_column(String(32))
    build_id: Mapped[str | None] = mapped_column(String(64), nullable=True)
    stack: Mapped[list[str]] = mapped_column(JSON)
    # Whether the decode job has turned the offsets into our code's names.
    decoded: Mapped[bool] = mapped_column(default=False)

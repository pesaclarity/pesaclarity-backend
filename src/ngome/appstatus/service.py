"""Which notices a build sees, and the payload the app verifies."""

import uuid
from datetime import datetime
from typing import Any

from sqlalchemy import or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from ngome.appstatus.models import AppNotice
from ngome.appstatus.schemas import NoticeCreate
from ngome.appstatus.versions import Version
from ngome.core.security import utcnow

PAYLOAD_FORMAT = 1


class NoticeNotFoundError(Exception):
    pass


async def create_notice(session: AsyncSession, body: NoticeCreate) -> AppNotice:
    notice = AppNotice(
        kind=body.kind,
        title=body.title,
        body=body.body,
        latest_version=body.latest_version,
        min_version=body.min_version,
        required_reason=body.required_reason,
        builds=list(body.builds),
        reread_from=body.reread_from,
        starts_at=body.starts_at or utcnow(),
        ends_at=body.ends_at,
    )
    session.add(notice)
    await session.commit()
    return notice


async def list_notices(session: AsyncSession) -> list[AppNotice]:
    result = await session.scalars(select(AppNotice).order_by(AppNotice.created_at.desc()))
    return list(result)


async def disable_notice(session: AsyncSession, notice_id: uuid.UUID) -> AppNotice:
    notice = await session.get(AppNotice, notice_id)
    if notice is None:
        raise NoticeNotFoundError
    if notice.disabled_at is None:
        notice.disabled_at = utcnow()
        await session.commit()
    return notice


def _applies(notice: AppNotice, version: Version, build: str) -> bool:
    if build not in notice.builds:
        return False
    if notice.kind == "update":
        # Only builds older than the update hear about it.
        return notice.latest_version is not None and version < Version(notice.latest_version)
    return True


def _notice_json(notice: AppNotice) -> dict[str, Any]:
    return {
        "id": str(notice.id),
        "kind": notice.kind,
        "title": notice.title,
        "body": notice.body,
        "latest_version": notice.latest_version,
        "min_version": notice.min_version,
        "required_reason": notice.required_reason,
        "reread_from": notice.reread_from.isoformat() if notice.reread_from else None,
    }


def _timestamp(moment: datetime) -> str:
    return moment.replace(microsecond=0).isoformat().replace("+00:00", "Z")


async def app_status(
    session: AsyncSession,
    *,
    version: str,
    build: str,
    platform: str,
    now: datetime | None = None,
) -> dict[str, Any]:
    """The payload for one build: the newest version out for it and its active notices.

    ``issued_at`` and the requested version, build and platform are part of the signed
    payload, so the app can refuse an old response or one made for another build.
    """
    now = now or utcnow()
    current = Version(version)
    rows = await session.scalars(
        select(AppNotice)
        .where(
            AppNotice.disabled_at.is_(None),
            AppNotice.starts_at <= now,
            or_(AppNotice.ends_at.is_(None), AppNotice.ends_at > now),
        )
        .order_by(AppNotice.starts_at.desc(), AppNotice.created_at.desc())
    )
    active = [notice for notice in rows if build in notice.builds]
    latest = max(
        (n.latest_version for n in active if n.kind == "update" and n.latest_version),
        key=Version,
        default=None,
    )
    shown = [notice for notice in active if _applies(notice, current, build)]
    return {
        "format": PAYLOAD_FORMAT,
        "issued_at": _timestamp(now),
        "version": version,
        "build": build,
        "platform": platform,
        "latest_version": latest,
        "notices": [_notice_json(notice) for notice in shown],
    }

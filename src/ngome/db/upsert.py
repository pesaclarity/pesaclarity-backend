"""``INSERT ... ON CONFLICT`` for the database in use: Postgres in production, SQLite in tests."""

from typing import Any

from sqlalchemy.dialects import postgresql, sqlite
from sqlalchemy.ext.asyncio import AsyncSession


def insert_for(session: AsyncSession) -> Any:
    """The dialect's ``insert`` (both have ``on_conflict_do_nothing`` and
    ``on_conflict_do_update``)."""
    bind = session.bind
    name = bind.dialect.name if bind is not None else "postgresql"
    return sqlite.insert if name == "sqlite" else postgresql.insert

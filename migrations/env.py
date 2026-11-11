"""Alembic environment, run against the async engine."""

import asyncio
from logging.config import fileConfig
from typing import Any, Literal

from alembic import context
from alembic.autogenerate.api import AutogenContext
from sqlalchemy import text
from sqlalchemy.engine import Connection

from ngome.core.config import get_settings
from ngome.db.base import UTCDateTime
from ngome.db.models import Base
from ngome.db.session import create_engine

config = context.config
# The server migrating on start keeps its own logging (ngome.db.migrate).
if config.config_file_name is not None and config.attributes.get("configure_logger", True):
    fileConfig(config.config_file_name)

target_metadata = Base.metadata

# Cloud Run can start several instances of a new revision at once, and each migrates as it
# starts, alongside the migrate job. A transaction-level advisory lock makes them take turns:
# the first applies the migrations, the rest then find nothing to do. Any fixed 64-bit key
# works, as long as nothing else in the database uses it.
_MIGRATION_LOCK_KEY = 0x6E676F6D65_4D4947  # "ngome" "MIG"


def _render_item(type_: str, obj: Any, autogen_context: AutogenContext) -> str | Literal[False]:
    # Migrations should not import application code, so render our column types as plain SQLAlchemy.
    if type_ == "type" and isinstance(obj, UTCDateTime):
        return "sa.DateTime(timezone=True)"
    return False


def _run(connection: Connection) -> None:
    context.configure(
        connection=connection,
        target_metadata=target_metadata,
        compare_type=True,
        render_item=_render_item,
        render_as_batch=connection.dialect.name == "sqlite",
    )
    with context.begin_transaction():
        if connection.dialect.name == "postgresql":
            connection.execute(
                text("SELECT pg_advisory_xact_lock(:key)"), {"key": _MIGRATION_LOCK_KEY}
            )
        context.run_migrations()


async def _run_online() -> None:
    engine = create_engine(get_settings().database_url)
    async with engine.connect() as connection:
        await connection.run_sync(_run)
    await engine.dispose()


def _run_offline() -> None:
    context.configure(
        url=get_settings().database_url,
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
    )
    with context.begin_transaction():
        context.run_migrations()


shared_connection: Connection | None = config.attributes.get("connection")
if context.is_offline_mode():
    _run_offline()
elif shared_connection is not None:
    _run(shared_connection)
else:
    asyncio.run(_run_online())

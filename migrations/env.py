"""Alembic environment, run against the async engine."""

import asyncio
from logging.config import fileConfig
from typing import Any, Literal

from alembic import context
from alembic.autogenerate.api import AutogenContext
from sqlalchemy.engine import Connection

from ngome.core.config import get_settings
from ngome.db.base import UTCDateTime
from ngome.db.models import Base
from ngome.db.session import create_engine

config = context.config
if config.config_file_name is not None:
    fileConfig(config.config_file_name)

target_metadata = Base.metadata


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


if context.is_offline_mode():
    _run_offline()
else:
    asyncio.run(_run_online())

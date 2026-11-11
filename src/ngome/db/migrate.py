"""Bring the schema up to date from inside the server, with the app's own engine."""

from pathlib import Path

from alembic import command
from alembic.config import Config
from alembic.runtime.migration import MigrationContext
from sqlalchemy.engine import Connection
from sqlalchemy.ext.asyncio import AsyncEngine


def _upgrade(connection: Connection, config: Config) -> str | None:
    # migrations/env.py runs on this connection instead of opening its own.
    config.attributes["connection"] = connection
    command.upgrade(config, "head")
    return MigrationContext.configure(connection).get_current_revision()


async def upgrade_to_head(engine: AsyncEngine, alembic_ini: Path) -> str | None:
    """Apply every pending migration in one transaction and return the revision now in
    place. Concurrent callers on Postgres wait for each other (migrations/env.py)."""
    config = Config(str(alembic_ini))
    # Alembic's logging config would replace the server's.
    config.attributes["configure_logger"] = False
    async with engine.begin() as connection:
        return await connection.run_sync(_upgrade, config)

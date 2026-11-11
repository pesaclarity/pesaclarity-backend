"""The server brings the schema up to date as it starts (docs/deploying.md)."""

import asyncio
import logging
import os
import sys
from pathlib import Path

import pytest
from alembic import command
from alembic.config import Config
from alembic.script import ScriptDirectory
from sqlalchemy import inspect
from sqlalchemy.engine import Connection
from sqlalchemy.ext.asyncio import AsyncEngine

from ngome.api.app import create_app
from ngome.db.migrate import upgrade_to_head
from ngome.db.models import Base
from ngome.db.session import create_engine
from tests.conftest import make_settings

ALEMBIC_INI = Path(__file__).resolve().parents[1] / "alembic.ini"
HEAD = ScriptDirectory.from_config(Config(str(ALEMBIC_INI))).get_current_head()

POSTGRES_URL = os.environ.get("NGOME_TEST_DATABASE_URL")
postgres = pytest.mark.skipif(
    POSTGRES_URL is None, reason="set NGOME_TEST_DATABASE_URL to an empty Postgres database"
)


async def _tables(engine: AsyncEngine) -> set[str]:
    async with engine.connect() as connection:
        return set(await connection.run_sync(lambda c: inspect(c).get_table_names()))


async def test_upgrade_to_head_builds_the_whole_schema(tmp_path: Path) -> None:
    engine = create_engine(f"sqlite+aiosqlite:///{tmp_path / 'fresh.db'}")
    try:
        assert await upgrade_to_head(engine, ALEMBIC_INI) == HEAD
        assert await _tables(engine) >= {*Base.metadata.tables, "alembic_version"}
        # Already current: nothing to do, same revision.
        assert await upgrade_to_head(engine, ALEMBIC_INI) == HEAD
    finally:
        await engine.dispose()


async def test_app_migrates_on_start_and_keeps_its_logging(tmp_path: Path) -> None:
    settings = make_settings(tmp_path, migrate_on_start=True, alembic_config=ALEMBIC_INI)
    app = create_app(settings)
    # Alembic's fileConfig would disable loggers that already exist.
    existing = logging.getLogger("ngome.test.existing")
    async with app.router.lifespan_context(app):
        assert "alembic_version" in await _tables(app.state.engine)
    assert not existing.disabled


async def test_app_leaves_the_schema_alone_by_default(tmp_path: Path) -> None:
    app = create_app(make_settings(tmp_path))
    async with app.router.lifespan_context(app):
        assert await _tables(app.state.engine) == set()


def _downgrade_to_base(connection: Connection) -> None:
    config = Config(str(ALEMBIC_INI))
    config.attributes["configure_logger"] = False
    config.attributes["connection"] = connection
    command.downgrade(config, "base")


# A server instance starting up, and the migrate job. Separate processes, as on Cloud Run:
# Alembic keeps its state per process.
_INSTANCE = (
    "import asyncio, sys\n"
    "from pathlib import Path\n"
    "from ngome.db.migrate import upgrade_to_head\n"
    "from ngome.db.session import create_engine\n"
    "async def main():\n"
    "    engine = create_engine(sys.argv[1])\n"
    "    print(await upgrade_to_head(engine, Path(sys.argv[2])))\n"
    "    await engine.dispose()\n"
    "asyncio.run(main())\n"
)


async def _run(*args: str, database_url: str) -> str:
    process = await asyncio.create_subprocess_exec(
        sys.executable,
        *args,
        env={**os.environ, "NGOME_DATABASE_URL": database_url},
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    out, err = await process.communicate()
    assert process.returncode == 0, err.decode()
    return out.decode().strip()


@pytest.mark.postgres
@postgres
async def test_instances_starting_together_migrate_once() -> None:
    assert POSTGRES_URL is not None
    engine = create_engine(POSTGRES_URL)
    try:
        async with engine.begin() as connection:
            await connection.run_sync(_downgrade_to_base)
        # Without the lock, all but one would fail creating tables that already exist.
        results = await asyncio.gather(
            *(
                _run("-c", _INSTANCE, POSTGRES_URL, str(ALEMBIC_INI), database_url=POSTGRES_URL)
                for _ in range(3)
            ),
            _run(
                "-m",
                "alembic",
                "-c",
                str(ALEMBIC_INI),
                "upgrade",
                "head",
                database_url=POSTGRES_URL,
            ),
        )
        assert results[:3] == [HEAD] * 3
        assert await _tables(engine) >= {*Base.metadata.tables, "alembic_version"}
    finally:
        await engine.dispose()

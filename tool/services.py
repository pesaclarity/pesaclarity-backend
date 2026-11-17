"""Finds the Postgres and MinIO that tool/check's integration steps use.

    python tool/services.py postgres URL   recreate an empty scratch database on the
                                           server at URL and print its asyncpg URL
    python tool/services.py s3 ENDPOINT    succeed if MinIO (or S3) answers at ENDPOINT

Exits 2 when the service cannot be reached, so tool/check can skip with a notice.
"""

import asyncio
import sys
import urllib.request
from urllib.parse import urlsplit, urlunsplit

import asyncpg

# Recreated on every run; never your development database.
SCRATCH_DATABASE = "ngome_check"


async def scratch_postgres(server_url: str) -> str:
    plain = server_url.replace("postgresql+asyncpg://", "postgresql://", 1)
    connection = await asyncpg.connect(plain, timeout=3)
    try:
        await connection.execute(f'DROP DATABASE IF EXISTS "{SCRATCH_DATABASE}" WITH (FORCE)')
        await connection.execute(f'CREATE DATABASE "{SCRATCH_DATABASE}"')
    finally:
        await connection.close()
    parts = urlsplit(plain)
    scratch = urlunsplit(parts._replace(path=f"/{SCRATCH_DATABASE}"))
    return scratch.replace("postgresql://", "postgresql+asyncpg://", 1)


def s3_ready(endpoint: str) -> None:
    # MinIO's readiness probe, as the old CI job used.
    url = endpoint.rstrip("/") + "/minio/health/ready"
    with urllib.request.urlopen(url, timeout=3):  # noqa: S310 (local endpoint from settings)
        pass


def main() -> int:
    kind, url = sys.argv[1], sys.argv[2]
    try:
        if kind == "postgres":
            sys.stdout.write(asyncio.run(scratch_postgres(url)) + "\n")
        else:
            s3_ready(url)
    except (OSError, asyncpg.PostgresError, TimeoutError) as exc:
        sys.stderr.write(f"{kind} not reachable at {url}: {type(exc).__name__}\n")
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())

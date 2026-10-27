from collections.abc import AsyncIterable, AsyncIterator
from dataclasses import dataclass, field
from pathlib import Path

import httpx
import pytest
from fastapi import FastAPI
from pydantic import SecretStr

from ngome.api.app import create_app
from ngome.auth.providers import GoogleIdentity, InvalidGoogleTokenError
from ngome.core.config import Settings
from ngome.db.models import Base
from ngome.vault.storage import BlobNotFoundError, BlobStore, FilesystemBlobStore

# Reserved example domain: never a real mailbox.
EMAIL = "Wanjiku@Example.com "
OTHER_EMAIL = "otieno@example.com"


@dataclass
class FakeMail:
    sent: list[tuple[str, str]] = field(default_factory=list)

    async def send(self, to: str, subject: str, text: str) -> None:
        self.sent.append((to, text))

    def last_code(self) -> str:
        return next(
            word.rstrip(".") for word in self.sent[-1][1].split() if word.rstrip(".").isdigit()
        )


class FakeGoogle:
    async def verify(self, id_token: str) -> GoogleIdentity:
        if not id_token.startswith("valid:"):
            raise InvalidGoogleTokenError
        return GoogleIdentity(subject=id_token.removeprefix("valid:"))


class MemoryBlobStore:
    """In-memory :class:`BlobStore` that can be told to fail deletes."""

    def __init__(self) -> None:
        self.objects: dict[str, bytes] = {}
        self.fail_deletes = False
        self.delete_calls = 0

    async def put(self, key: str, chunks: AsyncIterable[bytes]) -> None:
        buffer = bytearray()
        async for chunk in chunks:
            buffer.extend(chunk)
        self.objects[key] = bytes(buffer)

    async def open(self, key: str) -> AsyncIterator[bytes]:
        if key not in self.objects:
            raise BlobNotFoundError(key)
        data = self.objects[key]

        async def stream() -> AsyncIterator[bytes]:
            for start in range(0, len(data), 100):
                yield data[start : start + 100]

        return stream()

    async def delete(self, key: str) -> None:
        self.delete_calls += 1
        if self.fail_deletes:
            raise OSError("object store unavailable")
        self.objects.pop(key, None)

    async def aclose(self) -> None:
        return None


def make_settings(tmp_path: Path, **overrides: object) -> Settings:
    values: dict[str, object] = {
        "environment": "test",
        "database_url": f"sqlite+aiosqlite:///{tmp_path / 'test.db'}",
        "jwt_secret": SecretStr("test-jwt-secret-" + "x" * 32),
        "contact_pepper": SecretStr("test-contact-pepper-" + "y" * 32),
        "log_json": False,
        "vault_max_backup_bytes": 4096,
        "vault_keep_backups": 3,
        "google_sign_in_enabled": True,
        "google_client_ids": ["test-client.apps.example"],
        "email_code_subject": "Test code: {code}",
        "email_code_body": "Your test code is {code}. It works for {minutes} minutes.",
    }
    values.update(overrides)
    return Settings(**values)  # type: ignore[arg-type]


@pytest.fixture
def settings(tmp_path: Path) -> Settings:
    return make_settings(tmp_path)


@pytest.fixture
def mail() -> FakeMail:
    return FakeMail()


@pytest.fixture
def blob_store_kind() -> str:
    """Which blob store the app uses: ``memory`` (the fake), or the real ``postgres`` or
    ``filesystem`` store."""
    return "memory"


@pytest.fixture
async def app(
    settings: Settings, mail: FakeMail, blob_store_kind: str, tmp_path: Path
) -> AsyncIterator[FastAPI]:
    application = create_app(settings)
    if blob_store_kind == "memory":
        application.state.blob_store = MemoryBlobStore()
    elif blob_store_kind == "filesystem":
        application.state.blob_store = FilesystemBlobStore(tmp_path / "blobs")
    application.state.email_sender = mail
    application.state.google_verifier = FakeGoogle()
    async with application.state.engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    yield application
    await application.state.engine.dispose()


@pytest.fixture
def blob_store(app: FastAPI) -> BlobStore:
    store: BlobStore = app.state.blob_store
    return store


@pytest.fixture
async def client(app: FastAPI) -> AsyncIterator[httpx.AsyncClient]:
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as c:
        yield c


async def sign_in(
    client: httpx.AsyncClient, mail: FakeMail, email: str = EMAIL, device: str = "Test phone"
) -> dict[str, str]:
    start = await client.post("/v1/auth/email/start", json={"email": email})
    assert start.status_code == 202, start.text
    verify = await client.post(
        "/v1/auth/email/verify",
        json={
            "challenge_id": start.json()["challenge_id"],
            "code": mail.last_code(),
            "device_name": device,
        },
    )
    assert verify.status_code == 200, verify.text
    body: dict[str, str] = verify.json()
    return body


def bearer(tokens: dict[str, str]) -> dict[str, str]:
    return {"Authorization": f"Bearer {tokens['access_token']}"}

from collections.abc import AsyncIterator
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

# Obviously fake Kenyan numbers.
PHONE = "0700 000 000"
OTHER_PHONE = "0711 000 001"


@dataclass
class FakeSms:
    sent: list[tuple[str, str]] = field(default_factory=list)

    async def send(self, phone_e164: str, text: str) -> None:
        self.sent.append((phone_e164, text))

    def last_code(self) -> str:
        return next(
            word.rstrip(".") for word in self.sent[-1][1].split() if word.rstrip(".").isdigit()
        )


class FakeGoogle:
    async def verify(self, id_token: str) -> GoogleIdentity:
        if not id_token.startswith("valid:"):
            raise InvalidGoogleTokenError
        return GoogleIdentity(subject=id_token.removeprefix("valid:"))


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
    }
    values.update(overrides)
    return Settings(**values)  # type: ignore[arg-type]


@pytest.fixture
def settings(tmp_path: Path) -> Settings:
    return make_settings(tmp_path)


@pytest.fixture
def sms() -> FakeSms:
    return FakeSms()


@pytest.fixture
async def app(settings: Settings, sms: FakeSms) -> AsyncIterator[FastAPI]:
    application = create_app(settings)
    application.state.sms_sender = sms
    application.state.google_verifier = FakeGoogle()
    async with application.state.engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    yield application
    await application.state.engine.dispose()


@pytest.fixture
async def client(app: FastAPI) -> AsyncIterator[httpx.AsyncClient]:
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as c:
        yield c


async def sign_in(
    client: httpx.AsyncClient, sms: FakeSms, phone: str = PHONE, device: str = "Test phone"
) -> dict[str, str]:
    start = await client.post("/v1/auth/phone/start", json={"phone": phone})
    assert start.status_code == 202, start.text
    verify = await client.post(
        "/v1/auth/phone/verify",
        json={
            "challenge_id": start.json()["challenge_id"],
            "code": sms.last_code(),
            "device_name": device,
        },
    )
    assert verify.status_code == 200, verify.text
    body: dict[str, str] = verify.json()
    return body


def bearer(tokens: dict[str, str]) -> dict[str, str]:
    return {"Authorization": f"Bearer {tokens['access_token']}"}

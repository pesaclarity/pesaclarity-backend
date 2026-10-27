import uuid
from datetime import timedelta
from pathlib import Path

import httpx
import pytest
from pydantic import SecretStr, ValidationError

from ngome.core.config import Settings
from ngome.core.logging import REDACTED, redact_sensitive
from ngome.core.security import (
    InvalidTokenError,
    create_access_token,
    decode_access_token,
    utcnow,
)
from tests.conftest import FakeSms, bearer, make_settings, sign_in


async def test_health(client: httpx.AsyncClient) -> None:
    assert (await client.get("/health")).json() == {"status": "ok"}
    assert (await client.get("/health/ready")).json() == {"status": "ok"}


def test_redaction_drops_sensitive_fields() -> None:
    event = {"event": "x", "phone": "+254700000000", "code": "123456", "backup_id": "abc"}
    assert redact_sensitive(None, "info", event) == {
        "event": "x",
        "phone": REDACTED,
        "code": REDACTED,
        "backup_id": "abc",
    }


def test_access_token_round_trip_and_expiry(tmp_path: Path) -> None:
    settings = make_settings(tmp_path)
    account_id, device_id = uuid.uuid4(), uuid.uuid4()
    token = create_access_token(settings, account_id, device_id)
    claims = decode_access_token(settings, token)
    assert (claims.account_id, claims.device_id) == (account_id, device_id)

    stale = create_access_token(settings, account_id, device_id, now=utcnow() - timedelta(hours=1))
    with pytest.raises(InvalidTokenError):
        decode_access_token(settings, stale)

    other = make_settings(tmp_path, jwt_secret=SecretStr("another-secret-" + "z" * 32))
    with pytest.raises(InvalidTokenError):
        decode_access_token(other, token)


def test_settings_reject_weak_secrets(tmp_path: Path) -> None:
    with pytest.raises(ValidationError):
        make_settings(tmp_path, jwt_secret=SecretStr("short"))


def test_settings_refuse_console_sms_in_production(tmp_path: Path) -> None:
    with pytest.raises(ValidationError, match="console SMS provider"):
        make_settings(tmp_path, environment="production")


def test_settings_allow_disabled_sms_in_production(tmp_path: Path) -> None:
    settings = make_settings(tmp_path, environment="production", sms_provider="disabled")
    assert settings.sms_provider == "disabled"


@pytest.mark.parametrize(
    ("url", "expected"),
    [
        (
            "postgres://u:p@db.example:5432/d",
            "postgresql+asyncpg://u:p@db.example:5432/d?ssl=require",
        ),
        (
            "postgresql://u:p@db.example/d?sslmode=verify-full",
            "postgresql+asyncpg://u:p@db.example/d?ssl=verify-full",
        ),
        ("postgresql://u:p@localhost/d", "postgresql+asyncpg://u:p@localhost/d"),
        ("postgresql+asyncpg://u:p@localhost/d", "postgresql+asyncpg://u:p@localhost/d"),
    ],
)
def test_settings_convert_host_database_urls(tmp_path: Path, url: str, expected: str) -> None:
    assert make_settings(tmp_path, database_url=url).database_url == expected


def test_settings_read_heroku_database_url(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("NGOME_DATABASE_URL", raising=False)
    monkeypatch.setenv("DATABASE_URL", "postgres://u:p@db.example:5432/d")
    settings = Settings(
        jwt_secret=SecretStr("test-jwt-secret-" + "x" * 32),
        contact_pepper=SecretStr("test-contact-pepper-" + "y" * 32),
        _env_file=None,
    )
    assert settings.database_url == "postgresql+asyncpg://u:p@db.example:5432/d?ssl=require"

    monkeypatch.setenv("NGOME_DATABASE_URL", "postgresql+asyncpg://n:n@localhost/n")
    settings = Settings(
        jwt_secret=SecretStr("test-jwt-secret-" + "x" * 32),
        contact_pepper=SecretStr("test-contact-pepper-" + "y" * 32),
        _env_file=None,
    )
    assert settings.database_url == "postgresql+asyncpg://n:n@localhost/n"


async def test_logs_carry_no_contact_code_or_payload(
    capfd: pytest.CaptureFixture[str], client: httpx.AsyncClient, sms: FakeSms
) -> None:
    tokens = await sign_in(client, sms)
    payload = b"synthetic-ciphertext-marker-" + b"\x00" * 32
    await client.post(
        "/v1/vault/backups",
        content=payload,
        headers={**bearer(tokens), "Content-Type": "application/octet-stream"},
    )
    output = capfd.readouterr().out
    assert "vault.stored" in output
    assert "/v1/vault/backups" in output
    for secret in (
        "700000000",
        sms.last_code(),
        "synthetic-ciphertext-marker",
        tokens["refresh_token"],
    ):
        assert secret not in output

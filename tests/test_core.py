import uuid
from datetime import timedelta
from pathlib import Path

import httpx
import pytest
from pydantic import SecretStr, ValidationError

from ngome.api.app import create_app
from ngome.core.config import Settings
from ngome.core.logging import REDACTED, redact_sensitive
from ngome.core.security import (
    InvalidTokenError,
    create_access_token,
    decode_access_token,
    utcnow,
)
from tests.conftest import FakeMail, bearer, make_settings, sign_in


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


def test_settings_refuse_console_email_in_production(tmp_path: Path) -> None:
    with pytest.raises(ValidationError, match="console email provider"):
        make_settings(tmp_path, environment="production")


def test_settings_need_every_smtp_value(tmp_path: Path) -> None:
    with pytest.raises(ValidationError, match="email_from, smtp_port, smtp_timeout_seconds"):
        make_settings(tmp_path, email_provider="smtp", smtp_host="smtp.example.com")


@pytest.mark.parametrize("name", ["email_code_subject", "email_code_body"])
def test_api_needs_the_email_wording(tmp_path: Path, name: str) -> None:
    with pytest.raises(ValueError, match=f"{name} must be set"):
        create_app(make_settings(tmp_path, **{name: None}))


def test_settings_refuse_unknown_placeholders(tmp_path: Path) -> None:
    with pytest.raises(ValidationError, match="placeholders"):
        make_settings(tmp_path, email_code_subject="Hi {name}, your code is {code}")


async def test_sign_in_email_uses_the_configured_wording(
    client: httpx.AsyncClient, mail: FakeMail, settings: Settings
) -> None:
    await sign_in(client, mail)
    assert mail.sent[-1][1] == (
        f"Your test code is {mail.last_code()}. "
        f"It works for {settings.otp_ttl_seconds // 60} minutes."
    )


@pytest.mark.parametrize(
    ("url", "expected"),
    [
        (
            "postgresql://u:p@ep-x.eu-central-1.aws.neon.tech/d?sslmode=require&channel_binding=require",
            "postgresql+asyncpg://u:p@ep-x.eu-central-1.aws.neon.tech/d?ssl=require",
        ),
        ("postgres://u:p@localhost:5432/d", "postgresql+asyncpg://u:p@localhost:5432/d"),
        ("postgresql+asyncpg://u:p@localhost/d", "postgresql+asyncpg://u:p@localhost/d"),
    ],
)
def test_settings_convert_libpq_database_urls(tmp_path: Path, url: str, expected: str) -> None:
    assert make_settings(tmp_path, database_url=url).database_url == expected


async def test_logs_carry_no_contact_code_or_payload(
    capfd: pytest.CaptureFixture[str], client: httpx.AsyncClient, mail: FakeMail
) -> None:
    tokens = await sign_in(client, mail)
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
        "wanjiku",
        mail.last_code(),
        "synthetic-ciphertext-marker",
        tokens["refresh_token"],
    ):
        assert secret not in output

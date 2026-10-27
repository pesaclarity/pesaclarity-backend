import uuid
from datetime import timedelta
from pathlib import Path

import httpx
import pytest
from pydantic import SecretStr, ValidationError

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


def test_settings_need_a_host_and_sender_for_smtp(tmp_path: Path) -> None:
    with pytest.raises(ValidationError, match="smtp_host and email_from"):
        make_settings(tmp_path, email_provider="smtp", smtp_host="smtp.example.com")


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

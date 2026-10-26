"""Per-account storage quota for the backup vault."""

from pathlib import Path

import httpx
import pytest

from ngome.core.config import Settings
from tests.conftest import OTHER_PHONE, FakeSms, bearer, make_settings, sign_in
from tests.test_vault import OCTET, ciphertext


@pytest.fixture
def settings(tmp_path: Path) -> Settings:
    # Room for two 800-byte backups; the account keeps its newest three.
    return make_settings(tmp_path, vault_max_account_bytes=2000)


async def test_account_quota_counts_backups_that_survive_pruning(
    client: httpx.AsyncClient, sms: FakeSms
) -> None:
    auth = bearer(await sign_in(client, sms))
    for _ in range(2):
        ok = await client.post(
            "/v1/vault/backups", content=ciphertext(800), headers={**auth, **OCTET}
        )
        assert ok.status_code == 201, ok.text

    over = await client.post(
        "/v1/vault/backups", content=ciphertext(800), headers={**auth, **OCTET}
    )
    assert over.status_code == 413
    assert "quota" in over.json()["detail"]
    assert len((await client.get("/v1/vault/backups", headers=auth)).json()) == 2

    # The quota is per account.
    other = bearer(await sign_in(client, sms, OTHER_PHONE))
    elsewhere = await client.post(
        "/v1/vault/backups", content=ciphertext(800), headers={**other, **OCTET}
    )
    assert elsewhere.status_code == 201


async def test_quota_frees_up_when_backups_are_deleted(
    client: httpx.AsyncClient, sms: FakeSms
) -> None:
    auth = bearer(await sign_in(client, sms))
    first = await client.post(
        "/v1/vault/backups", content=ciphertext(1200), headers={**auth, **OCTET}
    )
    assert first.status_code == 201
    blocked = await client.post(
        "/v1/vault/backups", content=ciphertext(1200), headers={**auth, **OCTET}
    )
    assert blocked.status_code == 413

    deleted = await client.delete(f"/v1/vault/backups/{first.json()['id']}", headers=auth)
    assert deleted.status_code == 204
    retry = await client.post(
        "/v1/vault/backups", content=ciphertext(1200), headers={**auth, **OCTET}
    )
    assert retry.status_code == 201

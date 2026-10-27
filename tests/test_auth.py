from pathlib import Path

import httpx
from fastapi import FastAPI
from sqlalchemy import select

from ngome.api.app import create_app
from ngome.auth.models import Account, AuthEvent, AuthEventKind
from ngome.db.models import Base
from tests.conftest import OTHER_PHONE, PHONE, FakeSms, bearer, make_settings, sign_in


async def _events(app: FastAPI) -> list[AuthEventKind]:
    async with app.state.sessionmaker() as session:
        result = await session.scalars(select(AuthEvent.kind).order_by(AuthEvent.created_at))
        return list(result)


async def test_phone_sign_up_then_sign_in_reuses_account(
    app: FastAPI, client: httpx.AsyncClient, sms: FakeSms
) -> None:
    first = await sign_in(client, sms)
    second = await sign_in(client, sms, device="Second phone")

    assert first["account_id"] == second["account_id"]
    assert first["device_id"] != second["device_id"]
    assert sms.sent[0][0] == "+254700000000"
    assert await _events(app) == [AuthEventKind.SIGN_UP, AuthEventKind.SIGN_IN]


async def test_contact_is_stored_only_as_a_hash(
    app: FastAPI, client: httpx.AsyncClient, sms: FakeSms
) -> None:
    await sign_in(client, sms)
    async with app.state.sessionmaker() as session:
        account = await session.scalar(select(Account))
    assert account is not None
    assert "700000000" not in account.contact_hash
    assert len(account.contact_hash) == 64


async def test_invalid_phone_is_rejected(client: httpx.AsyncClient) -> None:
    response = await client.post("/v1/auth/phone/start", json={"phone": "0000 000"})
    assert response.status_code == 422


async def test_wrong_code_locks_challenge_after_max_attempts(
    client: httpx.AsyncClient, sms: FakeSms
) -> None:
    start = await client.post("/v1/auth/phone/start", json={"phone": PHONE})
    challenge_id = start.json()["challenge_id"]
    real = sms.last_code()
    wrong = "000000" if real != "000000" else "111111"

    for _ in range(5):
        response = await client.post(
            "/v1/auth/phone/verify",
            json={"challenge_id": challenge_id, "code": wrong, "device_name": "Test phone"},
        )
        assert response.status_code == 401

    locked = await client.post(
        "/v1/auth/phone/verify",
        json={"challenge_id": challenge_id, "code": real, "device_name": "Test phone"},
    )
    assert locked.status_code == 401


async def test_code_cannot_be_used_twice(client: httpx.AsyncClient, sms: FakeSms) -> None:
    start = await client.post("/v1/auth/phone/start", json={"phone": PHONE})
    body = {
        "challenge_id": start.json()["challenge_id"],
        "code": sms.last_code(),
        "device_name": "x",
    }
    assert (await client.post("/v1/auth/phone/verify", json=body)).status_code == 200
    assert (await client.post("/v1/auth/phone/verify", json=body)).status_code == 401


async def test_code_requests_are_rate_limited(client: httpx.AsyncClient) -> None:
    for _ in range(5):
        assert (await client.post("/v1/auth/phone/start", json={"phone": PHONE})).status_code == 202
    limited = await client.post("/v1/auth/phone/start", json={"phone": PHONE})
    assert limited.status_code == 429
    other = await client.post("/v1/auth/phone/start", json={"phone": OTHER_PHONE})
    assert other.status_code == 202


async def test_refresh_rotates_and_reuse_revokes_device(
    app: FastAPI, client: httpx.AsyncClient, sms: FakeSms
) -> None:
    tokens = await sign_in(client, sms)
    rotated = await client.post("/v1/auth/refresh", json={"refresh_token": tokens["refresh_token"]})
    assert rotated.status_code == 200
    new = rotated.json()
    assert new["refresh_token"] != tokens["refresh_token"]
    assert (await client.get("/v1/auth/devices", headers=bearer(new))).status_code == 200

    replay = await client.post("/v1/auth/refresh", json={"refresh_token": tokens["refresh_token"]})
    assert replay.status_code == 401
    assert (await client.get("/v1/auth/devices", headers=bearer(new))).status_code == 401
    after = await client.post("/v1/auth/refresh", json={"refresh_token": new["refresh_token"]})
    assert after.status_code == 401
    assert AuthEventKind.REFRESH_REUSE in await _events(app)


async def test_sign_out_ends_access(client: httpx.AsyncClient, sms: FakeSms) -> None:
    tokens = await sign_in(client, sms)
    assert (await client.post("/v1/auth/sign-out", headers=bearer(tokens))).status_code == 204
    assert (await client.get("/v1/auth/devices", headers=bearer(tokens))).status_code == 401
    refresh = await client.post("/v1/auth/refresh", json={"refresh_token": tokens["refresh_token"]})
    assert refresh.status_code == 401


async def test_remote_sign_out_of_another_device(client: httpx.AsyncClient, sms: FakeSms) -> None:
    phone_a = await sign_in(client, sms, device="Phone A")
    phone_b = await sign_in(client, sms, device="Phone B")

    listed = await client.get("/v1/auth/devices", headers=bearer(phone_a))
    assert [(d["name"], d["current"]) for d in listed.json()] == [
        ("Phone A", True),
        ("Phone B", False),
    ]

    revoked = await client.delete(
        f"/v1/auth/devices/{phone_b['device_id']}", headers=bearer(phone_a)
    )
    assert revoked.status_code == 204
    assert (await client.get("/v1/vault/backups", headers=bearer(phone_b))).status_code == 401
    listed = await client.get("/v1/auth/devices", headers=bearer(phone_a))
    assert [d["name"] for d in listed.json()] == ["Phone A"]


async def test_cannot_revoke_someone_elses_device(client: httpx.AsyncClient, sms: FakeSms) -> None:
    mine = await sign_in(client, sms)
    theirs = await sign_in(client, sms, phone=OTHER_PHONE)
    response = await client.delete(f"/v1/auth/devices/{theirs['device_id']}", headers=bearer(mine))
    assert response.status_code == 404


async def test_rejects_garbage_bearer_token(client: httpx.AsyncClient) -> None:
    response = await client.get("/v1/auth/devices", headers={"Authorization": "Bearer not-a-jwt"})
    assert response.status_code == 401


async def test_google_sign_in(client: httpx.AsyncClient) -> None:
    body = {"id_token": "valid:google-subject-1", "device_name": "Pixel"}
    first = await client.post("/v1/auth/google", json=body)
    second = await client.post("/v1/auth/google", json=body)
    assert first.status_code == 200
    assert first.json()["account_id"] == second.json()["account_id"]

    bad = await client.post("/v1/auth/google", json={"id_token": "forged", "device_name": "Pixel"})
    assert bad.status_code == 401


async def test_google_sign_in_can_be_disabled(app: FastAPI, client: httpx.AsyncClient) -> None:
    app.state.settings = app.state.settings.model_copy(update={"google_sign_in_enabled": False})
    response = await client.post(
        "/v1/auth/google", json={"id_token": "valid:google-subject-1", "device_name": "Pixel"}
    )
    assert response.status_code == 404


async def test_phone_sign_in_can_be_switched_off(tmp_path: Path) -> None:
    application = create_app(make_settings(tmp_path, sms_provider="disabled"))
    async with application.state.engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    transport = httpx.ASGITransport(app=application)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        response = await client.post("/v1/auth/phone/start", json={"phone": PHONE})
    await application.state.engine.dispose()
    assert response.status_code == 503

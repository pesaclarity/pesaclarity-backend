import httpx
from fastapi import FastAPI
from sqlalchemy import func, select

from ngome.db.models import Account, AuthEvent, Backup, Device, OtpChallenge, RefreshToken
from tests.conftest import OTHER_EMAIL, FakeMail, bearer, sign_in


async def test_get_account(client: httpx.AsyncClient, mail: FakeMail) -> None:
    tokens = await sign_in(client, mail)
    response = await client.get("/v1/account", headers=bearer(tokens))
    assert response.status_code == 200
    assert response.json()["id"] == tokens["account_id"]
    assert response.json()["contact_kind"] == "email"


async def test_delete_account_erases_everything(
    app: FastAPI, client: httpx.AsyncClient, mail: FakeMail
) -> None:
    tokens = await sign_in(client, mail)
    other = await sign_in(client, mail, email=OTHER_EMAIL)
    await client.post(
        "/v1/vault/backups",
        content=b"\x00" * 64,
        headers={**bearer(tokens), "Content-Type": "application/octet-stream"},
    )

    assert (await client.delete("/v1/account", headers=bearer(tokens))).status_code == 204
    assert (await client.get("/v1/account", headers=bearer(tokens))).status_code == 401
    refresh = await client.post("/v1/auth/refresh", json={"refresh_token": tokens["refresh_token"]})
    assert refresh.status_code == 401

    async with app.state.sessionmaker() as session:
        for model in (Account, Device, AuthEvent, OtpChallenge):
            count = await session.scalar(select(func.count()).select_from(model))
            assert count == 1, model.__name__
        assert await session.scalar(select(func.count()).select_from(Backup)) == 0
        assert await session.scalar(select(func.count()).select_from(RefreshToken)) == 1

    assert (await client.get("/v1/account", headers=bearer(other))).status_code == 200

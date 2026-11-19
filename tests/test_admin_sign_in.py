"""Admin sign-in (ADR 0025): the starter command, the first sign-in's forced steps, the
password and second factors, limits and lockouts, sessions, step-up, and what is never kept
or logged. Synthetic values only."""

import asyncio
import base64
import secrets
from collections.abc import AsyncIterator
from datetime import UTC, datetime, timedelta
from pathlib import Path

import httpx
import pytest
from cryptography.exceptions import InvalidTag
from fastapi import FastAPI
from sqlalchemy import delete, select, update
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from ngome.admin import accounts, passwords, throttle, totp
from ngome.admin.models import (
    AdminEmailCode,
    AdminEvent,
    AdminPasskey,
    AdminRecoveryCode,
    AdminSession,
    AdminThrottle,
    AdminUser,
)
from ngome.admin.web import COOKIE, DEVICE, PENDING
from ngome.auth.retention import purge_expired
from ngome.core.config import Settings
from ngome.db.migrate import upgrade_to_head
from ngome.db.session import create_engine, create_sessionmaker
from tests.admin_flow import (  # noqa: F401 - totp_clock is a fixture
    ADMIN,
    ORIGIN,
    OWNER_EMAIL,
    SAME,
    SECRET_KEY,
    Owner,
    admin_settings,
    first_sign_in,
    make_starter,
    post,
    sign_in,
    totp_clock,
)
from tests.conftest import FakeMail
from tests.soft_passkey import SoftPasskey
from tests.test_migrate import ALEMBIC_INI, POSTGRES_URL, postgres

WRONG = "username and password don\u2019t match"


@pytest.fixture
def settings(tmp_path: Path) -> Settings:
    return admin_settings(tmp_path)


@pytest.fixture
async def client(app: FastAPI) -> AsyncIterator[httpx.AsyncClient]:
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url=ORIGIN) as c:
        yield c


@pytest.fixture
def maker(app: FastAPI) -> async_sessionmaker[AsyncSession]:
    sessions: async_sessionmaker[AsyncSession] = app.state.sessionmaker
    return sessions


@pytest.fixture
async def owner(client: httpx.AsyncClient, mail: FakeMail) -> Owner:
    return await first_sign_in(client, mail)


async def fresh_client(app: FastAPI) -> httpx.AsyncClient:
    return httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url=ORIGIN)


# Building blocks.


@pytest.mark.parametrize(
    ("at", "code"),
    [
        (59, "287082"),
        (1111111109, "081804"),
        (1111111111, "050471"),
        (1234567890, "005924"),
        (2000000000, "279037"),
    ],
)
def test_totp_matches_rfc_6238(at: int, code: str) -> None:
    secret = b"12345678901234567890"
    assert totp.code_at(secret, at // 30) == code
    now = datetime.fromtimestamp(at, UTC)
    step = at // 30
    assert totp.matching_step(secret, code, now=now, after=0) == step
    # Each code works once: not for its own step or any before it again.
    assert totp.matching_step(secret, code, now=now, after=step) is None
    assert totp.matching_step(secret, "000000x", now=now, after=0) is None


def test_totp_secret_is_sealed_to_its_user() -> None:
    key = b"k" * 32
    sealed, nonce = totp.seal(key, b"s" * 20, b"user-1")
    assert b"s" * 20 not in sealed
    assert totp.unseal(key, sealed, nonce, b"user-1") == b"s" * 20
    with pytest.raises(InvalidTag):
        totp.unseal(key, sealed, nonce, b"user-2")


def test_password_rules() -> None:
    def why(p: str) -> str | None:
        return passwords.problem(p, username="owner", host="admin.test")

    assert why("short one") is not None
    assert why("x" * 129) is not None
    assert why("my owner password is long") is not None
    assert why("pesaclarity is my password") is not None
    assert why("passwordpassword") is not None  # common, twice
    assert why("aaaaaaaaaaaaaaaaaaaa") is not None
    assert why("1qaz2wsx3edc4rfv") is not None  # on the list
    assert why("plum orchard kettle drum seven") is None
    assert len(passwords.common_passwords()) > 40_000


async def test_argon2id_at_owasp_settings() -> None:
    hashed = await passwords.hash_password("plum orchard kettle drum seven")
    assert hashed.startswith("$argon2id$v=19$m=47104,t=1,p=1$")
    assert await passwords.verify_password(hashed, "plum orchard kettle drum seven")
    assert not await passwords.verify_password(hashed, "plum orchard kettle drum eight")
    assert not await passwords.verify_password(None, "anything at all, long enough")


# The starter command.


async def test_starter_user_needs_the_token_and_no_well_known_name(
    client: httpx.AsyncClient, maker: async_sessionmaker[AsyncSession]
) -> None:
    body = {"username": "owner"}
    assert (await client.post("/v1/admin/starter-user", json=body)).status_code == 401
    for name in ("admin", "root", "x", "Has Space"):
        made = await client.post("/v1/admin/starter-user", json={"username": name}, headers=ADMIN)
        assert made.status_code == 422, name
    first = await make_starter(client)
    assert len(first) == 24
    # Again while only a temporary password exists: a new one, and the old one stops working.
    second = await make_starter(client)
    assert second != first
    async with maker() as session:
        user = (await session.scalars(select(AdminUser))).one()
    assert user.password_temporary
    assert first not in user.password_hash
    assert second not in user.password_hash
    assert not await passwords.verify_password(user.password_hash, first)
    assert await passwords.verify_password(user.password_hash, second)
    assert user.temporary_until is not None
    assert user.temporary_until - datetime.now(UTC) <= timedelta(hours=24)


async def test_starter_user_refuses_once_a_password_is_set_unless_reset(
    app: FastAPI,
    client: httpx.AsyncClient,
    mail: FakeMail,
    owner: Owner,
    maker: async_sessionmaker[AsyncSession],
) -> None:
    refused = await client.post("/v1/admin/starter-user", json={"username": "owner"}, headers=ADMIN)
    assert refused.status_code == 409
    assert (await client.get("/admin")).status_code == 200
    async with maker() as session:
        session.add(AdminPasskey(credential_id=b"c" * 16, public_key=b"k", label="Kept"))
        await session.commit()
    sent = len(mail.sent)
    temporary = await make_starter(client, reset=True)
    # Every session ends, the authenticator and recovery codes go, passkeys stay, the owner
    # is emailed, and the first sign-in starts again.
    assert (await client.get("/admin")).status_code == 303
    assert any("starter command" in text for _, text in mail.sent[sent:])
    async with maker() as session:
        user = (await session.scalars(select(AdminUser))).one()
        assert user.totp_secret is None
        assert list(await session.scalars(select(AdminRecoveryCode))) == []
        assert len(list(await session.scalars(select(AdminPasskey)))) == 1
    old = await post(client, "/admin/sign-in", username="owner", password=owner.password)
    assert old.status_code == 401
    response = await post(client, "/admin/sign-in", username="owner", password=temporary)
    assert response.headers["location"] == "/admin/first/email"


async def test_the_token_only_passkey_enrolment_is_gone(client: httpx.AsyncClient) -> None:
    response = await client.post("/v1/admin/passkey-enrolments", json={"label": "x"}, headers=ADMIN)
    assert response.status_code in (404, 405)


# The first sign-in.


async def test_first_sign_in_forces_every_step(  # noqa: PLR0915 - one story, end to end
    app: FastAPI,
    client: httpx.AsyncClient,
    mail: FakeMail,
    maker: async_sessionmaker[AsyncSession],
) -> None:
    page = await client.get("/admin/sign-in")
    assert "Not set up yet" in page.text
    temporary = await make_starter(client)
    page = await client.get("/admin/sign-in")
    assert "First sign-in" in page.text
    assert "Temporary password" in page.text
    response = await post(client, "/admin/sign-in", username="owner", password=temporary)
    assert response.headers["location"] == "/admin/first/email"
    pending = response.headers["set-cookie"]
    assert pending.startswith(f"{PENDING}=")
    # Nothing opens on the strength of the temporary password alone.
    for path in ("/admin", "/admin/installs.csv", "/admin/security", "/admin/first/password"):
        assert (await client.get(path)).headers["location"] == "/admin/sign-in", path
    assert mail.sent[-1][0] == OWNER_EMAIL
    response = await post(client, "/admin/first/email", code=mail.last_code())
    assert response.headers["location"] == "/admin/first/password"
    staged = next(c for c in response.headers.get_list("set-cookie") if c.startswith(COOKIE))
    assert "max-age=1800" in staged.lower()

    # The temporary password is used up as soon as the email check passes.
    async with await fresh_client(app) as other:
        again = await post(other, "/admin/sign-in", username="owner", password=temporary)
        assert again.status_code == 401

    # Until the password is changed, every page, CSV and later step sends it back there.
    for path in (
        "/admin",
        "/admin/crashes",
        "/admin/monthly.csv",
        "/admin/security",
        "/admin/confirm",
        "/admin/first/authenticator",
        "/admin/first/recovery-codes",
    ):
        response = await client.get(path)
        assert response.status_code == 303, path
        assert response.headers["location"] == "/admin/first/password", path
    blocked = await post(client, "/admin/security/recovery-codes")
    assert blocked.headers["location"] == "/admin/first/password"
    weak = await post(client, "/admin/first/password", new_password="short", confirm="short")
    assert weak.status_code == 400
    assert "at least 15" in weak.text
    mismatch = await post(
        client,
        "/admin/first/password",
        new_password="plum orchard kettle drum seven",
        confirm="other",
    )
    assert "passwords don\u2019t match" in mismatch.text
    response = await post(
        client,
        "/admin/first/password",
        new_password="plum orchard kettle drum seven",
        confirm="plum orchard kettle drum seven",
    )
    assert response.headers["location"] == "/admin/first/authenticator"
    for path in ("/admin", "/admin/first/password", "/admin/first/recovery-codes"):
        assert (await client.get(path)).headers["location"] == "/admin/first/authenticator"

    setup = (await client.get("/admin/first/authenticator")).text
    assert "<svg" in setup
    assert 'class="qr"' in setup
    assert "data-key>" in setup
    # A reload shows the same key until it is confirmed.
    assert (
        setup.split("data-key>")[1][:40]
        == (await client.get("/admin/first/authenticator")).text.split("data-key>")[1][:40]
    )
    from tests.admin_flow import codes_from, key_from  # noqa: PLC0415

    owner = Owner(secret=key_from(setup))
    bad = await post(client, "/admin/first/authenticator", code="000000")
    assert bad.status_code == 400
    response = await post(client, "/admin/first/authenticator", code=owner.code())
    assert response.headers["location"] == "/admin/first/recovery-codes"
    assert (await client.get("/admin")).headers["location"] == "/admin/first/recovery-codes"
    codes = codes_from((await client.get("/admin/first/recovery-codes")).text)
    assert len(codes) == 10
    assert len(set(codes)) == 10
    # Without the tick, the dashboard stays shut.
    assert (await post(client, "/admin/first/recovery-codes")).headers["location"] == (
        "/admin/first/recovery-codes"
    )
    response = await post(client, "/admin/first/recovery-codes", saved="yes")
    assert response.headers["location"] == "/admin"
    cookies = response.headers.get_list("set-cookie")
    session_cookie = next(c for c in cookies if c.startswith(f"{COOKIE}="))
    device_cookie = next(c for c in cookies if c.startswith(f"{DEVICE}="))
    for cookie in (session_cookie, device_cookie):
        for flag in ("httponly", "secure", "samesite=strict", "path=/"):
            assert flag in cookie.lower()
        assert "domain" not in cookie.lower()
    assert (await client.get("/admin")).status_code == 200
    async with maker() as session:
        rows = list(await session.scalars(select(AdminRecoveryCode)))
    assert len(rows) == 10
    assert not {r.code_hash for r in rows} & set(codes)


# Later sign-ins.


async def test_sign_in_with_password_then_authenticator(
    client: httpx.AsyncClient, owner: Owner
) -> None:
    out = await post(client, "/admin/sign-out")
    assert out.headers["location"] == "/admin/sign-in"
    assert (await client.get("/admin")).status_code == 303
    page = await client.get("/admin/sign-in")
    assert "then the code from your authenticator app" in page.text
    response = await sign_in(client, owner)
    assert response.headers["location"] == "/admin"
    cookie = next(c for c in response.headers.get_list("set-cookie") if c.startswith(COOKIE))
    assert "max-age=28800" in cookie.lower()  # 8 hours
    overview = await client.get("/admin")
    assert overview.status_code == 200
    assert "Signed in with an authenticator" in overview.text


async def test_wrong_username_or_password_get_the_same_answer(
    client: httpx.AsyncClient, owner: Owner
) -> None:
    client.cookies.clear()
    wrong_password = await post(client, "/admin/sign-in", username="owner", password="nope")
    wrong_name = await post(client, "/admin/sign-in", username="nobody", password=owner.password)
    assert wrong_password.status_code == wrong_name.status_code == 401
    assert WRONG in wrong_password.text
    assert WRONG in wrong_name.text
    assert PENDING not in wrong_password.headers.get("set-cookie", "")


async def test_each_authenticator_code_works_once(
    app: FastAPI, client: httpx.AsyncClient, owner: Owner
) -> None:
    client.cookies.clear()
    code = owner.code()
    await post(client, "/admin/sign-in", username="owner", password=owner.password)
    assert (await post(client, "/admin/sign-in/code", code=code)).headers["location"] == "/admin"
    async with await fresh_client(app) as other:
        await post(other, "/admin/sign-in", username="owner", password=owner.password)
        replay = await post(other, "/admin/sign-in/code", code=code)
        assert replay.status_code == 401
        assert "code didn\u2019t work" in replay.text
        # The next step's code is new, so it works.
        ok = await post(other, "/admin/sign-in/code", code=owner.code())
        assert ok.headers["location"] == "/admin"


async def test_recovery_codes_work_once(
    app: FastAPI,
    client: httpx.AsyncClient,
    mail: FakeMail,
    owner: Owner,
    maker: async_sessionmaker[AsyncSession],
) -> None:
    code = owner.codes[3]
    client.cookies.clear()
    await post(client, "/admin/sign-in", username="owner", password=owner.password)
    sent = len(mail.sent)
    # Typed loosely: lower case, no hyphen.
    used = await post(client, "/admin/sign-in/recovery", code=code.lower().replace("-", " "))
    assert used.headers["location"] == "/admin"
    assert any("recovery code was used" in text for _, text in mail.sent[sent:])
    client.cookies.clear()
    await post(client, "/admin/sign-in", username="owner", password=owner.password)
    again = await post(client, "/admin/sign-in/recovery", code=code)
    assert again.status_code == 401
    async with maker() as session:
        left = await session.scalars(
            select(AdminRecoveryCode).where(AdminRecoveryCode.used_at.is_(None))
        )
        assert len(list(left)) == 9


async def test_email_code_is_a_fallback_that_cannot_change_sign_in(
    client: httpx.AsyncClient, mail: FakeMail, owner: Owner
) -> None:
    client.cookies.clear()
    await post(client, "/admin/sign-in", username="owner", password=owner.password)
    another = await client.get("/admin/sign-in/another")
    assert "Email a code" in another.text
    assert "o•••@e•••.org" in another.text
    sent = len(mail.sent)
    response = await post(client, "/admin/sign-in/email/send")
    assert response.headers["location"] == "/admin/sign-in/email"
    assert len(mail.sent) == sent + 1
    to, text = mail.sent[-1]
    assert to == OWNER_EMAIL
    assert "admin.test" in text
    assert "http" not in text  # never a link
    # One a minute.
    await post(client, "/admin/sign-in/email/send")
    assert len(mail.sent) == sent + 1
    assert "Send a new code in" in (await client.get("/admin/sign-in/email")).text
    response = await post(client, "/admin/sign-in/email", code=mail.last_code())
    assert response.headers["location"] == "/admin"
    # It opens reading and CSVs ...
    assert (await client.get("/admin/monthly.csv")).status_code == 200
    # ... but not sign-in changes: those need the authenticator or a passkey.
    change = await post(client, "/admin/security/recovery-codes")
    assert change.status_code == 303
    assert change.headers["location"].startswith("/admin/confirm?")
    assert "for=settings" in change.headers["location"]
    sneaky = await post(client, "/admin/confirm/email", code="123456", next="/admin/security")
    assert sneaky.headers["location"] == "/admin/security"
    ok = await post(client, "/admin/confirm", code=owner.code(), next="/admin/security")
    assert ok.headers["location"] == "/admin/security"
    made = await post(client, "/admin/security/recovery-codes")
    assert made.status_code == 200
    assert "Save your recovery codes" in made.text


async def test_step_up_before_csv_and_sign_in_changes(
    client: httpx.AsyncClient, owner: Owner, maker: async_sessionmaker[AsyncSession]
) -> None:
    assert (await client.get("/admin/installs.csv")).status_code == 200
    async with maker() as session:
        await session.execute(
            update(AdminSession).values(reauth_until=datetime.now(UTC) - timedelta(seconds=1))
        )
        await session.commit()
    csv = await client.get("/admin/installs.csv", params={"dim": "build"})
    assert csv.status_code == 303
    location = csv.headers["location"]
    assert location.startswith("/admin/confirm?next=%2Fadmin%2Finstalls.csv")
    page = await client.get(location)
    assert "installs.csv" in page.text
    assert "Email me a code" in page.text
    bad = await post(client, "/admin/confirm", code="000000", next="/admin/installs.csv?dim=build")
    assert bad.status_code == 401
    good = await post(
        client, "/admin/confirm", code=owner.code(), next="/admin/installs.csv?dim=build"
    )
    assert good.headers["location"] == "/admin/installs.csv?dim=build"
    assert (await client.get("/admin/installs.csv", params={"dim": "build"})).status_code == 200
    # Never sent off the dashboard.
    away = await post(client, "/admin/confirm", code=owner.code(), next="https://evil.example/")
    assert away.headers["location"] == "/admin"


async def test_sessions_end_when_idle_or_old(
    client: httpx.AsyncClient, owner: Owner, maker: async_sessionmaker[AsyncSession]
) -> None:
    assert (await client.get("/admin")).status_code == 200
    async with maker() as session:
        await session.execute(
            update(AdminSession).values(last_seen_at=datetime.now(UTC) - timedelta(minutes=31))
        )
        await session.commit()
    assert (await client.get("/admin")).headers["location"] == "/admin/sign-in"
    await sign_in(client, owner)
    assert (await client.get("/admin")).status_code == 200
    async with maker() as session:
        await session.execute(
            update(AdminSession).values(expires_at=datetime.now(UTC) - timedelta(seconds=1))
        )
        await session.commit()
    assert (await client.get("/admin")).headers["location"] == "/admin/sign-in"


# Limits.


async def test_password_lockout_backs_off_and_spares_known_browsers(
    app: FastAPI,
    client: httpx.AsyncClient,
    mail: FakeMail,
    owner: Owner,
    maker: async_sessionmaker[AsyncSession],
) -> None:
    sent = len(mail.sent)
    async with await fresh_client(app) as stranger:
        for _ in range(4):
            response = await post(stranger, "/admin/sign-in", username="owner", password="x")
            assert response.status_code == 401
        paused = await post(stranger, "/admin/sign-in", username="owner", password="x")
        assert paused.status_code == 429
        assert "Sign-in is paused" in paused.text
        # Paused means paused, even with the right password, and says nothing about it.
        right = await post(stranger, "/admin/sign-in", username="owner", password=owner.password)
        assert right.status_code == 429
    assert any("paused" in text for _, text in mail.sent[sent:])
    # The owner's own browser (it has the device cookie) has its own count.
    client.cookies.delete(COOKIE)
    response = await sign_in(client, owner)
    assert response.headers["location"] == "/admin"
    # The next pause is twice as long.
    async with maker() as session:
        await session.execute(
            update(AdminThrottle).values(locked_until=datetime.now(UTC) - timedelta(seconds=1))
        )
        await session.commit()
    async with await fresh_client(app) as stranger:
        for _ in range(5):
            last = await post(stranger, "/admin/sign-in", username="owner", password="x")
        assert last.status_code == 429
    async with maker() as session:
        longest = max(
            r.locked_until for r in await session.scalars(select(AdminThrottle)) if r.locked_until
        )
    assert longest - datetime.now(UTC) > timedelta(minutes=29)


async def test_address_limit_uses_the_entry_google_appends(
    app: FastAPI, client: httpx.AsyncClient, owner: Owner
) -> None:
    async with await fresh_client(app) as stranger:
        for n in range(20):
            # Made-up entries to the left change every time; the appended one does not.
            headers = {**SAME, "X-Forwarded-For": f"203.0.113.{n}, 198.51.100.4"}
            last = await stranger.post(
                "/admin/sign-in", headers=headers, data={"username": f"guess{n}", "password": "x"}
            )
        assert last.status_code == 429
        elsewhere = {**SAME, "X-Forwarded-For": "203.0.113.1, 198.51.100.5"}
        response = await stranger.post(
            "/admin/sign-in", headers=elsewhere, data={"username": "guess99", "password": "x"}
        )
        assert response.status_code == 401
    seen = await client.get(
        "/v1/admin/client-address", headers={**ADMIN, "X-Forwarded-For": "6.6.6.6, 198.51.100.7"}
    )
    assert seen.json() == {"address": "198.51.100.7"}


async def test_wrong_codes_end_the_sign_in_then_pause_the_second_step(
    app: FastAPI, client: httpx.AsyncClient, mail: FakeMail, owner: Owner
) -> None:
    client.cookies.clear()
    sent = len(mail.sent)
    await post(client, "/admin/sign-in", username="owner", password=owner.password)
    for _ in range(4):
        assert (await post(client, "/admin/sign-in/code", code="000000")).status_code == 401
    ended = await post(client, "/admin/sign-in/code", code="000000")
    assert "Sign in again from the start" in ended.text
    assert (await client.get("/admin/sign-in/code")).headers["location"] == "/admin/sign-in"
    # Right password, wrong codes: the owner hears about it.
    assert any("wrong second-step codes" in text for _, text in mail.sent[sent:])
    await post(client, "/admin/sign-in", username="owner", password=owner.password)
    for _ in range(4):
        await post(client, "/admin/sign-in/code", code="000000")
    paused = await post(client, "/admin/sign-in/code", code="000000")
    assert paused.status_code == 429
    await post(client, "/admin/sign-in", username="owner", password=owner.password)
    assert (await post(client, "/admin/sign-in/code", code=owner.code())).status_code == 429


async def test_email_codes_are_limited(
    client: httpx.AsyncClient,
    mail: FakeMail,
    owner: Owner,
    maker: async_sessionmaker[AsyncSession],
) -> None:
    for _ in range(4):
        client.cookies.delete(PENDING)
        await post(client, "/admin/sign-in", username="owner", password=owner.password)
        await post(client, "/admin/sign-in/email/send")
        async with maker() as session:
            # Pretend a minute passed, so only the hourly limit is left to stop it.
            for row in await session.scalars(select(AdminEmailCode)):
                row.created_at -= timedelta(minutes=2)
            await session.commit()
    async with maker() as session:
        count = len(list(await session.scalars(select(AdminEmailCode))))
    # The first sign-in's code plus four.
    assert count == 5
    before = len(mail.sent)
    client.cookies.delete(PENDING)
    await post(client, "/admin/sign-in", username="owner", password=owner.password)
    await post(client, "/admin/sign-in/email/send")
    assert len(mail.sent) == before  # five an hour


async def test_the_admin_token_is_limited_by_address(client: httpx.AsyncClient) -> None:
    wrong = {"Authorization": "Bearer " + "w" * 48}
    for _ in range(20):
        response = await client.get("/v1/admin/passkeys", headers=wrong)
        assert response.status_code == 401
    assert (await client.get("/v1/admin/passkeys", headers=wrong)).status_code == 429
    assert (await client.get("/v1/admin/passkeys", headers=ADMIN)).status_code == 429


async def test_forms_check_where_they_come_from(client: httpx.AsyncClient) -> None:
    await make_starter(client)
    data = {"username": "owner", "password": "x"}
    assert (await client.post("/admin/sign-in", data=data)).status_code == 403
    evil = {"Origin": "https://evil.example"}
    assert (await client.post("/admin/sign-in", data=data, headers=evil)).status_code == 403
    # A form from a no-referrer page sends Origin: null; the browser vouches for it.
    null_same = {"Origin": "null", "Sec-Fetch-Site": "same-origin"}
    assert (await client.post("/admin/sign-in", data=data, headers=null_same)).status_code == 401
    null_cross = {"Origin": "null", "Sec-Fetch-Site": "cross-site"}
    assert (await client.post("/admin/sign-in", data=data, headers=null_cross)).status_code == 403


# Passkeys as a second factor.


async def test_passkeys_are_added_from_security_and_used_after_the_password(
    client: httpx.AsyncClient, owner: Owner
) -> None:
    passkey = SoftPasskey("admin.test", ORIGIN)
    start = await client.post("/admin/security/passkeys/options", headers=SAME)
    assert start.status_code == 200
    body = start.json()
    added = await client.post(
        "/admin/security/passkeys/verify",
        json={
            "challenge_id": body["challenge_id"],
            "credential": passkey.register(body["options"]),
            "label": "Pixel phone",
        },
        headers=SAME,
    )
    assert added.status_code == 200, added.text
    assert "Pixel phone" in (await client.get("/admin/security")).text
    listed = await client.get("/v1/admin/passkeys", headers=ADMIN)
    assert [p["label"] for p in listed.json()] == ["Pixel phone"]

    client.cookies.delete(COOKIE)
    # Without the password first, no ceremony opens.
    assert (await client.post("/admin/sign-in/passkey/options", headers=SAME)).status_code == 400
    await post(client, "/admin/sign-in", username="owner", password=owner.password)
    assert "Passkey" in (await client.get("/admin/sign-in/another")).text
    start = (await client.post("/admin/sign-in/passkey/options", headers=SAME)).json()
    assert start["options"]["allowCredentials"]
    done = await client.post(
        "/admin/sign-in/passkey/verify",
        json={
            "challenge_id": start["challenge_id"],
            "credential": passkey.sign_in(start["options"]),
        },
        headers=SAME,
    )
    assert done.status_code == 200, done.text
    assert (await client.get("/admin")).status_code == 200
    # A passkey from another site does not verify.
    client.cookies.delete(COOKIE)
    await post(client, "/admin/sign-in", username="owner", password=owner.password)
    start = (await client.post("/admin/sign-in/passkey/options", headers=SAME)).json()
    bad = await client.post(
        "/admin/sign-in/passkey/verify",
        json={
            "challenge_id": start["challenge_id"],
            "credential": passkey.sign_in(start["options"], origin="https://evil.example"),
        },
        headers=SAME,
    )
    assert bad.status_code == 400


async def test_security_page_and_changes(
    client: httpx.AsyncClient, mail: FakeMail, owner: Owner
) -> None:
    page = await client.get("/admin/security")
    assert page.status_code == 200
    for text in (
        "Recovery codes",
        "10<small>of 10 left",
        "Authenticator app",
        "Signed-in browsers",
        "Recent activity",
        "This one",
        "o•••@e•••.org",
    ):
        assert text in page.text, text
    assert " style=" not in page.text
    assert "<style" not in page.text
    sent = len(mail.sent)
    wrong_current = await post(
        client,
        "/admin/security/password",
        current="nope",
        new_password="a new long passphrase here",
        confirm="a new long passphrase here",
    )
    assert wrong_current.status_code == 400
    changed = await post(
        client,
        "/admin/security/password",
        current=owner.password,
        new_password="a new long passphrase here",
        confirm="a new long passphrase here",
    )
    assert changed.headers["location"] == "/admin/security?done=password"
    assert any("sign-in setting" in text for _, text in mail.sent[sent:])
    owner.password = "a new long passphrase here"
    client.cookies.delete(COOKIE)
    assert (await sign_in(client, owner)).headers["location"] == "/admin"


# What is never kept or logged.


async def test_no_secret_or_code_in_logs_or_the_audit_log(
    app: FastAPI,
    client: httpx.AsyncClient,
    mail: FakeMail,
    maker: async_sessionmaker[AsyncSession],
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    temporary_seen: list[str] = []
    original = make_starter

    async def spy(c: httpx.AsyncClient, username: str = "owner", *, reset: bool = False) -> str:
        value = await original(c, username, reset=reset)
        temporary_seen.append(value)
        return value

    import tests.admin_flow as flow  # noqa: PLC0415

    monkeypatch.setattr(flow, "make_starter", spy)
    owner = await first_sign_in(client, mail)
    client.cookies.delete(COOKIE)
    await post(client, "/admin/sign-in", username="owner", password="wrong guess")
    await post(client, "/admin/sign-in", username="typo-of-a-password", password="x")
    await sign_in(client, owner)
    secrets_ = [
        owner.password,
        *temporary_seen,
        *owner.codes,
        totp.key_text(owner.secret),
        SECRET_KEY,
        "wrong guess",
        "typo-of-a-password",
    ]
    emailed = [
        word
        for _, text in mail.sent
        for word in text.split()
        if word.rstrip(".").isdigit() and len(word.rstrip(".")) == 6
    ]
    out = capsys.readouterr()
    logs = out.out + out.err
    for value in [*secrets_, *emailed]:
        assert value not in logs, value
    async with maker() as session:
        events = list(await session.scalars(select(AdminEvent)))
        users = list(await session.scalars(select(AdminUser)))
    assert events
    dump = " ".join(
        f"{e.kind} {e.factor} {e.address_hash} {e.country} {e.browser} {e.note}" for e in events
    )
    for value in [*secrets_, *emailed, "127.0.0.1"]:
        assert value not in dump, value
    assert owner.secret not in (users[0].totp_secret or b"")
    assert owner.password not in users[0].password_hash


async def test_purge_drops_old_audit_entries(
    client: httpx.AsyncClient,
    owner: Owner,
    maker: async_sessionmaker[AsyncSession],
    settings: Settings,
) -> None:
    async with maker() as session:
        await session.execute(update(AdminEvent).values(at=datetime.now(UTC) - timedelta(days=91)))
        await session.commit()
        await purge_expired(session, settings)
        assert list(await session.scalars(select(AdminEvent))) == []


# Several Cloud Run instances at once (Postgres only).


@pytest.mark.postgres
@postgres
async def test_limits_and_codes_hold_across_instances(tmp_path: Path) -> None:
    assert POSTGRES_URL is not None
    engine = create_engine(POSTGRES_URL)
    try:
        await upgrade_to_head(engine, ALEMBIC_INI)
        maker = create_sessionmaker(engine)
        settings = admin_settings(tmp_path, database_url=POSTGRES_URL)
        name = throttle.bucket(settings, "race", secrets.token_hex(8))
        rule = throttle.Rule(5, timedelta(hours=1), timedelta(minutes=15))
        now = datetime.now(UTC)

        async def fail_once() -> datetime | None:
            async with maker() as session:
                until = await throttle.fail(session, name, rule, now)
                await session.commit()
                return until

        # Five failures at the same moment, as from five instances: none is lost.
        results = await asyncio.gather(*(fail_once() for _ in range(5)))
        assert sum(r is not None for r in results) == 1

        secret = totp.new_secret()
        key = base64.b64decode(SECRET_KEY)
        async with maker() as session:
            await session.execute(delete(AdminUser))
            user = AdminUser(username="race", password_hash="x", password_temporary=False)
            session.add(user)
            await session.flush()
            user.totp_secret, user.totp_nonce = totp.seal(key, secret, user.id.bytes)
            await session.commit()
            user_id = user.id
        code = totp.code_at(secret, totp.step_at(datetime.now(UTC)))

        async def use_code() -> bool:
            async with maker() as session:
                row = await session.get(AdminUser, user_id)
                assert row is not None
                ok = await accounts._check_totp(session, settings, row, code)
                await session.commit()
                return ok

        # The same code sent twice at once works once.
        assert sorted(await asyncio.gather(use_code(), use_code())) == [False, True]
        async with maker() as session:
            await session.execute(delete(AdminUser))
            await session.commit()
    finally:
        await engine.dispose()


async def test_deployed_before_the_key_is_set_refuses_sign_in_and_says_why(
    app: FastAPI, tmp_path: Path, maker: async_sessionmaker[AsyncSession]
) -> None:
    app.state.settings = admin_settings(tmp_path, admin_email=None, admin_secret_key=None)
    async with maker() as session:
        session.add(AdminPasskey(credential_id=b"kept", public_key=b"k", label="Phone"))
        await session.commit()
    async with await fresh_client(app) as c:
        assert (await c.get("/health")).status_code == 200
        page = await c.get("/admin/sign-in")
        assert page.status_code == 503
        assert "NGOME_ADMIN_SECRET_KEY" in page.text
        refused = await c.post(
            "/admin/sign-in", data={"username": "a", "password": "b"}, headers=SAME
        )
        assert refused.status_code == 503
        made = await c.post("/v1/admin/starter-user", json={"username": "owner"}, headers=ADMIN)
        assert made.status_code == 503
        assert (await c.get("/admin")).headers["location"] == "/admin/sign-in"
    async with maker() as session:
        assert len(list(await session.scalars(select(AdminPasskey)))) == 1


async def test_a_second_origin_signs_in_and_has_its_own_passkeys(
    app: FastAPI, settings: Settings, client: httpx.AsyncClient, mail: FakeMail
) -> None:
    other_origin = "https://other.test"
    app.state.settings = settings.model_copy(update={"admin_extra_origins": [other_origin]})
    owner = await first_sign_in(client, mail)
    transport = httpx.ASGITransport(app=app)
    here = {"Origin": other_origin}
    async with httpx.AsyncClient(transport=transport, base_url=other_origin) as other:
        # The password and the authenticator work on every origin.
        await other.post(
            "/admin/sign-in", headers=here, data={"username": "owner", "password": owner.password}
        )
        done = await other.post("/admin/sign-in/code", headers=here, data={"code": owner.code()})
        assert done.headers["location"] == "/admin"
        # A passkey added here is bound to this host.
        start = await other.post("/admin/security/passkeys/options", headers=here)
        assert start.json()["options"]["rp"]["id"] == "other.test"
        passkey = SoftPasskey("other.test", other_origin)
        added = await other.post(
            "/admin/security/passkeys/verify",
            json={
                "challenge_id": start.json()["challenge_id"],
                "credential": passkey.register(start.json()["options"]),
                "label": "Mac",
            },
            headers=here,
        )
        assert added.status_code == 200, added.text
    # ... so it does not work on the main origin.
    client.cookies.delete(COOKIE)
    await post(client, "/admin/sign-in", username="owner", password=owner.password)
    start = (await client.post("/admin/sign-in/passkey/options", headers=SAME)).json()
    assert start["options"]["rpId"] == "admin.test"
    refused = await client.post(
        "/admin/sign-in/passkey/verify",
        json={
            "challenge_id": start["challenge_id"],
            "credential": passkey.sign_in(start["options"], origin=ORIGIN),
        },
        headers=SAME,
    )
    assert refused.status_code == 400
    # Origins not on the list are refused.
    evil = {"Origin": "https://evil.example"}
    assert (await client.post("/admin/sign-in/passkey/options", headers=evil)).status_code == 403

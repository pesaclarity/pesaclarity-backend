"""Driving the admin sign-in in tests (ADR 0025): the starter command, the first sign-in's
forced steps, and later sign-ins. Synthetic values only."""

import re
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path

import httpx
import pytest
from pydantic import SecretStr

from ngome.admin import totp
from ngome.core.config import Settings
from tests.conftest import FakeMail, make_settings
from tests.test_app_status import TEST_SEED

ORIGIN = "https://admin.test"
ADMIN_TOKEN = "test-admin-token-" + "z" * 32
ADMIN = {"Authorization": f"Bearer {ADMIN_TOKEN}"}
SAME = {"Origin": ORIGIN}
# Reserved example domain; a fixed, test-only key (32 bytes of "k").
OWNER_EMAIL = "owner@example.org"
SECRET_KEY = "a2tra2tra2tra2tra2tra2tra2tra2tra2tra2tra2s="
PASSWORD = "plum orchard kettle drum seven"


def admin_settings(tmp_path: Path, **overrides: object) -> Settings:
    values: dict[str, object] = {
        "admin_token": SecretStr(ADMIN_TOKEN),
        "admin_origin": ORIGIN,
        "admin_email": OWNER_EMAIL,
        "admin_secret_key": SecretStr(SECRET_KEY),
        "app_status_signing_seed": SecretStr(TEST_SEED),
        "downloads_csv_url": None,
    }
    values.update(overrides)
    return make_settings(tmp_path, **values)


# Codes are spent faster than 30-second steps pass, so tests move the authenticator's clock
# forward instead of waiting: each new code is for the next step, and the server sees that
# step as the current one.
_SHIFT = [0]
_REAL_STEP = totp.step_at


def _shifted_step(now: datetime) -> int:
    return _REAL_STEP(now) + _SHIFT[0]


@pytest.fixture(autouse=True)
def totp_clock(monkeypatch: pytest.MonkeyPatch) -> None:
    _SHIFT[0] = 0
    monkeypatch.setattr(totp, "step_at", _shifted_step)


@dataclass
class Owner:
    username: str = "owner"
    password: str = PASSWORD
    secret: bytes = b""
    codes: list[str] = field(default_factory=list)
    last_step: int = 0

    def code(self, offset: int = 0) -> str:
        """A code for a step not used yet (each code works once)."""
        current = totp.step_at(datetime.now(UTC))
        step = max(current + offset, self.last_step + 1)
        if step > current:
            _SHIFT[0] += step - current
        self.last_step = step
        return totp.code_at(self.secret, step)


async def make_starter(
    client: httpx.AsyncClient, username: str = "owner", *, reset: bool = False
) -> str:
    made = await client.post(
        "/v1/admin/starter-user", json={"username": username, "reset": reset}, headers=ADMIN
    )
    assert made.status_code == 201, made.text
    body = made.json()
    assert body["sign_in_url"] == f"{ORIGIN}/admin/sign-in"
    temporary: str = body["temporary_password"]
    return temporary


async def post(client: httpx.AsyncClient, url: str, **fields: str) -> httpx.Response:
    return await client.post(url, data=fields, headers=SAME)


def key_from(page: str) -> bytes:
    match = re.search(r"data-key>([A-Z2-7 ]+)<", page)
    assert match, "no key on the page"
    text = match.group(1).replace(" ", "")
    import base64  # noqa: PLC0415

    return base64.b32decode(text + "=" * (-len(text) % 8))


def codes_from(page: str) -> list[str]:
    return re.findall(r"<li>([0-9A-Z]{5}-[0-9A-Z]{5})</li>", page)


async def first_sign_in(
    client: httpx.AsyncClient, mail: FakeMail, owner: Owner | None = None
) -> Owner:
    """The whole first sign-in, ending signed in on the overview."""
    owner = owner or Owner()
    temporary = await make_starter(client, owner.username)
    response = await post(client, "/admin/sign-in", username=owner.username, password=temporary)
    assert response.status_code == 303, response.text
    assert response.headers["location"] == "/admin/first/email"
    response = await post(client, "/admin/first/email", code=mail.last_code())
    assert response.headers["location"] == "/admin/first/password", response.text
    response = await post(
        client, "/admin/first/password", new_password=owner.password, confirm=owner.password
    )
    assert response.headers["location"] == "/admin/first/authenticator", response.text
    owner.secret = key_from((await client.get("/admin/first/authenticator")).text)
    response = await post(client, "/admin/first/authenticator", code=owner.code())
    assert response.headers["location"] == "/admin/first/recovery-codes", response.text
    owner.codes = codes_from((await client.get("/admin/first/recovery-codes")).text)
    assert len(owner.codes) == 10
    response = await post(client, "/admin/first/recovery-codes", saved="yes")
    assert response.headers["location"] == "/admin", response.text
    return owner


async def sign_in(client: httpx.AsyncClient, owner: Owner) -> httpx.Response:
    """A later sign-in: the password, then an authenticator code."""
    response = await post(
        client, "/admin/sign-in", username=owner.username, password=owner.password
    )
    assert response.status_code == 303, response.text
    assert response.headers["location"] == "/admin/sign-in/code"
    return await post(client, "/admin/sign-in/code", code=owner.code())

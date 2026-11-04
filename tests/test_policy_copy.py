"""Emailing a copy of the privacy policy."""

from pathlib import Path

import httpx
import pytest

from ngome.api.app import create_app
from ngome.core.config import Settings
from ngome.db.models import Base
from ngome.privacy.pdf import text_to_pdf
from ngome.privacy.service import plain_text, policy_digest
from tests.conftest import FakeGoogle, FakeMail, bearer, make_settings, sign_in

POLICY = (
    "# Privacy policy\n\nVersion 1.4.\n\n## What stays on your phone\n\n"
    "- Your **messages** — always.\n- Your transactions.\n"
)


@pytest.fixture
def settings(tmp_path: Path) -> Settings:
    return make_settings(
        tmp_path, privacy_policy_sha256=[policy_digest(POLICY)], privacy_copy_max_per_day=2
    )


def test_the_copy_reads_as_plain_text() -> None:
    text = plain_text(POLICY)
    assert "WHAT STAYS ON YOUR PHONE" in text
    assert "**" not in text
    assert "#" not in text


def test_the_pdf_is_a_pdf() -> None:
    pdf = text_to_pdf(plain_text(POLICY) * 40, title="Policy")
    assert pdf.startswith(b"%PDF-1.4")
    assert pdf.rstrip().endswith(b"%%EOF")
    # Long text runs over several pages, and every page is listed.
    assert pdf.count(b"/Type /Page ") > 1
    assert b"WHAT STAYS ON YOUR PHONE" in pdf


async def test_sends_the_policy_as_text_and_pdf(client: httpx.AsyncClient, mail: FakeMail) -> None:
    auth = bearer(await sign_in(client, mail))
    response = await client.post(
        "/v1/privacy/copy",
        json={"email": "  Copy@Example.com ", "policy": POLICY},
        headers=auth,
    )
    assert response.status_code == 202, response.text
    to, text = mail.sent[-1]
    assert to == "copy@example.com"
    assert "WHAT STAYS ON YOUR PHONE" in text
    (attachment,) = mail.attachments[-1]
    assert attachment.content_type == "application/pdf"
    assert attachment.data.startswith(b"%PDF")


async def test_only_an_approved_policy_is_sent(client: httpx.AsyncClient, mail: FakeMail) -> None:
    auth = bearer(await sign_in(client, mail))
    sent = len(mail.sent)
    response = await client.post(
        "/v1/privacy/copy",
        json={"email": "copy@example.com", "policy": POLICY + "Buy cheap watches!"},
        headers=auth,
    )
    assert response.status_code == 422
    assert len(mail.sent) == sent


async def test_needs_a_signed_in_account(client: httpx.AsyncClient) -> None:
    response = await client.post(
        "/v1/privacy/copy", json={"email": "copy@example.com", "policy": POLICY}
    )
    assert response.status_code == 401


async def test_a_few_copies_a_day(client: httpx.AsyncClient, mail: FakeMail) -> None:
    auth = bearer(await sign_in(client, mail))
    body = {"email": "copy@example.com", "policy": POLICY}
    for _ in range(2):
        assert (await client.post("/v1/privacy/copy", json=body, headers=auth)).status_code == 202
    third = await client.post("/v1/privacy/copy", json=body, headers=auth)
    assert third.status_code == 429


async def test_a_bad_address_is_refused(client: httpx.AsyncClient, mail: FakeMail) -> None:
    auth = bearer(await sign_in(client, mail))
    response = await client.post(
        "/v1/privacy/copy", json={"email": "not an address", "policy": POLICY}, headers=auth
    )
    assert response.status_code == 422


async def test_off_until_a_policy_is_approved(tmp_path: Path, mail: FakeMail) -> None:
    application = create_app(make_settings(tmp_path))
    application.state.email_sender = mail
    application.state.google_verifier = FakeGoogle()
    async with application.state.engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    transport = httpx.ASGITransport(app=application)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        auth = bearer(await sign_in(client, mail))
        response = await client.post(
            "/v1/privacy/copy", json={"email": "copy@example.com", "policy": POLICY}, headers=auth
        )
    await application.state.engine.dispose()
    assert response.status_code == 503

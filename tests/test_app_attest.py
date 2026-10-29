"""App Attest, checked against a stand-in for Apple's chain built in the test."""

import base64
import hashlib
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path

import cbor2
import httpx
import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID
from fastapi import FastAPI
from pydantic import ValidationError

from ngome.core.config import Settings
from ngome.integrity.apple import (
    AAGUIDS,
    NONCE_OID,
    ROOT_CA_SHA256,
    AppAttestPolicy,
    AttestedKey,
    load_root_ca,
    verify_assertion,
    verify_attestation,
)
from ngome.integrity.play import IntegrityFailedError, request_hash_of_sha256_hex
from tests.conftest import OTHER_EMAIL, FakeMail, bearer, make_settings, sign_in

APP_ID = "ABCDE12345.com.pesaclarity.app"
POLICY = AppAttestPolicy(app_id=APP_ID, environment="production")
NOW = datetime(2026, 10, 29, 12, tzinfo=UTC)
OCTET = {"Content-Type": "application/octet-stream"}


def _name(common: str) -> x509.Name:
    return x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common)])


def _cert(
    subject: str,
    key: ec.EllipticCurvePrivateKey,
    issuer: str,
    issuer_key: ec.EllipticCurvePrivateKey,
    *,
    ca: bool,
    nonce: bytes | None = None,
) -> x509.Certificate:
    builder = (
        x509.CertificateBuilder()
        .subject_name(_name(subject))
        .issuer_name(_name(issuer))
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(NOW - timedelta(days=1))
        .not_valid_after(NOW + timedelta(days=1))
        .add_extension(x509.BasicConstraints(ca=ca, path_length=None), critical=True)
    )
    if nonce is not None:
        # SEQUENCE { [1] { OCTET STRING nonce } }
        octets = b"\x04\x20" + nonce
        tagged = b"\xa1" + bytes([len(octets)]) + octets
        der = b"\x30" + bytes([len(tagged)]) + tagged
        builder = builder.add_extension(x509.UnrecognizedExtension(NONCE_OID, der), critical=False)
    return builder.sign(issuer_key, hashes.SHA256())


@dataclass
class FakeApple:
    """Plays Apple's part: a root, an intermediate, and a key the "phone" attests."""

    root_key: ec.EllipticCurvePrivateKey
    root: x509.Certificate
    ca_key: ec.EllipticCurvePrivateKey
    ca: x509.Certificate

    @classmethod
    def create(cls) -> "FakeApple":
        root_key = ec.generate_private_key(ec.SECP384R1())
        root = _cert("Test root", root_key, "Test root", root_key, ca=True)
        ca_key = ec.generate_private_key(ec.SECP384R1())
        ca = _cert("Test CA", ca_key, "Test root", root_key, ca=True)
        return cls(root_key, root, ca_key, ca)


@dataclass
class FakePhone:
    apple: FakeApple
    key: ec.EllipticCurvePrivateKey
    counter: int = 0

    @classmethod
    def create(cls, apple: FakeApple) -> "FakePhone":
        return cls(apple, ec.generate_private_key(ec.SECP256R1()))

    @property
    def key_id(self) -> bytes:
        point = self.key.public_key().public_bytes(
            serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint
        )
        return hashlib.sha256(point).digest()

    def attest(
        self,
        challenge: bytes,
        *,
        app_id: str = APP_ID,
        aaguid: bytes = AAGUIDS["production"],
        counter: int = 0,
        nonce: bytes | None = None,
    ) -> bytes:
        auth_data = (
            hashlib.sha256(app_id.encode()).digest()
            + b"\x40"
            + counter.to_bytes(4, "big")
            + aaguid
            + len(self.key_id).to_bytes(2, "big")
            + self.key_id
        )
        expected = hashlib.sha256(auth_data + hashlib.sha256(challenge).digest()).digest()
        leaf = _cert(
            "Leaf", self.key, "Test CA", self.apple.ca_key, ca=False, nonce=nonce or expected
        )
        return cbor2.dumps(
            {
                "fmt": "apple-appattest",
                "attStmt": {
                    "x5c": [
                        leaf.public_bytes(serialization.Encoding.DER),
                        self.apple.ca.public_bytes(serialization.Encoding.DER),
                    ],
                    "receipt": b"",
                },
                "authData": auth_data,
            }
        )

    def sign(self, client_data: bytes, *, app_id: str = APP_ID) -> bytes:
        self.counter += 1
        auth_data = (
            hashlib.sha256(app_id.encode()).digest() + b"\x40" + self.counter.to_bytes(4, "big")
        )
        nonce = hashlib.sha256(auth_data + hashlib.sha256(client_data).digest()).digest()
        signature = self.key.sign(nonce, ec.ECDSA(hashes.SHA256()))
        return cbor2.dumps({"signature": signature, "authenticatorData": auth_data})

    def header(self, request_hash: str) -> str:
        assertion = self.sign(request_hash.encode())
        return (
            f"appattest {base64.b64encode(self.key_id).decode()} "
            f"{base64.b64encode(assertion).decode()}"
        )


@pytest.fixture
def apple() -> FakeApple:
    return FakeApple.create()


@pytest.fixture
def phone(apple: FakeApple) -> FakePhone:
    return FakePhone.create(apple)


def test_the_bundled_root_is_apples() -> None:
    root = load_root_ca()
    assert root.fingerprint(hashes.SHA256()).hex() == ROOT_CA_SHA256
    assert "CN=Apple App Attestation Root CA" in root.subject.rfc4514_string()


def test_a_good_attestation_gives_the_key(apple: FakeApple, phone: FakePhone) -> None:
    key = verify_attestation(
        phone.attest(b"challenge"), b"challenge", phone.key_id, POLICY, apple.root, NOW
    )
    assert key.key_id == phone.key_id
    assert key.sign_count == 0


@pytest.mark.parametrize(
    ("change", "reason"),
    [
        ({"challenge": b"other"}, "nonce"),
        ({"app_id": "ZZZZZ99999.com.example"}, "app"),
        ({"aaguid": AAGUIDS["development"]}, "environment"),
        ({"counter": 1}, "counter"),
        ({"nonce": b"\x00" * 32}, "nonce"),
    ],
)
def test_a_wrong_attestation_is_refused(
    apple: FakeApple, phone: FakePhone, change: dict[str, object], reason: str
) -> None:
    challenge = change.pop("challenge", b"challenge")
    attestation = phone.attest(challenge, **change)  # type: ignore[arg-type]
    with pytest.raises(IntegrityFailedError) as caught:
        verify_attestation(attestation, b"challenge", phone.key_id, POLICY, apple.root, NOW)
    assert caught.value.reason == reason


def test_another_root_is_refused(apple: FakeApple, phone: FakePhone) -> None:
    with pytest.raises(IntegrityFailedError) as caught:
        verify_attestation(
            phone.attest(b"c"), b"c", phone.key_id, POLICY, FakeApple.create().root, NOW
        )
    assert caught.value.reason == "certificate"


def test_an_expired_chain_is_refused(apple: FakeApple, phone: FakePhone) -> None:
    with pytest.raises(IntegrityFailedError):
        verify_attestation(
            phone.attest(b"c"), b"c", phone.key_id, POLICY, apple.root, NOW + timedelta(days=9)
        )


def test_a_key_id_for_another_key_is_refused(apple: FakeApple, phone: FakePhone) -> None:
    with pytest.raises(IntegrityFailedError) as caught:
        verify_attestation(phone.attest(b"c"), b"c", b"\x01" * 32, POLICY, apple.root, NOW)
    assert caught.value.reason == "key"


def test_garbage_is_refused(apple: FakeApple) -> None:
    with pytest.raises(IntegrityFailedError):
        verify_attestation(b"not cbor", b"c", b"\x00" * 32, POLICY, apple.root, NOW)
    with pytest.raises(IntegrityFailedError):
        verify_attestation(cbor2.dumps({"fmt": "x"}), b"c", b"\x00" * 32, POLICY, apple.root, NOW)


def _attested(apple: FakeApple, phone: FakePhone) -> AttestedKey:
    return verify_attestation(phone.attest(b"c"), b"c", phone.key_id, POLICY, apple.root, NOW)


def test_assertions_need_the_key_the_data_and_a_rising_counter(
    apple: FakeApple, phone: FakePhone
) -> None:
    key = _attested(apple, phone)
    first = phone.sign(b"hash-1")
    count = verify_assertion(first, b"hash-1", key, POLICY)
    assert count == 1
    key = AttestedKey(key.key_id, key.public_key_der, count)

    # The same assertion again: the counter has not risen.
    with pytest.raises(IntegrityFailedError) as replayed:
        verify_assertion(first, b"hash-1", key, POLICY)
    assert replayed.value.reason == "counter"
    # Moved onto other bytes.
    with pytest.raises(IntegrityFailedError) as moved:
        verify_assertion(phone.sign(b"hash-2"), b"hash-3", key, POLICY)
    assert moved.value.reason == "signature"
    # Signed by another key.
    stranger = FakePhone.create(apple)
    with pytest.raises(IntegrityFailedError):
        verify_assertion(stranger.sign(b"h"), b"h", key, POLICY)
    # For another app.
    with pytest.raises(IntegrityFailedError) as other_app:
        verify_assertion(phone.sign(b"h", app_id="ZZZZZ99999.x"), b"h", key, POLICY)
    assert other_app.value.reason == "app"


def test_enabling_app_attest_needs_every_setting(tmp_path: Path) -> None:
    with pytest.raises(ValidationError):
        make_settings(tmp_path, app_attest_enabled=True)
    with pytest.raises(ValidationError):
        make_settings(tmp_path, app_attest_app_id="com.pesaclarity.app")
    settings = make_settings(
        tmp_path,
        app_attest_enabled=True,
        app_attest_app_id=APP_ID,
        app_attest_environment="production",
        vault_unattested_uploads="reject",
    )
    assert settings.app_attest_enabled


# The HTTP flow: register a key, then upload with assertions.


@pytest.fixture
def settings(tmp_path: Path) -> Settings:
    return make_settings(
        tmp_path,
        app_attest_enabled=True,
        app_attest_app_id=APP_ID,
        app_attest_environment="production",
        vault_unattested_uploads="reject",
    )


@pytest.fixture
def attest_app(app: FastAPI, apple: FakeApple) -> FastAPI:
    app.state.app_attest_root = apple.root
    return app


async def _register(
    client: httpx.AsyncClient, tokens: dict[str, str], phone: FakePhone
) -> httpx.Response:
    challenge = await client.post("/v1/integrity/app-attest/challenges", headers=bearer(tokens))
    assert challenge.status_code == 201, challenge.text
    raw = base64.b64decode(challenge.json()["challenge"])
    return await client.post(
        "/v1/integrity/app-attest/keys",
        headers=bearer(tokens),
        json={
            "key_id": base64.b64encode(phone.key_id).decode(),
            "attestation": base64.b64encode(phone.attest(raw)).decode(),
            "challenge": challenge.json()["challenge"],
        },
    )


def _upload_headers(tokens: dict[str, str], body: bytes, phone: FakePhone) -> dict[str, str]:
    sha = hashlib.sha256(body).hexdigest()
    return {
        **bearer(tokens),
        **OCTET,
        "X-Content-SHA256": sha,
        "X-Pesaclarity-Integrity": phone.header(request_hash_of_sha256_hex(sha)),
    }


async def test_an_attested_iphone_can_upload(
    attest_app: FastAPI, client: httpx.AsyncClient, mail: FakeMail, phone: FakePhone
) -> None:
    tokens = await sign_in(client, mail)
    registered = await _register(client, tokens, phone)
    assert registered.status_code == 204, registered.text

    body = b"\x01" * 300
    first = await client.post(
        "/v1/vault/backups", content=body, headers=_upload_headers(tokens, body, phone)
    )
    assert first.status_code == 201, first.text

    # Unattested uploads stay refused.
    plain = await client.post(
        "/v1/vault/backups",
        content=body,
        headers={**bearer(tokens), **OCTET, "X-Content-SHA256": hashlib.sha256(body).hexdigest()},
    )
    assert plain.status_code == 403


async def test_a_replayed_assertion_is_refused(
    attest_app: FastAPI, client: httpx.AsyncClient, mail: FakeMail, phone: FakePhone
) -> None:
    tokens = await sign_in(client, mail)
    assert (await _register(client, tokens, phone)).status_code == 204
    body = b"\x02" * 300
    headers = _upload_headers(tokens, body, phone)
    assert (
        await client.post("/v1/vault/backups", content=body, headers=headers)
    ).status_code == 201
    again = await client.post("/v1/vault/backups", content=body, headers=headers)
    assert again.status_code == 403


async def test_a_challenge_works_once_and_only_for_its_account(
    attest_app: FastAPI, client: httpx.AsyncClient, mail: FakeMail, phone: FakePhone
) -> None:
    tokens = await sign_in(client, mail)
    other = await sign_in(client, mail, email=OTHER_EMAIL)
    challenge = (
        await client.post("/v1/integrity/app-attest/challenges", headers=bearer(tokens))
    ).json()["challenge"]
    body = {
        "key_id": base64.b64encode(phone.key_id).decode(),
        "attestation": base64.b64encode(phone.attest(base64.b64decode(challenge))).decode(),
        "challenge": challenge,
    }
    wrong_account = await client.post(
        "/v1/integrity/app-attest/keys", headers=bearer(other), json=body
    )
    assert wrong_account.status_code == 403
    used = await client.post("/v1/integrity/app-attest/keys", headers=bearer(tokens), json=body)
    assert used.status_code == 204
    again = await client.post("/v1/integrity/app-attest/keys", headers=bearer(tokens), json=body)
    assert again.status_code == 403


async def test_another_accounts_key_cannot_upload(
    attest_app: FastAPI, client: httpx.AsyncClient, mail: FakeMail, phone: FakePhone
) -> None:
    owner = await sign_in(client, mail)
    assert (await _register(client, owner, phone)).status_code == 204
    other = await sign_in(client, mail, email=OTHER_EMAIL)
    body = b"\x03" * 300
    response = await client.post(
        "/v1/vault/backups", content=body, headers=_upload_headers(other, body, phone)
    )
    assert response.status_code == 403


async def test_deleting_the_account_removes_its_keys(
    attest_app: FastAPI, client: httpx.AsyncClient, mail: FakeMail, phone: FakePhone
) -> None:
    tokens = await sign_in(client, mail)
    assert (await _register(client, tokens, phone)).status_code == 204
    assert (await client.delete("/v1/account", headers=bearer(tokens))).status_code == 204
    again = await sign_in(client, mail)
    body = b"\x04" * 300
    response = await client.post(
        "/v1/vault/backups", content=body, headers=_upload_headers(again, body, phone)
    )
    assert response.status_code == 403


class TestWhenOff:
    @pytest.fixture
    def settings(self, tmp_path: Path) -> Settings:
        return make_settings(tmp_path)

    async def test_registration_is_not_found(
        self, client: httpx.AsyncClient, mail: FakeMail
    ) -> None:
        tokens = await sign_in(client, mail)
        response = await client.post("/v1/integrity/app-attest/challenges", headers=bearer(tokens))
        assert response.status_code == 404

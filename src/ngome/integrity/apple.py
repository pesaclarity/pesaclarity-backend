"""Apple App Attest: the iPhone counterpart of Play Integrity.

An install registers a key once: the server sends a challenge, the app asks Apple to attest a
new key over it, and the server checks the attestation against Apple's root and keeps the key.
Each vault upload then carries an assertion: a signature by that key over the upload's
``requestHash`` (the same base64url SHA-256 of the body that Play builds bind their token to),
with a counter that must rise, so an assertion cannot be replayed or moved to other bytes.

See Apple's "Validating apps that connect to your server".
"""

import hashlib
import itertools
from dataclasses import dataclass
from datetime import datetime
from importlib.resources import files
from typing import Literal

import cbor2
from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec

from ngome.core.config import Settings
from ngome.integrity.play import IntegrityFailedError

# Apple App Attestation Root CA, from
# https://www.apple.com/certificateauthority/Apple_App_Attestation_Root_CA.pem
# SHA-256 fingerprint 1C:B9:82:3B:A2:8B:A6:AD:2D:33:A0:06:94:1D:E2:AE:
# 4F:51:3E:F1:D4:E8:31:B9:F7:E0:FA:7B:62:42:C9:32 (checked by a test).
ROOT_CA_FILE = "apple_app_attestation_root_ca.pem"
ROOT_CA_SHA256 = "1cb9823ba28ba6ad2d33a006941de2ae4f513ef1d4e831b9f7e0fa7b6242c932"

# The leaf certificate's extension holding the nonce.
NONCE_OID = x509.ObjectIdentifier("1.2.840.113635.100.8.2")

AAGUIDS = {
    "production": b"appattest" + b"\x00" * 7,
    "development": b"appattestdevelop",
}

# The header value the app sends: "appattest <key id> <assertion>", both base64.
HEADER_SCHEME = "appattest"

Environment = Literal["production", "development"]


@dataclass(frozen=True, slots=True)
class AppAttestPolicy:
    """``app_id`` is the Apple team id and bundle id, such as ``ABCDE12345.com.pesaclarity.app``."""

    app_id: str
    environment: Environment

    @property
    def rp_id_hash(self) -> bytes:
        return hashlib.sha256(self.app_id.encode()).digest()


@dataclass(frozen=True, slots=True)
class AttestedKey:
    key_id: bytes
    public_key_der: bytes
    sign_count: int


def load_root_ca() -> x509.Certificate:
    pem = files("ngome.integrity").joinpath(ROOT_CA_FILE).read_bytes()
    return x509.load_pem_x509_certificate(pem)


def _der_length(data: bytes, at: int) -> tuple[int, int]:
    first = data[at]
    if first < 0x80:
        return first, at + 1
    count = first & 0x7F
    if count == 0 or count > 4:
        raise IntegrityFailedError("nonce")
    return int.from_bytes(data[at + 1 : at + 1 + count], "big"), at + 1 + count


def _nonce_from_extension(der: bytes) -> bytes:
    """``SEQUENCE { [1] EXPLICIT OCTET STRING nonce }``."""
    try:
        if der[0] != 0x30:
            raise IntegrityFailedError("nonce")
        _, at = _der_length(der, 1)
        if der[at] != 0xA1:
            raise IntegrityFailedError("nonce")
        _, at = _der_length(der, at + 1)
        if der[at] != 0x04:
            raise IntegrityFailedError("nonce")
        length, at = _der_length(der, at + 1)
        return der[at : at + length]
    except IndexError:
        raise IntegrityFailedError("nonce") from None


def _check_chain(
    leaf: x509.Certificate,
    intermediates: list[x509.Certificate],
    root: x509.Certificate,
    now: datetime,
) -> None:
    chain = [leaf, *intermediates, root]
    try:
        for cert, issuer in itertools.pairwise(chain):
            cert.verify_directly_issued_by(issuer)
    except (InvalidSignature, ValueError, TypeError):
        raise IntegrityFailedError("certificate") from None
    for cert in chain:
        if not cert.not_valid_before_utc <= now <= cert.not_valid_after_utc:
            raise IntegrityFailedError("certificate")


def _counter(auth_data: bytes) -> int:
    return int.from_bytes(auth_data[33:37], "big")


def verify_attestation(
    attestation: bytes,
    challenge: bytes,
    key_id: bytes,
    policy: AppAttestPolicy,
    root: x509.Certificate,
    now: datetime,
) -> AttestedKey:
    """Check an attestation of ``key_id`` made over ``challenge``; return the key to keep."""
    try:
        decoded = cbor2.loads(attestation)
        statement = decoded["attStmt"]
        auth_data: bytes = decoded["authData"]
        x5c: list[bytes] = statement["x5c"]
        fmt = decoded["fmt"]
    except (cbor2.CBORDecodeError, KeyError, TypeError, ValueError):
        raise IntegrityFailedError("attestation") from None
    if fmt != "apple-appattest" or len(x5c) < 2 or not isinstance(auth_data, bytes):
        raise IntegrityFailedError("attestation")
    try:
        leaf, *intermediates = [x509.load_der_x509_certificate(c) for c in x5c]
    except (ValueError, TypeError):
        raise IntegrityFailedError("certificate") from None
    _check_chain(leaf, intermediates, root, now)

    client_data_hash = hashlib.sha256(challenge).digest()
    nonce = hashlib.sha256(auth_data + client_data_hash).digest()
    try:
        extension = leaf.extensions.get_extension_for_oid(NONCE_OID).value
    except x509.ExtensionNotFound:
        raise IntegrityFailedError("nonce") from None
    if not isinstance(extension, x509.UnrecognizedExtension):
        raise IntegrityFailedError("nonce")
    if _nonce_from_extension(extension.value) != nonce:
        raise IntegrityFailedError("nonce")

    public_key = leaf.public_key()
    if not isinstance(public_key, ec.EllipticCurvePublicKey):
        raise IntegrityFailedError("key")
    point = public_key.public_bytes(
        serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint
    )
    if hashlib.sha256(point).digest() != key_id:
        raise IntegrityFailedError("key")

    if len(auth_data) < 55 or auth_data[:32] != policy.rp_id_hash:
        raise IntegrityFailedError("app")
    if _counter(auth_data) != 0:
        raise IntegrityFailedError("counter")
    if auth_data[37:53] != AAGUIDS[policy.environment]:
        raise IntegrityFailedError("environment")
    id_length = int.from_bytes(auth_data[53:55], "big")
    if auth_data[55 : 55 + id_length] != key_id:
        raise IntegrityFailedError("key")

    return AttestedKey(
        key_id=key_id,
        public_key_der=public_key.public_bytes(
            serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
        ),
        sign_count=0,
    )


def verify_assertion(
    assertion: bytes, client_data: bytes, key: AttestedKey, policy: AppAttestPolicy
) -> int:
    """Check an assertion over ``client_data`` by ``key``; return the new counter to keep."""
    try:
        decoded = cbor2.loads(assertion)
        signature: bytes = decoded["signature"]
        auth_data: bytes = decoded["authenticatorData"]
    except (cbor2.CBORDecodeError, KeyError, TypeError, ValueError):
        raise IntegrityFailedError("assertion") from None
    if not isinstance(signature, bytes) or not isinstance(auth_data, bytes) or len(auth_data) < 37:
        raise IntegrityFailedError("assertion")
    nonce = hashlib.sha256(auth_data + hashlib.sha256(client_data).digest()).digest()
    public_key = serialization.load_der_public_key(key.public_key_der)
    if not isinstance(public_key, ec.EllipticCurvePublicKey):
        raise IntegrityFailedError("key")
    try:
        public_key.verify(signature, nonce, ec.ECDSA(hashes.SHA256()))
    except InvalidSignature:
        raise IntegrityFailedError("signature") from None
    if auth_data[:32] != policy.rp_id_hash:
        raise IntegrityFailedError("app")
    counter = _counter(auth_data)
    if counter <= key.sign_count:
        raise IntegrityFailedError("counter")
    return counter


def build_app_attest_policy(settings: Settings) -> AppAttestPolicy | None:
    """The policy when App Attest is on, else None."""
    if not settings.app_attest_enabled:
        return None
    if settings.app_attest_app_id is None or settings.app_attest_environment is None:
        # The settings validator rejects this; kept for type narrowing.
        raise ValueError("App Attest settings are incomplete")
    return AppAttestPolicy(
        app_id=settings.app_attest_app_id, environment=settings.app_attest_environment
    )

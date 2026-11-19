"""Authenticator codes (TOTP, RFC 6238), the QR code that sets an app up, and the secret's
encryption at rest (ADR 0025 §3).

SHA-1, 6 digits, 30-second steps: what every authenticator app supports. A code is accepted
for the current step or one either side, and only for a step later than the last one accepted,
so each code works once.
"""

import base64
import hashlib
import hmac
import secrets
import struct
from datetime import datetime
from urllib.parse import quote

import segno
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

ISSUER = "Pesa Clarity admin"
DIGITS = 6
PERIOD = 30
SECRET_BYTES = 20


def new_secret() -> bytes:
    return secrets.token_bytes(SECRET_BYTES)


def key_text(secret: bytes) -> str:
    """The base32 key an app takes when the QR code cannot be scanned."""
    return base64.b32encode(secret).decode().rstrip("=")


def spaced(key: str) -> str:
    return " ".join(key[i : i + 4] for i in range(0, len(key), 4))


def provisioning_uri(secret: bytes, username: str) -> str:
    label = quote(f"{ISSUER}:{username}")
    issuer = quote(ISSUER)
    return (
        f"otpauth://totp/{label}?secret={key_text(secret)}&issuer={issuer}"
        f"&algorithm=SHA1&digits={DIGITS}&period={PERIOD}"
    )


def qr_svg(uri: str) -> str:
    """Inline SVG (attributes only, no style), which the dashboard's CSP allows."""
    return str(
        segno.make(uri, error="m").svg_inline(
            scale=1,
            border=2,
            dark="#000",
            light="#fff",
            omitsize=True,
            svgclass="qr",
            lineclass=None,
        )
    )


def step_at(now: datetime) -> int:
    return int(now.timestamp()) // PERIOD


def code_at(secret: bytes, step: int) -> str:
    digest = hmac.new(secret, struct.pack(">Q", step), hashlib.sha1).digest()
    offset = digest[-1] & 0x0F
    value = struct.unpack(">I", digest[offset : offset + 4])[0] & 0x7FFFFFFF
    return f"{value % 10**DIGITS:0{DIGITS}d}"


def clean(code: str) -> str:
    return "".join(c for c in code if not c.isspace())


def matching_step(secret: bytes, code: str, *, now: datetime, after: int) -> int | None:
    """The step ``code`` belongs to (the current one or one either side), if it is later
    than ``after``; otherwise ``None``."""
    code = clean(code)
    if len(code) != DIGITS or not code.isdigit():
        return None
    current = step_at(now)
    for step in (current - 1, current, current + 1):
        if step > after and hmac.compare_digest(code_at(secret, step), code):
            return step
    return None


def seal(key: bytes, secret: bytes, associated: bytes) -> tuple[bytes, bytes]:
    nonce = secrets.token_bytes(12)
    return AESGCM(key).encrypt(nonce, secret, associated), nonce


def unseal(key: bytes, ciphertext: bytes, nonce: bytes, associated: bytes) -> bytes:
    return AESGCM(key).decrypt(nonce, ciphertext, associated)

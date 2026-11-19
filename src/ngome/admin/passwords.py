"""Admin passwords: Argon2id hashes and the rules a new password must meet (ADR 0025 §2).

Argon2id at OWASP's first listed setting (m = 46 MiB, t = 1, p = 1). At most two hashes run
at once per instance, so a burst of sign-ins cannot exhaust a 512 MiB instance.

The breached-password check is offline: a bundled list of the 47,023 most common passwords
(zxcvbn's list, MIT; see ``data/``). A full check against every breached password does not fit
in the image, so the 15-character minimum and the required second factor carry the rest.
"""

import asyncio
import re
import secrets
import unicodedata
from concurrent.futures import ThreadPoolExecutor
from functools import cache
from importlib import resources

from argon2 import PasswordHasher, Type
from argon2.exceptions import InvalidHashError, VerificationError

MIN_LENGTH = 15
MAX_LENGTH = 128
_HASHER = PasswordHasher(
    time_cost=1, memory_cost=47_104, parallelism=1, hash_len=32, salt_len=16, type=Type.ID
)
# Two threads: at most two hashes at once on this instance, whatever the load.
_POOL = ThreadPoolExecutor(max_workers=2, thread_name_prefix="argon2")
_TAIL = re.compile(r"[\d\W_]+$")


def normalise(password: str) -> str:
    return unicodedata.normalize("NFKC", password)


@cache
def _dummy_hash() -> str:
    # Checked when the username is unknown, so timing does not say whether it exists.
    return _HASHER.hash(secrets.token_urlsafe(24))


async def hash_password(password: str) -> str:
    return await asyncio.get_running_loop().run_in_executor(
        _POOL, _HASHER.hash, normalise(password)
    )


async def verify_password(stored: str | None, password: str) -> bool:
    """True when ``password`` matches ``stored``; with ``None``, checks a dummy hash and is
    False, taking as long as a real check."""
    target = stored or _dummy_hash()
    ok: bool
    try:
        ok = await asyncio.get_running_loop().run_in_executor(
            _POOL, _HASHER.verify, target, normalise(password)
        )
    except (VerificationError, InvalidHashError):
        ok = False
    return ok and stored is not None


def needs_rehash(stored: str) -> bool:
    return _HASHER.check_needs_rehash(stored)


@cache
def common_passwords() -> frozenset[str]:
    text = (resources.files("ngome.admin") / "data" / "common-passwords.txt").read_text()
    return frozenset(line for line in text.splitlines() if line and not line.startswith("#"))


def _is_common(lowered: str) -> bool:
    common = common_passwords()
    if lowered in common or _TAIL.sub("", lowered) in common:
        return True
    # A common password said twice or more ("passwordpassword").
    for size in range(1, len(lowered) // 2 + 1):
        if len(lowered) % size == 0 and lowered == lowered[:size] * (len(lowered) // size):
            return lowered[:size] in common or size < 4
    return False


def problem(password: str, *, username: str, host: str) -> str | None:
    """Why ``password`` cannot be used, in words for the page, or ``None`` if it can."""
    text = normalise(password)
    if len(text) < MIN_LENGTH:
        return f"Use at least {MIN_LENGTH} characters."
    if len(text) > MAX_LENGTH:
        return f"Use at most {MAX_LENGTH} characters."
    lowered = text.lower()
    for word in (username.lower(), "pesaclarity", "pesa clarity", host.lower()):
        if word and word in lowered:
            return (
                "Don\u2019t use the username, \u201cpesaclarity\u201d or the "
                "dashboard\u2019s address in it."
            )
    if len(set(lowered)) < 5 or _is_common(lowered):
        return "That password is too common. Try a long passphrase from your password manager."
    return None

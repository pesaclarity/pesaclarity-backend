"""Outbound identity providers, kept behind small interfaces so they can be swapped or faked."""

from dataclasses import dataclass
from typing import Protocol

from ngome.core.config import Settings
from ngome.core.logging import get_logger

log = get_logger(__name__)


class SmsSender(Protocol):
    async def send(self, phone_e164: str, text: str) -> None:
        """Deliver ``text`` to ``phone_e164`` or raise."""
        ...


class ConsoleSmsSender:
    """Development-only sender that prints the message instead of sending it.

    Settings validation refuses this provider in production.
    """

    async def send(self, phone_e164: str, text: str) -> None:
        # Printed, not logged, so the code never reaches log storage.
        print(f"[dev sms to ...{phone_e164[-3:]}] {text}", flush=True)  # noqa: T201


class PhoneSignInDisabledError(Exception):
    """Phone sign-in is switched off on this server."""


class DisabledSmsSender:
    """Sends nothing: phone sign-in is off on this server."""

    async def send(self, phone_e164: str, text: str) -> None:
        raise PhoneSignInDisabledError


@dataclass(frozen=True, slots=True)
class GoogleIdentity:
    subject: str


class InvalidGoogleTokenError(Exception):
    """The Google ID token failed verification."""


class GoogleVerifier(Protocol):
    async def verify(self, id_token: str) -> GoogleIdentity:
        """Verify a Google ID token for one of our client ids and return the stable subject."""
        ...


class UnconfiguredGoogleVerifier:
    """Refuses every token. Used when Google sign-in is disabled, as on F-Droid deployments."""

    async def verify(self, id_token: str) -> GoogleIdentity:
        raise InvalidGoogleTokenError("Google sign-in is not configured on this server")


def build_sms_sender(settings: Settings) -> SmsSender:
    match settings.sms_provider:
        case "console":
            return ConsoleSmsSender()
        case "disabled":
            return DisabledSmsSender()

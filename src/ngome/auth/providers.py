"""Outbound identity providers, kept behind small interfaces so they can be swapped or faked."""

import asyncio
import smtplib
import ssl
from dataclasses import dataclass
from email.message import EmailMessage
from typing import Protocol

from ngome.core.config import Settings
from ngome.core.logging import get_logger

log = get_logger(__name__)


class EmailSender(Protocol):
    async def send(self, to: str, subject: str, text: str) -> None:
        """Deliver a plain-text email to ``to`` or raise."""
        ...


class ConsoleEmailSender:
    """Development-only sender that prints the message instead of sending it.

    Settings validation refuses this provider in production.
    """

    async def send(self, to: str, subject: str, text: str) -> None:
        # Printed, not logged, so the code never reaches log storage.
        print(f"[dev email to {to[:1]}...] {subject}\n{text}", flush=True)  # noqa: T201


class SmtpEmailSender:
    """Sends through any SMTP relay (Brevo, Resend, Amazon SES...) over STARTTLS."""

    def __init__(self, settings: Settings) -> None:
        if (
            settings.smtp_host is None
            or settings.smtp_port is None
            or settings.smtp_timeout_seconds is None
            or settings.email_from is None
        ):
            raise ValueError("SMTP settings are incomplete")
        self._host = settings.smtp_host
        self._port = settings.smtp_port
        self._username = settings.smtp_username
        self._password = settings.smtp_password
        self._sender = settings.email_from
        self._timeout = settings.smtp_timeout_seconds

    async def send(self, to: str, subject: str, text: str) -> None:
        message = EmailMessage()
        message["From"] = self._sender
        message["To"] = to
        message["Subject"] = subject
        message.set_content(text)
        await asyncio.to_thread(self._deliver, message)

    def _deliver(self, message: EmailMessage) -> None:
        with smtplib.SMTP(self._host, self._port, timeout=self._timeout) as smtp:
            smtp.starttls(context=ssl.create_default_context())
            if self._username is not None and self._password is not None:
                smtp.login(self._username, self._password.get_secret_value())
            smtp.send_message(message)


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


def build_email_sender(settings: Settings) -> EmailSender:
    """The API's sender. Migrations and the purge job never send email, so only the API
    needs the wording and provider settings; it refuses to start without them."""
    missing = [
        name for name in ("email_code_subject", "email_code_body") if not getattr(settings, name)
    ]
    if missing:
        raise ValueError(f"{', '.join(missing)} must be set to send sign-in codes")
    match settings.email_provider:
        case "console":
            return ConsoleEmailSender()
        case "smtp":
            return SmtpEmailSender(settings)

"""Structured logging that refuses to carry personal or secret data.

Log calls should only ever pass ids, counts and outcomes. The redaction processor is a
backstop: any event key that looks like a contact, code, token or payload is replaced.
"""

import logging
import sys
from collections.abc import MutableMapping
from typing import Any

import structlog

SENSITIVE_KEYS = frozenset(
    {
        "authorization",
        "body",
        "ciphertext",
        "code",
        "contact",
        "content",
        "email",
        "id_token",
        "message",
        "otp",
        "password",
        "phone",
        "refresh_token",
        "access_token",
        "token",
    }
)
REDACTED = "[redacted]"


def redact_sensitive(
    _logger: Any, _method: str, event_dict: MutableMapping[str, Any]
) -> MutableMapping[str, Any]:
    for key in list(event_dict):
        if key.lower() in SENSITIVE_KEYS:
            event_dict[key] = REDACTED
    return event_dict


def configure_logging(level: str = "INFO", *, json: bool = True) -> None:
    renderer: structlog.typing.Processor = (
        structlog.processors.JSONRenderer() if json else structlog.dev.ConsoleRenderer()
    )
    structlog.configure(
        processors=[
            structlog.contextvars.merge_contextvars,
            structlog.processors.add_log_level,
            structlog.processors.TimeStamper(fmt="iso", utc=True),
            redact_sensitive,
            structlog.processors.format_exc_info,
            renderer,
        ],
        wrapper_class=structlog.make_filtering_bound_logger(logging.getLevelName(level.upper())),
        # No explicit file: structlog then resolves sys.stdout per call, so a swapped stream
        # (as under pytest) is never written to after it closes.
        logger_factory=structlog.PrintLoggerFactory(),
        cache_logger_on_first_use=True,
    )
    logging.basicConfig(level=level.upper(), stream=sys.stdout, format="%(message)s")
    # Uvicorn's access log records client IPs and query strings; we log requests ourselves.
    logging.getLogger("uvicorn.access").disabled = True


def get_logger(name: str) -> structlog.stdlib.BoundLogger:
    return structlog.get_logger(name)  # type: ignore[no-any-return]

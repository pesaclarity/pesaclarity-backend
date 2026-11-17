"""Ed25519 signatures on app status responses.

The app pins the public key, so a server or network that is not ours cannot show a fake
"Please update" screen. The signed bytes are a fixed context string followed by the payload
exactly as sent, so the app never has to re-encode JSON to check them.

Make a key pair with ``uv run ngome-app-status-key``.
"""

import base64
import json
from typing import Any

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

# Separates these signatures from anything else the key could ever sign.
SIGNING_CONTEXT = b"pesaclarity.app-status.v1\n"


class AppStatusSigner:
    def __init__(self, seed: bytes) -> None:
        self._key = Ed25519PrivateKey.from_private_bytes(seed)

    @classmethod
    def from_base64(cls, seed: str) -> "AppStatusSigner":
        return cls(base64.b64decode(seed, validate=True))

    @property
    def public_key_base64(self) -> str:
        raw = self._key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
        return base64.b64encode(raw).decode()

    def envelope(self, payload: dict[str, Any]) -> dict[str, str]:
        """``payload`` as compact JSON in base64, with its signature."""
        data = json.dumps(payload, separators=(",", ":"), sort_keys=True).encode()
        signature = self._key.sign(SIGNING_CONTEXT + data)
        return {
            "alg": "Ed25519",
            "payload": base64.b64encode(data).decode(),
            "signature": base64.b64encode(signature).decode(),
        }


def main() -> None:
    """Print a new seed for the server and its public key for the app."""
    key = Ed25519PrivateKey.generate()
    seed = key.private_bytes_raw()
    signer = AppStatusSigner(seed)
    print("# Server secret (keep it secret; never commit it):")  # noqa: T201
    print(f"NGOME_APP_STATUS_SIGNING_SEED={base64.b64encode(seed).decode()}")  # noqa: T201
    print("# Public key to pin in the app (lib/src/features/app_status/domain/pinned_keys.dart):")  # noqa: T201
    print(signer.public_key_base64)  # noqa: T201

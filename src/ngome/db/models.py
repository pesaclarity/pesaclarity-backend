"""Import every model so ``Base.metadata`` is complete for Alembic and tests."""

from ngome.auth.models import Account, AuthEvent, Device, OtpChallenge, RefreshToken
from ngome.db.base import Base
from ngome.integrity.models import AppAttestChallenge, AppAttestKey
from ngome.vault.models import Backup, BlobDeletion, StoredBlob

__all__ = [
    "Account",
    "AppAttestChallenge",
    "AppAttestKey",
    "AuthEvent",
    "Backup",
    "Base",
    "BlobDeletion",
    "Device",
    "OtpChallenge",
    "RefreshToken",
    "StoredBlob",
]

"""Import every model so ``Base.metadata`` is complete for Alembic and tests."""

from ngome.auth.models import Account, AuthEvent, Device, OtpChallenge, RefreshToken
from ngome.db.base import Base
from ngome.vault.models import Backup

__all__ = ["Account", "AuthEvent", "Backup", "Base", "Device", "OtpChallenge", "RefreshToken"]

"""Import every model so ``Base.metadata`` is complete for Alembic and tests."""

from ngome.admin.models import AdminChallenge, AdminEnrolment, AdminPasskey, AdminSession
from ngome.appstatus.models import AppNotice
from ngome.auth.models import Account, AuthEvent, Device, OtpChallenge, RefreshToken
from ngome.counting.models import CountFlood, CountKey, CountSeen, CountTotal, NoticeReach
from ngome.crashes.models import CrashGroup, CrashGroupDay, CrashReportRow
from ngome.db.base import Base
from ngome.integrity.models import AppAttestChallenge, AppAttestKey
from ngome.privacy.models import PolicyCopy
from ngome.vault.models import Backup, BlobDeletion, StoredBlob

__all__ = [
    "Account",
    "AdminChallenge",
    "AdminEnrolment",
    "AdminPasskey",
    "AdminSession",
    "AppAttestChallenge",
    "AppAttestKey",
    "AppNotice",
    "AuthEvent",
    "Backup",
    "Base",
    "BlobDeletion",
    "CountFlood",
    "CountKey",
    "CountSeen",
    "CountTotal",
    "CrashGroup",
    "CrashGroupDay",
    "CrashReportRow",
    "Device",
    "NoticeReach",
    "OtpChallenge",
    "PolicyCopy",
    "RefreshToken",
    "StoredBlob",
]

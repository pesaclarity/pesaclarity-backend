"""Vault response bodies. Metadata only; ciphertext travels as raw bytes."""

import uuid
from datetime import datetime

from pydantic import BaseModel


class BackupOut(BaseModel):
    id: uuid.UUID
    size_bytes: int
    sha256: str
    created_at: datetime

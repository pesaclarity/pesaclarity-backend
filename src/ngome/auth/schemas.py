"""Request and response bodies for the auth API."""

import uuid
from datetime import datetime

from pydantic import BaseModel, Field

DeviceName = Field(min_length=1, max_length=64, examples=["Tecno Spark 20"])


class PhoneStartRequest(BaseModel):
    phone: str = Field(min_length=6, max_length=20, examples=["0700 000 000"])


class PhoneStartResponse(BaseModel):
    challenge_id: uuid.UUID
    expires_in: int


class PhoneVerifyRequest(BaseModel):
    challenge_id: uuid.UUID
    code: str = Field(pattern=r"^\d{6,8}$")
    device_name: str = DeviceName


class GoogleSignInRequest(BaseModel):
    id_token: str = Field(min_length=1, max_length=4096)
    device_name: str = DeviceName


class RefreshRequest(BaseModel):
    refresh_token: str = Field(min_length=1, max_length=256)


class TokenPair(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"  # noqa: S105
    expires_in: int
    account_id: uuid.UUID
    device_id: uuid.UUID


class DeviceOut(BaseModel):
    id: uuid.UUID
    name: str
    created_at: datetime
    last_seen_at: datetime
    current: bool

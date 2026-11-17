"""Request and response bodies for app status and the admin notice routes."""

import uuid
from datetime import date, datetime
from typing import Literal, Self

from pydantic import AwareDatetime, BaseModel, ConfigDict, Field, model_validator

from ngome.appstatus.versions import MAX_VERSION_LENGTH, VERSION_PATTERN, Version

Build = Literal["play", "foss", "ios", "website"]
Platform = Literal["android", "ios"]
NoticeKind = Literal["update", "info"]
# The owner's rule: the app is blocked only for a bug that makes amounts wrong.
RequiredReason = Literal["amounts_wrong"]

VersionText = Field(default=None, max_length=MAX_VERSION_LENGTH, pattern=VERSION_PATTERN)


class NoticeCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    kind: NoticeKind
    title: str = Field(min_length=1, max_length=80)
    body: str = Field(min_length=1, max_length=500)
    latest_version: str | None = VersionText
    min_version: str | None = VersionText
    required_reason: RequiredReason | None = None
    builds: list[Build] = Field(min_length=1, max_length=4)
    reread_from: date | None = None
    starts_at: AwareDatetime | None = None
    ends_at: AwareDatetime | None = None

    @model_validator(mode="after")
    def _consistent(self) -> Self:
        if self.kind == "update":
            if self.latest_version is None:
                raise ValueError("an update needs latest_version")
            if self.min_version is not None and Version(self.min_version) > Version(
                self.latest_version
            ):
                raise ValueError("min_version cannot be newer than latest_version")
        elif self.latest_version or self.min_version:
            raise ValueError("only an update has versions")
        if self.required_reason is not None and self.min_version is None:
            raise ValueError("required_reason needs min_version")
        if self.starts_at and self.ends_at and self.ends_at <= self.starts_at:
            raise ValueError("ends_at must be after starts_at")
        if len(set(self.builds)) != len(self.builds):
            raise ValueError("builds must not repeat")
        return self


class NoticeOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    kind: str
    title: str
    body: str
    latest_version: str | None
    min_version: str | None
    required_reason: str | None
    builds: list[str]
    reread_from: date | None
    starts_at: datetime
    ends_at: datetime | None
    created_at: datetime
    disabled_at: datetime | None

"""Runtime settings, read from the environment (prefix ``NGOME_``) or a ``.env`` file."""

from functools import lru_cache
from pathlib import Path
from typing import Literal, Self
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

from pydantic import Field, SecretStr, field_validator, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

Environment = Literal["development", "test", "production"]

_MIN_SECRET_LENGTH = 32


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="NGOME_", env_file=".env", extra="ignore")

    environment: Environment = "development"
    log_level: str = "INFO"
    log_json: bool = True

    database_url: str = "postgresql+asyncpg://ngome:ngome@localhost:5432/ngome"

    jwt_secret: SecretStr
    contact_pepper: SecretStr = Field(
        description="HMAC key for sign-in contacts and one-time codes. Rotating it orphans "
        "existing accounts, so treat it as permanent."
    )
    access_token_ttl_seconds: int = Field(default=600, ge=60, le=3600)
    refresh_token_ttl_days: int = Field(default=30, ge=1, le=180)

    default_phone_region: str = "KE"
    otp_length: int = Field(default=6, ge=6, le=8)
    otp_ttl_seconds: int = Field(default=300, ge=60, le=900)
    otp_max_attempts: int = Field(default=5, ge=1, le=10)
    otp_max_per_hour: int = Field(default=5, ge=1, le=20)
    sms_provider: Literal["console"] = "console"

    google_sign_in_enabled: bool = False
    google_client_ids: list[str] = Field(default_factory=list)
    google_token_leeway_seconds: int = Field(default=60, ge=0, le=300)

    # Provisional defaults pending a final decision for the privacy policy.
    # Keep at least an hour of codes: the per-hour rate limit counts them.
    retention_otp_challenge_hours: int = Field(default=24, ge=1, le=24 * 30)
    retention_auth_event_days: int = Field(default=90, ge=1, le=730)

    vault_max_backup_bytes: int = Field(default=64 * 1024 * 1024, ge=1024)
    vault_keep_backups: int = Field(default=10, ge=1, le=100)
    vault_max_account_bytes: int = Field(
        default=256 * 1024 * 1024,
        ge=1024,
        description="Per-account quota: the total size of the backups an account keeps.",
    )
    vault_blob_store: Literal["postgres", "filesystem", "s3"] = Field(
        default="postgres",
        description="Where ciphertext lives. 'postgres' and 'filesystem' suit development and "
        "tests; 's3' is any S3-compatible store (AWS S3, Cloudflare R2, MinIO).",
    )
    vault_fs_root: Path | None = Field(
        default=None, description="Directory for the 'filesystem' blob store."
    )
    vault_s3_bucket: str | None = None
    vault_s3_endpoint_url: str | None = Field(
        default=None, description="Leave unset for AWS; set for R2 or MinIO."
    )
    vault_s3_region: str | None = None
    vault_s3_access_key_id: SecretStr | None = None
    vault_s3_secret_access_key: SecretStr | None = None
    vault_s3_addressing_style: Literal["auto", "virtual", "path"] = "auto"
    vault_s3_part_bytes: int = Field(default=8 * 1024 * 1024, ge=5 * 1024 * 1024)

    @field_validator("database_url")
    @classmethod
    def _asyncpg_url(cls, value: str) -> str:
        """Accept the plain ``postgres://`` URLs that hosts such as Neon hand out."""
        parts = urlsplit(value)
        if parts.scheme not in {"postgres", "postgresql"}:
            return value
        query = dict(parse_qsl(parts.query))
        # asyncpg takes "ssl", not libpq's "sslmode", and has no "channel_binding" option.
        sslmode = query.pop("sslmode", None)
        query.pop("channel_binding", None)
        if sslmode and "ssl" not in query:
            query["ssl"] = sslmode
        return urlunsplit(parts._replace(scheme="postgresql+asyncpg", query=urlencode(query)))

    @model_validator(mode="after")
    def _check_secrets(self) -> Self:
        for name in ("jwt_secret", "contact_pepper"):
            value: SecretStr = getattr(self, name)
            if len(value.get_secret_value()) < _MIN_SECRET_LENGTH:
                raise ValueError(f"{name} must be at least {_MIN_SECRET_LENGTH} characters")
        if self.environment == "production" and self.sms_provider == "console":
            raise ValueError("the console SMS provider prints codes and must not run in production")
        if self.google_sign_in_enabled and not self.google_client_ids:
            raise ValueError("google_client_ids is required when Google sign-in is enabled")
        if self.vault_blob_store == "s3" and not self.vault_s3_bucket:
            raise ValueError("vault_s3_bucket is required when vault_blob_store is 's3'")
        if self.vault_blob_store == "filesystem" and self.vault_fs_root is None:
            raise ValueError("vault_fs_root is required when vault_blob_store is 'filesystem'")
        return self


@lru_cache
def get_settings() -> Settings:
    return Settings()

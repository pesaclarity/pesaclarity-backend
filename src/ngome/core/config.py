"""Runtime settings, read from the environment (prefix ``NGOME_``) or a ``.env`` file."""

from functools import lru_cache
from typing import Literal, Self

from pydantic import Field, SecretStr, model_validator
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

    # Keep at least an hour of codes: the per-hour rate limit counts them.
    retention_otp_challenge_hours: int = Field(default=24, ge=1, le=24 * 30)
    retention_auth_event_days: int = Field(default=90, ge=1, le=730)

    vault_max_backup_bytes: int = Field(default=64 * 1024 * 1024, ge=1024)
    vault_keep_backups: int = Field(default=10, ge=1, le=100)

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
        return self


@lru_cache
def get_settings() -> Settings:
    return Settings()

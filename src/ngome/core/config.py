"""Runtime settings, read from the environment (prefix ``NGOME_``) or a ``.env`` file."""

import base64
import binascii
from functools import lru_cache
from pathlib import Path
from typing import Annotated, Literal, Self
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

from email_validator import EmailNotValidError, validate_email
from pydantic import Field, SecretStr, field_validator, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

Environment = Literal["development", "test", "production"]

_MIN_SECRET_LENGTH = 32
_ED25519_SEED_BYTES = 32
_ORIGIN_PATTERN = r"^https?://[a-z0-9.-]+(:\d+)?$"
_AES_KEY_BYTES = 32


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="NGOME_", env_file=".env", extra="ignore")

    environment: Environment = "development"
    log_level: str = "INFO"
    log_json: bool = True

    database_url: str = "postgresql+asyncpg://ngome:ngome@localhost:5432/ngome"
    migrate_on_start: bool = Field(
        default=False,
        description="Bring the schema up to date before the API takes requests. The "
        "Docker image turns it on, so each new Cloud Run revision migrates as it starts.",
    )
    alembic_config: Path = Field(
        default=Path("alembic.ini"),
        description="The Alembic config the API migrates with, relative to its working directory.",
    )

    jwt_secret: SecretStr
    contact_pepper: SecretStr = Field(
        description="HMAC key for sign-in contacts and one-time codes. Rotating it orphans "
        "existing accounts, so treat it as permanent."
    )
    access_token_ttl_seconds: int = Field(default=600, ge=60, le=3600)
    refresh_token_ttl_days: int = Field(default=30, ge=1, le=180)

    otp_length: int = Field(default=6, ge=6, le=8)
    otp_ttl_seconds: int = Field(default=300, ge=60, le=900)
    otp_max_attempts: int = Field(default=5, ge=1, le=10)
    otp_max_per_hour: int = Field(default=5, ge=1, le=20)
    # "console" prints codes to stdout and is refused in production; "smtp" sends them.
    email_provider: Literal["console", "smtp"] = "console"
    # Sign-in email wording. Placeholders: {code} and {minutes}. Set per deployment.
    email_code_subject: str | None = None
    email_code_body: str | None = None
    email_from: str | None = None
    smtp_host: str | None = None
    smtp_port: int | None = Field(default=None, ge=1, le=65535)
    smtp_username: str | None = None
    smtp_password: SecretStr | None = None
    smtp_timeout_seconds: float | None = Field(default=None, gt=0, le=60)

    # Emailing a copy of the privacy policy. Only text whose SHA-256 is listed is sent, so the
    # endpoint can never be used to mail anything else. Empty turns the feature off.
    privacy_policy_sha256: list[str] = Field(default_factory=list)
    privacy_copy_subject: str = "Your copy of the Pesa Clarity privacy policy"
    privacy_copy_max_per_day: int = Field(default=3, ge=1, le=20)
    privacy_policy_max_bytes: int = Field(default=200_000, ge=1_000, le=2_000_000)

    google_sign_in_enabled: bool = False
    google_client_ids: list[str] = Field(default_factory=list)
    google_token_leeway_seconds: int = Field(default=60, ge=0, le=300)

    # Provisional defaults pending a final decision for the privacy policy.
    # Keep at least an hour of codes: the per-hour rate limit counts them.
    retention_otp_challenge_hours: int = Field(default=24, ge=1, le=24 * 30)
    retention_auth_event_days: int = Field(default=90, ge=1, le=730)

    # Play Integrity (play builds only). Every value is required once it is enabled.
    play_integrity_enabled: bool = False
    play_integrity_package_name: str | None = None
    play_integrity_device_verdict: (
        Literal["MEETS_BASIC_INTEGRITY", "MEETS_DEVICE_INTEGRITY", "MEETS_STRONG_INTEGRITY"] | None
    ) = None
    play_integrity_max_token_age_seconds: int | None = Field(default=None, ge=10, le=3600)
    # Apple App Attest (iPhone builds). ``app_attest_app_id`` is the Apple team id and bundle
    # id, such as ``ABCDE12345.com.pesaclarity.app``; ``development`` accepts keys from Xcode
    # builds, ``production`` from TestFlight and App Store builds.
    app_attest_enabled: bool = False
    app_attest_app_id: str | None = Field(default=None, pattern=r"^[A-Z0-9]{10}\.[A-Za-z0-9.-]+$")
    app_attest_environment: Literal["production", "development"] | None = None
    app_attest_challenge_seconds: int = Field(default=300, ge=30, le=3600)
    # Uploads without a token or assertion: F-Droid builds, and builds that could not attest.
    vault_unattested_uploads: Literal["allow", "reject"] | None = None

    # App status and notices (``GET /v1/app-status``, ``/v1/admin/app-notices``).
    admin_token: SecretStr | None = Field(
        default=None,
        description="Bearer token for the admin routes. Unset turns them off.",
    )
    app_status_signing_seed: SecretStr | None = Field(
        default=None,
        description="Base64 of the 32-byte Ed25519 seed that signs app status responses. "
        "The app pins the matching public key. Unset turns app status off.",
    )
    app_status_cache_seconds: int = Field(default=300, ge=0, le=3600)

    proxy_hops: int = Field(
        default=1,
        ge=0,
        le=5,
        description="Where the caller's address sits in X-Forwarded-For, counted from the "
        "right: 1 on Cloud Run (Google appends it), 2 behind a Google load balancer. 0 uses "
        "the socket's peer. Entries further left are written by the caller and never used.",
    )

    # Counting active installs from the app status check-in (ADR 0024, ``ngome.counting``).
    counting_enabled: bool = Field(
        default=True,
        description="Count the random monthly Count-Token on app status check-ins. Off "
        "ignores the header; the check-in is answered either way.",
    )
    counting_max_new_per_hour: int = Field(
        default=600,
        ge=1,
        le=1_000_000,
        description="Flood ceiling: new tokens counted per hour by one instance. Above it, "
        "tokens are not counted and the hour is marked as a flood on the dashboard.",
    )
    counting_max_per_period: int = Field(
        default=1_000_000,
        ge=1,
        description="Most tokens counted in one day or month, to protect the database.",
    )
    # Country by month, from the DB-IP IP to Country Lite database (CC BY 4.0). Off until the
    # owner has confirmed the licence on db-ip.com; off, every install counts as "Unknown".
    country_lookup_enabled: bool = False
    country_db_path: Path | None = Field(
        default=None,
        description="The DB-IP IP to Country Lite MMDB file, read into memory at start.",
    )

    # Crash reports (``POST /v1/crash-reports``), sent only when the person says yes.
    crash_reports_enabled: bool = True
    crash_reports_max_per_day: int = Field(default=2000, ge=1, le=1_000_000)
    retention_crash_report_days: int = Field(default=90, ge=1, le=365)
    retention_crash_group_days: int = Field(default=365, ge=1, le=3650)
    retention_daily_count_days: int = Field(
        default=395,
        ge=1,
        description="Daily install totals and notice reach (13 months).",
    )

    # The admin dashboard (``/admin``, ADR 0024 and 0025): a username and password, then a
    # second factor. Off until ``admin_origin`` is set, the dashboard's exact origin, such as
    # ``https://api.example.org``; passkeys are bound to its host.
    # ``admin_extra_origins`` are more exact origins serving the same dashboard, as a JSON
    # list (a custom domain beside the run.app address). A passkey is bound to the host it
    # was added on, so each origin needs its own.
    admin_origin: str | None = Field(default=None, pattern=_ORIGIN_PATTERN)
    admin_extra_origins: list[Annotated[str, Field(pattern=_ORIGIN_PATTERN)]] = Field(
        default_factory=list
    )
    admin_email: str | None = Field(
        default=None,
        max_length=254,
        description="The owner's address for admin sign-in codes and security alerts. "
        "Until it and admin_secret_key are set, the dashboard refuses sign-in and says so; "
        "the rest of the server runs as usual.",
    )
    admin_secret_key: SecretStr | None = Field(
        default=None,
        description="Base64 of 32 random bytes that encrypt the authenticator secret "
        "(AES-256-GCM). Needed for dashboard sign-in. Losing it means setting up the "
        "authenticator again (the starter command with reset).",
    )

    @property
    def admin_sign_in_ready(self) -> bool:
        """Whether the dashboard has what sign-in needs: its origin, email and key."""
        return None not in (self.admin_origin, self.admin_email, self.admin_secret_key)

    admin_session_hours: int = Field(default=8, ge=1, le=24)
    admin_idle_minutes: int = Field(default=30, ge=5, le=240)
    admin_reauth_minutes: int = Field(default=10, ge=1, le=60)
    admin_starter_hours: int = Field(default=24, ge=1, le=72)
    admin_pending_minutes: int = Field(default=5, ge=1, le=15)
    # Limits (ADR 0025 §4). A pause doubles with each lockout in 24 hours, up to a day.
    admin_pause_minutes: int = Field(default=15, ge=1, le=240)
    admin_password_max_failures: int = Field(default=5, ge=3, le=50)
    admin_password_known_max_failures: int = Field(default=10, ge=3, le=50)
    admin_address_max_failures: int = Field(default=20, ge=5, le=500)
    admin_code_max_failures: int = Field(default=5, ge=3, le=10)
    admin_user_code_max_failures: int = Field(default=10, ge=3, le=100)
    admin_email_codes_per_day: int = Field(default=10, ge=1, le=50)
    admin_alert_failures_per_hour: int = Field(default=200, ge=10, le=100_000)
    downloads_csv_url: str | None = Field(
        default="https://raw.githubusercontent.com/pesaclarity/.github/stats/stats/downloads.csv",
        description="GitHub's daily download counters, read for the dashboard. Unset hides "
        "the downloads cards.",
    )

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

    @property
    def admin_origins(self) -> tuple[str, ...]:
        """Every origin the dashboard answers on, ``admin_origin`` first; empty when off."""
        if self.admin_origin is None:
            return ()
        return (self.admin_origin, *self.admin_extra_origins)

    @model_validator(mode="after")
    def _check_secrets(self) -> Self:
        for name in ("jwt_secret", "contact_pepper"):
            value: SecretStr = getattr(self, name)
            if len(value.get_secret_value()) < _MIN_SECRET_LENGTH:
                raise ValueError(f"{name} must be at least {_MIN_SECRET_LENGTH} characters")
        if self.environment == "production" and self.email_provider == "console":
            raise ValueError(
                "the console email provider prints codes and must not run in production"
            )
        for name in ("email_code_subject", "email_code_body"):
            template = getattr(self, name)
            if template is None:
                continue
            try:
                template.format(code="000000", minutes=0)
            except (KeyError, IndexError, ValueError) as exc:
                raise ValueError(
                    f"{name} may only use the {{code}} and {{minutes}} placeholders"
                ) from exc
        if self.email_provider == "smtp":
            missing = [
                name
                for name in ("email_from", "smtp_host", "smtp_port", "smtp_timeout_seconds")
                if getattr(self, name) is None
            ]
            if missing:
                raise ValueError(f"{', '.join(missing)} required for the smtp email provider")
        if self.google_sign_in_enabled and not self.google_client_ids:
            raise ValueError("google_client_ids is required when Google sign-in is enabled")
        if self.vault_blob_store == "s3" and not self.vault_s3_bucket:
            raise ValueError("vault_s3_bucket is required when vault_blob_store is 's3'")
        if self.vault_blob_store == "filesystem" and self.vault_fs_root is None:
            raise ValueError("vault_fs_root is required when vault_blob_store is 'filesystem'")
        return self

    @model_validator(mode="after")
    def _check_app_status(self) -> Self:
        if (
            self.admin_token is not None
            and len(self.admin_token.get_secret_value()) < _MIN_SECRET_LENGTH
        ):
            raise ValueError(f"admin_token must be at least {_MIN_SECRET_LENGTH} characters")
        if self.app_status_signing_seed is not None:
            try:
                seed = base64.b64decode(
                    self.app_status_signing_seed.get_secret_value(), validate=True
                )
            except binascii.Error as exc:
                raise ValueError("app_status_signing_seed must be base64") from exc
            if len(seed) != _ED25519_SEED_BYTES:
                raise ValueError("app_status_signing_seed must be 32 bytes, base64-encoded")
        if self.country_lookup_enabled and self.country_db_path is None:
            raise ValueError("country_db_path is required when country_lookup_enabled is on")
        if self.admin_extra_origins and self.admin_origin is None:
            raise ValueError("admin_extra_origins needs admin_origin")
        if self.environment == "production" and any(
            not origin.startswith("https://") for origin in self.admin_origins
        ):
            raise ValueError("admin_origin and admin_extra_origins must be https in production")
        return self

    @model_validator(mode="after")
    def _check_admin(self) -> Self:
        if self.admin_email is not None:
            try:
                validate_email(self.admin_email, check_deliverability=False)
            except EmailNotValidError as exc:
                raise ValueError("admin_email is not a valid email address") from exc
        if self.admin_secret_key is not None:
            try:
                key = base64.b64decode(self.admin_secret_key.get_secret_value(), validate=True)
            except binascii.Error as exc:
                raise ValueError("admin_secret_key must be base64") from exc
            if len(key) != _AES_KEY_BYTES:
                raise ValueError("admin_secret_key must be 32 bytes, base64-encoded")
        return self

    @model_validator(mode="after")
    def _check_play_integrity(self) -> Self:
        if self.play_integrity_enabled:
            missing = [
                name
                for name in (
                    "play_integrity_package_name",
                    "play_integrity_device_verdict",
                    "play_integrity_max_token_age_seconds",
                    "vault_unattested_uploads",
                )
                if getattr(self, name) is None
            ]
            if missing:
                raise ValueError(f"{', '.join(missing)} required when Play Integrity is enabled")
        return self

    @model_validator(mode="after")
    def _check_app_attest(self) -> Self:
        if self.app_attest_enabled:
            missing = [
                name
                for name in (
                    "app_attest_app_id",
                    "app_attest_environment",
                    "vault_unattested_uploads",
                )
                if getattr(self, name) is None
            ]
            if missing:
                raise ValueError(f"{', '.join(missing)} required when App Attest is enabled")
        return self


@lru_cache
def get_settings() -> Settings:
    return Settings()

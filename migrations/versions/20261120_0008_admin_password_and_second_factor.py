"""admin sign-in with a password and a second factor (ADR 0025)

Passkey-only sign-in ends: every admin session and open passkey ceremony is deleted, and the
token-only enrolment links go. The owner's passkeys stay, as optional second factors.

Revision ID: 0008
Revises: 0007
Create Date: 2026-11-20 09:00:00.000000
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0008"
down_revision: str | None = "0007"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "admin_devices",
        sa.Column("id_hash", sa.String(length=64), nullable=False),
        sa.Column("first_seen_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_seen_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("id_hash", name=op.f("pk_admin_devices")),
    )
    op.create_index(
        op.f("ix_admin_devices_last_seen_at"), "admin_devices", ["last_seen_at"], unique=False
    )
    op.create_table(
        "admin_email_codes",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("owner_hash", sa.String(length=64), nullable=False),
        sa.Column("code_hash", sa.String(length=64), nullable=False),
        sa.Column("attempts", sa.Integer(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("consumed_at", sa.DateTime(timezone=True), nullable=True),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_admin_email_codes")),
    )
    op.create_index(
        op.f("ix_admin_email_codes_created_at"), "admin_email_codes", ["created_at"], unique=False
    )
    op.create_index(
        op.f("ix_admin_email_codes_expires_at"), "admin_email_codes", ["expires_at"], unique=False
    )
    op.create_index(
        op.f("ix_admin_email_codes_owner_hash"), "admin_email_codes", ["owner_hash"], unique=False
    )
    op.create_table(
        "admin_events",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("kind", sa.String(length=32), nullable=False),
        sa.Column("ok", sa.Boolean(), nullable=False),
        sa.Column("factor", sa.String(length=16), nullable=True),
        sa.Column("address_hash", sa.String(length=16), nullable=True),
        sa.Column("country", sa.String(length=2), nullable=True),
        sa.Column("browser", sa.String(length=48), nullable=False),
        sa.Column("known_browser", sa.Boolean(), nullable=False),
        sa.Column("note", sa.String(length=64), nullable=False),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_admin_events")),
    )
    op.create_index(op.f("ix_admin_events_at"), "admin_events", ["at"], unique=False)
    op.create_table(
        "admin_pending",
        sa.Column("id_hash", sa.String(length=64), nullable=False),
        sa.Column("user_id", sa.Uuid(), nullable=False),
        sa.Column("starter", sa.Boolean(), nullable=False),
        sa.Column("failures", sa.Integer(), nullable=False),
        sa.Column("email_sends", sa.Integer(), nullable=False),
        sa.Column("last_send_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("id_hash", name=op.f("pk_admin_pending")),
    )
    op.create_index(
        op.f("ix_admin_pending_expires_at"), "admin_pending", ["expires_at"], unique=False
    )
    op.create_table(
        "admin_recovery_codes",
        sa.Column("code_hash", sa.String(length=64), nullable=False),
        sa.Column("user_id", sa.Uuid(), nullable=False),
        sa.Column("used_at", sa.DateTime(timezone=True), nullable=True),
        sa.PrimaryKeyConstraint("code_hash", name=op.f("pk_admin_recovery_codes")),
    )
    op.create_index(
        op.f("ix_admin_recovery_codes_user_id"), "admin_recovery_codes", ["user_id"], unique=False
    )
    op.create_table(
        "admin_throttle",
        sa.Column("bucket", sa.String(length=64), nullable=False),
        sa.Column("failures", sa.Integer(), nullable=False),
        sa.Column("window_start", sa.DateTime(timezone=True), nullable=False),
        sa.Column("locked_until", sa.DateTime(timezone=True), nullable=True),
        sa.Column("lockouts", sa.Integer(), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("bucket", name=op.f("pk_admin_throttle")),
    )
    op.create_index(
        op.f("ix_admin_throttle_updated_at"), "admin_throttle", ["updated_at"], unique=False
    )
    op.create_table(
        "admin_users",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("username", sa.String(length=32), nullable=False),
        sa.Column("password_hash", sa.String(length=255), nullable=False),
        sa.Column("password_temporary", sa.Boolean(), nullable=False),
        sa.Column("temporary_until", sa.DateTime(timezone=True), nullable=True),
        sa.Column("password_changed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("totp_secret", sa.LargeBinary(length=64), nullable=True),
        sa.Column("totp_nonce", sa.LargeBinary(length=12), nullable=True),
        sa.Column("totp_last_step", sa.Integer(), nullable=False),
        sa.Column("totp_added_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("totp_used_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("totp_pending", sa.LargeBinary(length=64), nullable=True),
        sa.Column("totp_pending_nonce", sa.LargeBinary(length=12), nullable=True),
        sa.Column("recovery_made_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_admin_users")),
        sa.UniqueConstraint("username", name=op.f("uq_admin_users_username")),
    )
    op.drop_index(op.f("ix_admin_enrolments_expires_at"), table_name="admin_enrolments")
    op.drop_table("admin_enrolments")
    op.execute("DELETE FROM admin_challenges")
    op.execute("DELETE FROM admin_sessions")
    op.add_column("admin_challenges", sa.Column("owner_hash", sa.String(length=64), nullable=True))
    op.drop_column("admin_challenges", "enrolment_hash")
    op.add_column("admin_sessions", sa.Column("user_id", sa.Uuid(), nullable=False))
    op.add_column("admin_sessions", sa.Column("stage", sa.String(length=16), nullable=False))
    op.add_column("admin_sessions", sa.Column("factor", sa.String(length=16), nullable=False))
    op.add_column("admin_sessions", sa.Column("device_hash", sa.String(length=64), nullable=True))
    op.add_column("admin_sessions", sa.Column("browser", sa.String(length=48), nullable=False))
    op.add_column("admin_sessions", sa.Column("country", sa.String(length=2), nullable=True))
    op.add_column(
        "admin_sessions", sa.Column("last_seen_at", sa.DateTime(timezone=True), nullable=False)
    )
    op.add_column(
        "admin_sessions", sa.Column("reauth_until", sa.DateTime(timezone=True), nullable=True)
    )
    op.add_column("admin_sessions", sa.Column("reauth_factor", sa.String(length=16), nullable=True))
    op.create_index(op.f("ix_admin_sessions_user_id"), "admin_sessions", ["user_id"], unique=False)
    op.drop_column("admin_sessions", "passkey_id")


def downgrade() -> None:
    op.execute("DELETE FROM admin_sessions")
    op.add_column(
        "admin_sessions", sa.Column("passkey_id", sa.UUID(), autoincrement=False, nullable=False)
    )
    op.drop_index(op.f("ix_admin_sessions_user_id"), table_name="admin_sessions")
    op.drop_column("admin_sessions", "reauth_factor")
    op.drop_column("admin_sessions", "reauth_until")
    op.drop_column("admin_sessions", "last_seen_at")
    op.drop_column("admin_sessions", "country")
    op.drop_column("admin_sessions", "browser")
    op.drop_column("admin_sessions", "device_hash")
    op.drop_column("admin_sessions", "factor")
    op.drop_column("admin_sessions", "stage")
    op.drop_column("admin_sessions", "user_id")
    op.add_column(
        "admin_challenges",
        sa.Column("enrolment_hash", sa.VARCHAR(length=64), autoincrement=False, nullable=True),
    )
    op.drop_column("admin_challenges", "owner_hash")
    op.create_table(
        "admin_enrolments",
        sa.Column("token_hash", sa.VARCHAR(length=64), autoincrement=False, nullable=False),
        sa.Column("label", sa.VARCHAR(length=64), autoincrement=False, nullable=False),
        sa.Column(
            "expires_at", postgresql.TIMESTAMP(timezone=True), autoincrement=False, nullable=False
        ),
        sa.Column(
            "used_at", postgresql.TIMESTAMP(timezone=True), autoincrement=False, nullable=True
        ),
        sa.PrimaryKeyConstraint("token_hash", name=op.f("pk_admin_enrolments")),
    )
    op.create_index(
        op.f("ix_admin_enrolments_expires_at"), "admin_enrolments", ["expires_at"], unique=False
    )
    op.drop_table("admin_users")
    op.drop_index(op.f("ix_admin_throttle_updated_at"), table_name="admin_throttle")
    op.drop_table("admin_throttle")
    op.drop_index(op.f("ix_admin_recovery_codes_user_id"), table_name="admin_recovery_codes")
    op.drop_table("admin_recovery_codes")
    op.drop_index(op.f("ix_admin_pending_expires_at"), table_name="admin_pending")
    op.drop_table("admin_pending")
    op.drop_index(op.f("ix_admin_events_at"), table_name="admin_events")
    op.drop_table("admin_events")
    op.drop_index(op.f("ix_admin_email_codes_owner_hash"), table_name="admin_email_codes")
    op.drop_index(op.f("ix_admin_email_codes_expires_at"), table_name="admin_email_codes")
    op.drop_index(op.f("ix_admin_email_codes_created_at"), table_name="admin_email_codes")
    op.drop_table("admin_email_codes")
    op.drop_index(op.f("ix_admin_devices_last_seen_at"), table_name="admin_devices")
    op.drop_table("admin_devices")

"""counting, crash reports and admin passkeys (ADR 0024)

Revision ID: 0007
Revises: 0006
Create Date: 2026-11-19 12:00:00.000000
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0007"
down_revision: str | None = "0006"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "admin_challenges",
        sa.Column("id_hash", sa.String(length=64), nullable=False),
        sa.Column("purpose", sa.String(length=16), nullable=False),
        sa.Column("challenge", sa.LargeBinary(length=64), nullable=False),
        sa.Column("enrolment_hash", sa.String(length=64), nullable=True),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("id_hash", name=op.f("pk_admin_challenges")),
    )
    op.create_index(
        op.f("ix_admin_challenges_expires_at"), "admin_challenges", ["expires_at"], unique=False
    )
    op.create_table(
        "admin_enrolments",
        sa.Column("token_hash", sa.String(length=64), nullable=False),
        sa.Column("label", sa.String(length=64), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("used_at", sa.DateTime(timezone=True), nullable=True),
        sa.PrimaryKeyConstraint("token_hash", name=op.f("pk_admin_enrolments")),
    )
    op.create_index(
        op.f("ix_admin_enrolments_expires_at"), "admin_enrolments", ["expires_at"], unique=False
    )
    op.create_table(
        "admin_passkeys",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("credential_id", sa.LargeBinary(length=1023), nullable=False),
        sa.Column("public_key", sa.LargeBinary(length=2048), nullable=False),
        sa.Column("sign_count", sa.Integer(), nullable=False),
        sa.Column("label", sa.String(length=64), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_used_at", sa.DateTime(timezone=True), nullable=True),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_admin_passkeys")),
        sa.UniqueConstraint("credential_id", name=op.f("uq_admin_passkeys_credential_id")),
    )
    op.create_table(
        "admin_sessions",
        sa.Column("id_hash", sa.String(length=64), nullable=False),
        sa.Column("passkey_id", sa.Uuid(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("id_hash", name=op.f("pk_admin_sessions")),
    )
    op.create_index(
        op.f("ix_admin_sessions_expires_at"), "admin_sessions", ["expires_at"], unique=False
    )
    op.create_table(
        "count_floods",
        sa.Column("hour", sa.DateTime(timezone=True), nullable=False),
        sa.Column("dropped", sa.Integer(), nullable=False),
        sa.PrimaryKeyConstraint("hour", name=op.f("pk_count_floods")),
    )
    op.create_table(
        "count_keys",
        sa.Column("kind", sa.String(length=8), nullable=False),
        sa.Column("period", sa.Date(), nullable=False),
        sa.Column("key", sa.LargeBinary(length=32), nullable=False),
        sa.PrimaryKeyConstraint("kind", "period", name=op.f("pk_count_keys")),
    )
    op.create_table(
        "count_seen",
        sa.Column("kind", sa.String(length=8), nullable=False),
        sa.Column("period", sa.Date(), nullable=False),
        sa.Column("digest", sa.LargeBinary(length=16), nullable=False),
        sa.PrimaryKeyConstraint("kind", "period", "digest", name=op.f("pk_count_seen")),
    )
    op.create_table(
        "count_totals",
        sa.Column("kind", sa.String(length=8), nullable=False),
        sa.Column("period", sa.Date(), nullable=False),
        sa.Column("dimension", sa.String(length=16), nullable=False),
        sa.Column("value", sa.String(length=64), nullable=False),
        sa.Column("n", sa.Integer(), nullable=False),
        sa.PrimaryKeyConstraint(
            "kind", "period", "dimension", "value", name=op.f("pk_count_totals")
        ),
    )
    op.create_table(
        "crash_groups",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("fingerprint", sa.String(length=64), nullable=False),
        sa.Column("error", sa.String(length=32), nullable=False),
        sa.Column("frames", sa.JSON(), nullable=False),
        sa.Column("decoded_function", sa.String(length=160), nullable=True),
        sa.Column("decoded_location", sa.String(length=160), nullable=True),
        sa.Column("first_seen", sa.Date(), nullable=False),
        sa.Column("last_seen", sa.Date(), nullable=False),
        sa.Column("reports", sa.Integer(), nullable=False),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_crash_groups")),
        sa.UniqueConstraint("fingerprint", name=op.f("uq_crash_groups_fingerprint")),
    )
    op.create_index(op.f("ix_crash_groups_last_seen"), "crash_groups", ["last_seen"], unique=False)
    op.create_table(
        "crash_group_days",
        sa.Column("group_id", sa.Uuid(), nullable=False),
        sa.Column("day", sa.Date(), nullable=False),
        sa.Column("n", sa.Integer(), nullable=False),
        sa.ForeignKeyConstraint(
            ["group_id"],
            ["crash_groups.id"],
            name=op.f("fk_crash_group_days_group_id_crash_groups"),
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("group_id", "day", name=op.f("pk_crash_group_days")),
    )
    op.create_index(op.f("ix_crash_group_days_day"), "crash_group_days", ["day"], unique=False)
    op.create_table(
        "crash_reports",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("group_id", sa.Uuid(), nullable=False),
        sa.Column("received_on", sa.Date(), nullable=False),
        sa.Column("app", sa.String(length=64), nullable=False),
        sa.Column("build_number", sa.Integer(), nullable=False),
        sa.Column("build", sa.String(length=16), nullable=False),
        sa.Column("os", sa.String(length=16), nullable=False),
        sa.Column("cpu", sa.String(length=16), nullable=False),
        sa.Column("error", sa.String(length=32), nullable=False),
        sa.Column("build_id", sa.String(length=64), nullable=True),
        sa.Column("stack", sa.JSON(), nullable=False),
        sa.Column("decoded", sa.Boolean(), nullable=False),
        sa.ForeignKeyConstraint(
            ["group_id"],
            ["crash_groups.id"],
            name=op.f("fk_crash_reports_group_id_crash_groups"),
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_crash_reports")),
    )
    op.create_index(op.f("ix_crash_reports_group_id"), "crash_reports", ["group_id"], unique=False)
    op.create_index(
        op.f("ix_crash_reports_received_on"), "crash_reports", ["received_on"], unique=False
    )
    op.create_table(
        "notice_reach",
        sa.Column("notice_id", sa.Uuid(), nullable=False),
        sa.Column("day", sa.Date(), nullable=False),
        sa.Column("n", sa.Integer(), nullable=False),
        sa.ForeignKeyConstraint(
            ["notice_id"],
            ["app_notices.id"],
            name=op.f("fk_notice_reach_notice_id_app_notices"),
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("notice_id", "day", name=op.f("pk_notice_reach")),
    )


def downgrade() -> None:
    op.drop_table("notice_reach")
    op.drop_index(op.f("ix_crash_reports_received_on"), table_name="crash_reports")
    op.drop_index(op.f("ix_crash_reports_group_id"), table_name="crash_reports")
    op.drop_table("crash_reports")
    op.drop_index(op.f("ix_crash_group_days_day"), table_name="crash_group_days")
    op.drop_table("crash_group_days")
    op.drop_index(op.f("ix_crash_groups_last_seen"), table_name="crash_groups")
    op.drop_table("crash_groups")
    op.drop_table("count_totals")
    op.drop_table("count_seen")
    op.drop_table("count_keys")
    op.drop_table("count_floods")
    op.drop_index(op.f("ix_admin_sessions_expires_at"), table_name="admin_sessions")
    op.drop_table("admin_sessions")
    op.drop_table("admin_passkeys")
    op.drop_index(op.f("ix_admin_enrolments_expires_at"), table_name="admin_enrolments")
    op.drop_table("admin_enrolments")
    op.drop_index(op.f("ix_admin_challenges_expires_at"), table_name="admin_challenges")
    op.drop_table("admin_challenges")

"""Add MFA settings and challenges."""

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision: str = "20250310_add_mfa"
down_revision: Union[str, None] = "20250301_auth_settings_split"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column(
        "auth_tenant_settings",
        sa.Column("mfa_sms_enabled", sa.Boolean(), nullable=False, server_default=sa.text("true")),
    )
    op.add_column(
        "auth_tenant_settings",
        sa.Column("mfa_required_for_all", sa.Boolean(), nullable=False, server_default=sa.text("false")),
    )
    op.add_column(
        "auth_tenant_settings",
        sa.Column("mfa_required_for_admins", sa.Boolean(), nullable=False, server_default=sa.text("false")),
    )

    op.add_column(
        "users",
        sa.Column("mfa_enabled", sa.Boolean(), nullable=False, server_default=sa.text("false")),
    )
    op.add_column(
        "users",
        sa.Column("mfa_phone_e164", sa.String(length=20), nullable=True),
    )
    op.add_column(
        "users",
        sa.Column("mfa_phone_verified_at", sa.DateTime(), nullable=True),
    )
    op.add_column(
        "users",
        sa.Column("mfa_method", sa.String(length=20), nullable=True, server_default="sms"),
    )
    op.add_column(
        "users",
        sa.Column("mfa_enforced_by_policy", sa.Boolean(), nullable=False, server_default=sa.text("false")),
    )

    op.create_table(
        "mfa_challenges",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("organization_id", sa.Integer(), nullable=False),
        sa.Column("user_id", sa.Integer(), nullable=False),
        sa.Column("purpose", sa.String(length=20), nullable=False),
        sa.Column("channel", sa.String(length=20), nullable=False, server_default="sms"),
        sa.Column("destination_hash", sa.String(length=64), nullable=False),
        sa.Column("code_hash", sa.String(length=255), nullable=False),
        sa.Column("salt", sa.String(length=64), nullable=False),
        sa.Column("expires_at", sa.DateTime(), nullable=False),
        sa.Column("used_at", sa.DateTime(), nullable=True),
        sa.Column("attempt_count", sa.Integer(), nullable=False, server_default=sa.text("0")),
        sa.Column("max_attempts", sa.Integer(), nullable=False, server_default=sa.text("5")),
        sa.Column("resend_count", sa.Integer(), nullable=False, server_default=sa.text("0")),
        sa.Column("last_sent_at", sa.DateTime(), nullable=True),
        sa.Column("created_ip", sa.String(length=64), nullable=True),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.Column("updated_at", sa.DateTime(), nullable=False),
        sa.ForeignKeyConstraint(["organization_id"], ["organizations.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["user_id"], ["users.id"], ondelete="CASCADE"),
    )
    op.create_index("ix_mfa_challenges_user_expires", "mfa_challenges", ["user_id", "expires_at"])
    op.create_index("ix_mfa_challenges_user_used", "mfa_challenges", ["user_id", "used_at"])


def downgrade() -> None:
    op.drop_index("ix_mfa_challenges_user_used", table_name="mfa_challenges")
    op.drop_index("ix_mfa_challenges_user_expires", table_name="mfa_challenges")
    op.drop_table("mfa_challenges")

    op.drop_column("users", "mfa_enforced_by_policy")
    op.drop_column("users", "mfa_method")
    op.drop_column("users", "mfa_phone_verified_at")
    op.drop_column("users", "mfa_phone_e164")
    op.drop_column("users", "mfa_enabled")

    op.drop_column("auth_tenant_settings", "mfa_required_for_admins")
    op.drop_column("auth_tenant_settings", "mfa_required_for_all")
    op.drop_column("auth_tenant_settings", "mfa_sms_enabled")

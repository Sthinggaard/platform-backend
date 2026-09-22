"""Split auth settings out of organizations."""

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision: str = "20250301_auth_settings_split"
down_revision: Union[str, None] = "20250215_auth_setup"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "auth_tenant_settings",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("organization_id", sa.Integer(), nullable=False),
        sa.Column(
            "domain_allowlist",
            postgresql.ARRAY(sa.String()),
            nullable=False,
            server_default=sa.text("ARRAY[]::text[]"),
        ),
        sa.Column("local_login_enabled", sa.Boolean(), nullable=False, server_default=sa.text("true")),
        sa.Column("sso_google_enabled", sa.Boolean(), nullable=False, server_default=sa.text("false")),
        sa.Column("sso_ms_enabled", sa.Boolean(), nullable=False, server_default=sa.text("false")),
        sa.Column("sso_required", sa.Boolean(), nullable=False, server_default=sa.text("false")),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.Column("updated_at", sa.DateTime(), nullable=False),
        sa.ForeignKeyConstraint(["organization_id"], ["organizations.id"], ondelete="CASCADE"),
        sa.UniqueConstraint("organization_id", name="ux_auth_tenant_settings_org"),
    )
    op.create_index(
        "ix_auth_tenant_settings_org_id",
        "auth_tenant_settings",
        ["organization_id"],
        unique=True,
    )

    op.create_table(
        "auth_ms_tenant_allowlist",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("auth_settings_id", sa.Integer(), nullable=False),
        sa.Column("tenant_id", sa.String(length=255), nullable=False),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.ForeignKeyConstraint(["auth_settings_id"], ["auth_tenant_settings.id"], ondelete="CASCADE"),
    )
    op.create_index(
        "ix_auth_ms_tenant_allowlist_settings_tenant",
        "auth_ms_tenant_allowlist",
        ["auth_settings_id", "tenant_id"],
        unique=True,
    )

    op.create_table(
        "auth_ms_group_roles",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("auth_settings_id", sa.Integer(), nullable=False),
        sa.Column("group_id", sa.String(length=255), nullable=False),
        sa.Column("role", sa.String(length=50), nullable=False),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.ForeignKeyConstraint(["auth_settings_id"], ["auth_tenant_settings.id"], ondelete="CASCADE"),
    )
    op.create_index(
        "ix_auth_ms_group_roles_settings_group",
        "auth_ms_group_roles",
        ["auth_settings_id", "group_id"],
        unique=True,
    )

    op.execute(
        "INSERT INTO auth_tenant_settings "
        "(organization_id, domain_allowlist, local_login_enabled, sso_google_enabled, "
        "sso_ms_enabled, sso_required, created_at, updated_at) "
        "SELECT id, domain_allowlist, local_login_enabled, sso_google_enabled, "
        "sso_ms_enabled, sso_required, NOW(), NOW() FROM organizations"
    )

    op.drop_column("organizations", "sso_required")
    op.drop_column("organizations", "sso_ms_enabled")
    op.drop_column("organizations", "sso_google_enabled")
    op.drop_column("organizations", "local_login_enabled")
    op.drop_column("organizations", "domain_allowlist")


def downgrade() -> None:
    op.add_column(
        "organizations",
        sa.Column(
            "domain_allowlist",
            postgresql.ARRAY(sa.String()),
            nullable=False,
            server_default=sa.text("ARRAY[]::text[]"),
        ),
    )
    op.add_column(
        "organizations",
        sa.Column("local_login_enabled", sa.Boolean(), nullable=False, server_default=sa.text("true")),
    )
    op.add_column(
        "organizations",
        sa.Column("sso_google_enabled", sa.Boolean(), nullable=False, server_default=sa.text("false")),
    )
    op.add_column(
        "organizations",
        sa.Column("sso_ms_enabled", sa.Boolean(), nullable=False, server_default=sa.text("false")),
    )
    op.add_column(
        "organizations",
        sa.Column("sso_required", sa.Boolean(), nullable=False, server_default=sa.text("false")),
    )

    op.execute(
        "UPDATE organizations "
        "SET domain_allowlist = settings.domain_allowlist, "
        "local_login_enabled = settings.local_login_enabled, "
        "sso_google_enabled = settings.sso_google_enabled, "
        "sso_ms_enabled = settings.sso_ms_enabled, "
        "sso_required = settings.sso_required "
        "FROM auth_tenant_settings AS settings "
        "WHERE organizations.id = settings.organization_id"
    )

    op.drop_index("ix_auth_ms_group_roles_settings_group", table_name="auth_ms_group_roles")
    op.drop_table("auth_ms_group_roles")

    op.drop_index("ix_auth_ms_tenant_allowlist_settings_tenant", table_name="auth_ms_tenant_allowlist")
    op.drop_table("auth_ms_tenant_allowlist")

    op.drop_index("ix_auth_tenant_settings_org_id", table_name="auth_tenant_settings")
    op.drop_table("auth_tenant_settings")

"""Add onboarding session, compliance profile, and roadmap item tables."""

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql


# revision identifiers, used by Alembic.
revision = "20241211_add_onboarding_models"
down_revision = "0001_baseline"
branch_labels = None
depends_on = None


onboarding_status_enum = postgresql.ENUM(
    "draft", "in_progress", "completed", "failed", name="onboardingstatus", create_type=False
)


def upgrade() -> None:
    # Create enums (idempotent)
    op.execute(
        """
        DO $$
        BEGIN
            IF NOT EXISTS (
                SELECT 1 FROM pg_type t
                JOIN pg_namespace n ON n.oid = t.typnamespace
                WHERE t.typname = 'onboardingstatus'
            ) THEN
                CREATE TYPE onboardingstatus AS ENUM ('draft', 'in_progress', 'completed', 'failed');
            END IF;
        END$$;
        """
    )

    op.create_table(
        "onboarding_sessions",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("organization_id", sa.Integer(), nullable=False, index=True),
        sa.Column("status", onboarding_status_enum, nullable=False, server_default="draft"),
        sa.Column("current_step", sa.String(length=50), nullable=True),
        sa.Column("created_by_user_id", sa.Integer(), nullable=True),
        sa.Column("completed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("responses", sa.JSON(), nullable=True),
        sa.Column("ai_summary", sa.JSON(), nullable=True),
        sa.Column("notes", sa.Text(), nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.func.now(),
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.func.now(),
        ),
        sa.ForeignKeyConstraint(["organization_id"], ["organizations.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["created_by_user_id"], ["users.id"], ondelete="SET NULL"),
    )
    op.create_index(
        "ix_onboarding_sessions_org_status",
        "onboarding_sessions",
        ["organization_id", "status"],
    )

    op.create_table(
        "compliance_profiles",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("organization_id", sa.Integer(), nullable=False, index=True),
        sa.Column("onboarding_session_id", sa.Integer(), nullable=False, unique=True),
        sa.Column("frameworks", sa.JSON(), nullable=True),
        sa.Column("data_types", sa.JSON(), nullable=True),
        sa.Column("regions", sa.JSON(), nullable=True),
        sa.Column("cloud_providers", sa.JSON(), nullable=True),
        sa.Column("critical_assets", sa.JSON(), nullable=True),
        sa.Column("risk_tolerance", sa.String(length=50), nullable=True),
        sa.Column("additional_requirements", sa.JSON(), nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.func.now(),
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.func.now(),
        ),
        sa.ForeignKeyConstraint(["organization_id"], ["organizations.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(
            ["onboarding_session_id"], ["onboarding_sessions.id"], ondelete="CASCADE"
        ),
    )
    op.create_index(
        "ix_compliance_profiles_org_session",
        "compliance_profiles",
        ["organization_id", "onboarding_session_id"],
    )

    op.create_table(
        "onboarding_roadmap_items",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("organization_id", sa.Integer(), nullable=False, index=True),
        sa.Column("onboarding_session_id", sa.Integer(), nullable=False, index=True),
        sa.Column("title", sa.String(length=200), nullable=False),
        sa.Column("description", sa.Text(), nullable=True),
        sa.Column("category", sa.String(length=50), nullable=True),
        sa.Column("severity", sa.Enum("critical", "high", "medium", "low", "info", name="severitylevel"), nullable=True),
        sa.Column("priority_rank", sa.Integer(), nullable=False, server_default="1"),
        sa.Column("status", sa.String(length=50), nullable=False, server_default="pending"),
        sa.Column("context", sa.JSON(), nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.func.now(),
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.func.now(),
        ),
        sa.ForeignKeyConstraint(["organization_id"], ["organizations.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(
            ["onboarding_session_id"], ["onboarding_sessions.id"], ondelete="CASCADE"
        ),
    )
    op.create_index(
        "ix_onboarding_roadmap_items_org_session",
        "onboarding_roadmap_items",
        ["organization_id", "onboarding_session_id"],
    )

    op.create_table(
        "connector_requests",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("organization_id", sa.Integer(), nullable=False, index=True),
        sa.Column("onboarding_session_id", sa.Integer(), nullable=False, index=True),
        sa.Column("connector_type", sa.String(length=50), nullable=False),
        sa.Column("credential_name", sa.String(length=200), nullable=True),
        sa.Column("status", sa.String(length=50), nullable=False, server_default="pending"),
        sa.Column("encrypted_credentials", sa.Text(), nullable=True),
        sa.Column("encryption_key_id", sa.String(length=100), nullable=True),
        sa.Column("scope", sa.JSON(), nullable=True),
        sa.Column("metadata_json", sa.JSON(), nullable=True),
        sa.Column("validation_status", sa.String(length=50), nullable=True),
        sa.Column("last_validated_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.func.now(),
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.func.now(),
        ),
        sa.ForeignKeyConstraint(["organization_id"], ["organizations.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(
            ["onboarding_session_id"], ["onboarding_sessions.id"], ondelete="CASCADE"
        ),
    )
    op.create_index(
        "ix_connector_requests_org_session",
        "connector_requests",
        ["organization_id", "onboarding_session_id"],
    )


def downgrade() -> None:
    op.drop_index("ix_connector_requests_org_session", table_name="connector_requests")
    op.drop_table("connector_requests")

    op.drop_index("ix_onboarding_roadmap_items_org_session", table_name="onboarding_roadmap_items")
    op.drop_table("onboarding_roadmap_items")

    op.drop_index("ix_compliance_profiles_org_session", table_name="compliance_profiles")
    op.drop_table("compliance_profiles")

    op.drop_index("ix_onboarding_sessions_org_status", table_name="onboarding_sessions")
    op.drop_table("onboarding_sessions")

    onboarding_status_enum.drop(op.get_bind(), checkfirst=True)

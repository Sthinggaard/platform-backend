"""UC-6 onboarding expansion: new entities and state machine."""

from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision = "20241212_uc6_onboarding"
down_revision = "20241211_add_onboarding_models"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # Expand onboardingstatus enum with UC-6 states
    for value in [
        "created",
        "collecting_profile",
        "collecting_compliance",
        "collecting_assets",
        "generating_docs",
        "activating_scans",
    ]:
        op.execute(f"ALTER TYPE onboardingstatus ADD VALUE IF NOT EXISTS '{value}'")

    op.add_column(
        "onboarding_sessions",
        sa.Column("ai_conversation_id", sa.String(length=100), nullable=True),
    )

    # Org profile captured during onboarding
    op.create_table(
        "org_profiles",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("organization_id", sa.Integer(), nullable=False, index=True),
        sa.Column("onboarding_session_id", sa.Integer(), nullable=False, unique=True),
        sa.Column("company_size", sa.String(length=50), nullable=True),
        sa.Column("industry", sa.String(length=100), nullable=True),
        sa.Column("locations", sa.JSON(), nullable=True),
        sa.Column("critical_services", sa.JSON(), nullable=True),
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
        "ix_org_profiles_org_session",
        "org_profiles",
        ["organization_id", "onboarding_session_id"],
    )

    # Architecture assets discovered or declared during onboarding
    op.create_table(
        "architecture_assets",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("organization_id", sa.Integer(), nullable=False, index=True),
        sa.Column("onboarding_session_id", sa.Integer(), nullable=False, index=True),
        sa.Column("asset_type", sa.String(length=50), nullable=False),
        sa.Column("provider", sa.String(length=50), nullable=True),
        sa.Column("identifier", sa.String(length=255), nullable=False),
        sa.Column("classification", sa.String(length=50), nullable=True),
        sa.Column("is_critical", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("metadata_json", sa.JSON(), nullable=True),
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
        "ix_architecture_assets_org_session",
        "architecture_assets",
        ["organization_id", "onboarding_session_id"],
    )

    # Secure integration credentials gathered during onboarding
    op.create_table(
        "integration_credentials",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("organization_id", sa.Integer(), nullable=False, index=True),
        sa.Column("onboarding_session_id", sa.Integer(), nullable=False, index=True),
        sa.Column("provider", sa.String(length=50), nullable=False),
        sa.Column("credential_type", sa.String(length=50), nullable=False),
        sa.Column("encrypted_secret", sa.Text(), nullable=True),
        sa.Column("encryption_key_id", sa.String(length=100), nullable=True),
        sa.Column("status", sa.String(length=50), nullable=False, server_default="pending"),
        sa.Column("validation_details", sa.JSON(), nullable=True),
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
        "ix_integration_credentials_org_session",
        "integration_credentials",
        ["organization_id", "onboarding_session_id"],
    )

    # Generated documents from onboarding AI/doc pipeline
    op.create_table(
        "generated_documents",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("organization_id", sa.Integer(), nullable=False, index=True),
        sa.Column("onboarding_session_id", sa.Integer(), nullable=False, index=True),
        sa.Column("doc_type", sa.String(length=50), nullable=False),
        sa.Column("version", sa.String(length=20), nullable=True),
        sa.Column("format", sa.String(length=20), nullable=False, server_default="markdown"),
        sa.Column("content", sa.Text(), nullable=True),
        sa.Column("status", sa.String(length=50), nullable=False, server_default="draft"),
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
        "ix_generated_documents_org_session",
        "generated_documents",
        ["organization_id", "onboarding_session_id"],
    )

    # Initial scan jobs created after onboarding
    op.create_table(
        "risk_scan_jobs",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("organization_id", sa.Integer(), nullable=False, index=True),
        sa.Column("onboarding_session_id", sa.Integer(), nullable=False, index=True),
        sa.Column("asset_id", sa.Integer(), nullable=True),
        sa.Column("status", sa.String(length=50), nullable=False, server_default="pending"),
        sa.Column("findings_count", sa.Integer(), nullable=True),
        sa.Column("risk_level", sa.String(length=50), nullable=True),
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
        sa.ForeignKeyConstraint(["asset_id"], ["architecture_assets.id"], ondelete="SET NULL"),
    )
    op.create_index(
        "ix_risk_scan_jobs_org_session",
        "risk_scan_jobs",
        ["organization_id", "onboarding_session_id"],
    )

    # Compliance profile enrichment fields
    op.add_column(
        "compliance_profiles",
        sa.Column("required_documents", sa.JSON(), nullable=True),
    )
    op.add_column(
        "compliance_profiles",
        sa.Column("auto_fill_ratio", sa.Float(), nullable=True),
    )

    # Conversation messages during onboarding
    op.create_table(
        "onboarding_messages",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("organization_id", sa.Integer(), nullable=False, index=True),
        sa.Column("onboarding_session_id", sa.Integer(), nullable=False, index=True),
        sa.Column("role", sa.String(length=20), nullable=False),  # user|assistant
        sa.Column("content", sa.Text(), nullable=False),
        sa.Column("metadata_json", sa.JSON(), nullable=True),
        sa.Column(
            "created_at",
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
        "ix_onboarding_messages_org_session",
        "onboarding_messages",
        ["organization_id", "onboarding_session_id"],
    )


def downgrade() -> None:
    op.drop_index("ix_onboarding_messages_org_session", table_name="onboarding_messages")
    op.drop_table("onboarding_messages")

    op.drop_column("compliance_profiles", "auto_fill_ratio")
    op.drop_column("compliance_profiles", "required_documents")

    op.drop_index("ix_risk_scan_jobs_org_session", table_name="risk_scan_jobs")
    op.drop_table("risk_scan_jobs")

    op.drop_index("ix_generated_documents_org_session", table_name="generated_documents")
    op.drop_table("generated_documents")

    op.drop_index("ix_integration_credentials_org_session", table_name="integration_credentials")
    op.drop_table("integration_credentials")

    op.drop_index("ix_architecture_assets_org_session", table_name="architecture_assets")
    op.drop_table("architecture_assets")

    op.drop_index("ix_org_profiles_org_session", table_name="org_profiles")
    op.drop_table("org_profiles")

    op.drop_column("onboarding_sessions", "ai_conversation_id")

    # No safe downgrade for enum value removals
    op.execute("ALTER TABLE onboarding_sessions ALTER COLUMN status SET DEFAULT 'draft'")

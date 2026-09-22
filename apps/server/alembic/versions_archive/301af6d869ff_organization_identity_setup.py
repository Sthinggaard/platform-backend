"""Organisation Identity Setup — post-signup identity confirmation & scoping

New post-signup stage sitting before Leadership Authorisation in the
onboarding readiness sequence: legal identity, a primary legal entity,
confirmed Risklence implementation scope, identity evidence/provenance, and
organisation domains. Extends the existing Organization row rather than
introducing a parallel tenant-root entity; reuses the existing pretenant
CvrEnrichmentClient for registry lookups (no new provider abstraction) and
the existing AuditEvent table (no new audit mechanism).

Revision ID: 301af6d869ff
Revises: c8a1e5f9d203
Create Date: 2026-07-16 00:00:00.000000
"""

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import JSONB

revision = "301af6d869ff"
down_revision = "c8a1e5f9d203"
branch_labels = None
depends_on = None


def _table_exists(conn, table: str) -> bool:
    return conn.execute(
        sa.text("SELECT 1 FROM information_schema.tables WHERE table_name=:t"),
        {"t": table},
    ).fetchone() is not None


def _col_exists(conn, table: str, col: str) -> bool:
    return conn.execute(
        sa.text(
            "SELECT 1 FROM information_schema.columns WHERE table_name=:t AND column_name=:c"
        ),
        {"t": table, "c": col},
    ).fetchone() is not None


def upgrade() -> None:
    conn = op.get_bind()

    if not _table_exists(conn, "organization_identity_evidence"):
        op.create_table(
            "organization_identity_evidence",
            sa.Column("id", sa.String(36), primary_key=True),
            sa.Column(
                "organization_id",
                sa.Integer(),
                sa.ForeignKey("organizations.id", ondelete="CASCADE"),
                nullable=False,
            ),
            sa.Column("source_type", sa.String(30), nullable=False),
            sa.Column("source_reference", sa.String(100), nullable=True),
            sa.Column("observed_at", sa.DateTime(), nullable=False, server_default=sa.func.now()),
            sa.Column("raw_legal_name", sa.String(255), nullable=True),
            sa.Column("raw_industry_code", sa.String(20), nullable=True),
            sa.Column("raw_legal_form", sa.String(100), nullable=True),
            sa.Column("raw_address", JSONB(), nullable=True),
            sa.Column("created_at", sa.DateTime(), nullable=False, server_default=sa.func.now()),
        )
        op.create_index(
            "ix_organization_identity_evidence_org",
            "organization_identity_evidence",
            ["organization_id"],
        )

    if not _table_exists(conn, "organization_legal_entities"):
        op.create_table(
            "organization_legal_entities",
            sa.Column("id", sa.String(36), primary_key=True),
            sa.Column(
                "organization_id",
                sa.Integer(),
                sa.ForeignKey("organizations.id", ondelete="CASCADE"),
                nullable=False,
            ),
            sa.Column("legal_name", sa.String(255), nullable=False),
            sa.Column("registration_number", sa.String(50), nullable=True),
            sa.Column("registration_country", sa.String(2), nullable=False),
            sa.Column("entity_type", sa.String(30), nullable=False),
            sa.Column("status", sa.String(20), nullable=False),
            sa.Column("is_primary", sa.Boolean(), nullable=False, server_default=sa.false()),
            sa.Column(
                "parent_entity_id",
                sa.String(36),
                sa.ForeignKey("organization_legal_entities.id", ondelete="SET NULL"),
                nullable=True,
            ),
            sa.Column(
                "source_evidence_id",
                sa.String(36),
                sa.ForeignKey("organization_identity_evidence.id", ondelete="SET NULL"),
                nullable=True,
            ),
            sa.Column("created_at", sa.DateTime(), nullable=False, server_default=sa.func.now()),
            sa.Column("updated_at", sa.DateTime(), nullable=False, server_default=sa.func.now()),
        )
        op.create_index(
            "ix_organization_legal_entities_org",
            "organization_legal_entities",
            ["organization_id"],
        )

    if not _table_exists(conn, "organization_identity_confirmations"):
        op.create_table(
            "organization_identity_confirmations",
            sa.Column("id", sa.String(36), primary_key=True),
            sa.Column(
                "organization_id",
                sa.Integer(),
                sa.ForeignKey("organizations.id", ondelete="CASCADE"),
                nullable=False,
            ),
            sa.Column("status", sa.String(20), nullable=False, server_default="draft"),
            sa.Column("version", sa.Integer(), nullable=False, server_default="1"),
            sa.Column("confirmed_legal_name", sa.String(255), nullable=True),
            sa.Column("confirmed_registration_country", sa.String(2), nullable=True),
            sa.Column("confirmed_organization_type", sa.String(30), nullable=True),
            sa.Column(
                "evidence_id",
                sa.String(36),
                sa.ForeignKey("organization_identity_evidence.id", ondelete="SET NULL"),
                nullable=True,
            ),
            sa.Column(
                "confirmed_by_user_id",
                sa.Integer(),
                sa.ForeignKey("users.id", ondelete="RESTRICT"),
                nullable=True,
            ),
            sa.Column("confirmed_at", sa.DateTime(), nullable=True),
            sa.Column(
                "superseded_by_id",
                sa.String(36),
                sa.ForeignKey("organization_identity_confirmations.id", ondelete="SET NULL"),
                nullable=True,
            ),
            sa.Column("correction_reason", sa.Text(), nullable=True),
            sa.Column("backfilled", sa.Boolean(), nullable=False, server_default=sa.false()),
            sa.Column("created_at", sa.DateTime(), nullable=False, server_default=sa.func.now()),
            sa.Column("updated_at", sa.DateTime(), nullable=False, server_default=sa.func.now()),
        )
        op.create_index(
            "ix_organization_identity_confirmations_org_status",
            "organization_identity_confirmations",
            ["organization_id", "status"],
        )

    if not _table_exists(conn, "organization_scopes"):
        op.create_table(
            "organization_scopes",
            sa.Column("id", sa.String(36), primary_key=True),
            sa.Column(
                "organization_id",
                sa.Integer(),
                sa.ForeignKey("organizations.id", ondelete="CASCADE"),
                nullable=False,
            ),
            sa.Column("scope_type", sa.String(30), nullable=False),
            sa.Column("name", sa.String(255), nullable=False),
            sa.Column("description", sa.Text(), nullable=True),
            sa.Column("status", sa.String(20), nullable=False),
            sa.Column("included_entity_ids", JSONB(), nullable=True),
            sa.Column("excluded_entity_ids", JSONB(), nullable=True),
            sa.Column("included_countries", JSONB(), nullable=True),
            sa.Column(
                "confirmed_by_user_id",
                sa.Integer(),
                sa.ForeignKey("users.id", ondelete="SET NULL"),
                nullable=True,
            ),
            sa.Column("confirmed_at", sa.DateTime(), nullable=True),
            sa.Column("created_at", sa.DateTime(), nullable=False, server_default=sa.func.now()),
            sa.Column("updated_at", sa.DateTime(), nullable=False, server_default=sa.func.now()),
        )
        op.create_index(
            "ix_organization_scopes_org_status",
            "organization_scopes",
            ["organization_id", "status"],
        )

    if not _table_exists(conn, "organization_domains"):
        op.create_table(
            "organization_domains",
            sa.Column("id", sa.String(36), primary_key=True),
            sa.Column(
                "organization_id",
                sa.Integer(),
                sa.ForeignKey("organizations.id", ondelete="CASCADE"),
                nullable=False,
            ),
            sa.Column("domain", sa.String(255), nullable=False),
            sa.Column("domain_type", sa.String(20), nullable=False),
            sa.Column("verification_status", sa.String(30), nullable=False),
            sa.Column("verification_method", sa.String(50), nullable=True),
            sa.Column(
                "verified_by_user_id",
                sa.Integer(),
                sa.ForeignKey("users.id", ondelete="SET NULL"),
                nullable=True,
            ),
            sa.Column("verified_at", sa.DateTime(), nullable=True),
            sa.Column("created_at", sa.DateTime(), nullable=False, server_default=sa.func.now()),
        )
        op.create_index(
            "ix_organization_domains_org",
            "organization_domains",
            ["organization_id"],
        )

    if not _col_exists(conn, "organizations", "organization_type"):
        op.add_column("organizations", sa.Column("organization_type", sa.String(30), nullable=True))
    if not _col_exists(conn, "organizations", "headquarters_country"):
        op.add_column("organizations", sa.Column("headquarters_country", sa.String(2), nullable=True))
    if not _col_exists(conn, "organizations", "operating_countries"):
        op.add_column(
            "organizations", sa.Column("operating_countries", sa.ARRAY(sa.String()), nullable=True)
        )
    if not _col_exists(conn, "organizations", "employee_range"):
        op.add_column("organizations", sa.Column("employee_range", sa.String(30), nullable=True))
    if not _col_exists(conn, "organizations", "website_domain"):
        op.add_column("organizations", sa.Column("website_domain", sa.String(255), nullable=True))


def downgrade() -> None:
    conn = op.get_bind()
    for col in (
        "website_domain",
        "employee_range",
        "operating_countries",
        "headquarters_country",
        "organization_type",
    ):
        if _col_exists(conn, "organizations", col):
            op.drop_column("organizations", col)

    if _table_exists(conn, "organization_domains"):
        op.drop_index("ix_organization_domains_org", table_name="organization_domains")
        op.drop_table("organization_domains")
    if _table_exists(conn, "organization_scopes"):
        op.drop_index("ix_organization_scopes_org_status", table_name="organization_scopes")
        op.drop_table("organization_scopes")
    if _table_exists(conn, "organization_identity_confirmations"):
        op.drop_index(
            "ix_organization_identity_confirmations_org_status",
            table_name="organization_identity_confirmations",
        )
        op.drop_table("organization_identity_confirmations")
    if _table_exists(conn, "organization_legal_entities"):
        op.drop_index("ix_organization_legal_entities_org", table_name="organization_legal_entities")
        op.drop_table("organization_legal_entities")
    if _table_exists(conn, "organization_identity_evidence"):
        op.drop_index(
            "ix_organization_identity_evidence_org", table_name="organization_identity_evidence"
        )
        op.drop_table("organization_identity_evidence")

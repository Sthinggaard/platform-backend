"""Organisation Structure — sufficient operational structure (post-ORG-ID stage)

Organisation units (hierarchical, no fixed depth), non-hierarchical unit
relationships, locations, unit membership, and pairwise duplicate-unit
detection — enough to place technical evidence, ownership, Business
Services, and future Business Processes in the right organisational
context.

Revision ID: 76f0ab784980
Revises: 301af6d869ff
Create Date: 2026-07-16 00:00:00.000000
"""

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import JSONB

revision = "76f0ab784980"
down_revision = "301af6d869ff"
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

    if not _col_exists(conn, "organizations", "technical_setup_owner_user_id"):
        op.add_column(
            "organizations",
            sa.Column(
                "technical_setup_owner_user_id",
                sa.Integer(),
                sa.ForeignKey(
                    "users.id", ondelete="SET NULL", name="fk_organizations_technical_setup_owner"
                ),
                nullable=True,
            ),
        )

    if not _table_exists(conn, "organization_units"):
        op.create_table(
            "organization_units",
            sa.Column("id", sa.String(36), primary_key=True),
            sa.Column(
                "organization_id",
                sa.Integer(),
                sa.ForeignKey("organizations.id", ondelete="CASCADE"),
                nullable=False,
            ),
            sa.Column("name", sa.String(255), nullable=False),
            sa.Column("code", sa.String(50), nullable=True),
            sa.Column("description", sa.Text(), nullable=True),
            sa.Column("unit_type", sa.String(30), nullable=False),
            sa.Column(
                "parent_unit_id",
                sa.String(36),
                sa.ForeignKey("organization_units.id", ondelete="SET NULL"),
                nullable=True,
            ),
            sa.Column(
                "legal_entity_id",
                sa.String(36),
                sa.ForeignKey("organization_legal_entities.id", ondelete="SET NULL"),
                nullable=True,
            ),
            sa.Column("country_code", sa.String(2), nullable=True),
            sa.Column("location_reference", sa.String(255), nullable=True),
            sa.Column("status", sa.String(20), nullable=False),
            sa.Column("scope_status", sa.String(30), nullable=False, server_default="unresolved"),
            sa.Column("source", sa.String(30), nullable=False),
            sa.Column("source_reference", sa.String(255), nullable=True),
            sa.Column("confidence", sa.Float(), nullable=True),
            sa.Column(
                "merged_into_unit_id",
                sa.String(36),
                sa.ForeignKey("organization_units.id", ondelete="SET NULL"),
                nullable=True,
            ),
            sa.Column("aliases", JSONB(), nullable=True),
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
            "ix_organization_units_org_status", "organization_units", ["organization_id", "status"]
        )
        op.create_index(
            "ix_organization_units_org_parent",
            "organization_units",
            ["organization_id", "parent_unit_id"],
        )

    if not _table_exists(conn, "organization_unit_relationships"):
        op.create_table(
            "organization_unit_relationships",
            sa.Column("id", sa.String(36), primary_key=True),
            sa.Column(
                "organization_id",
                sa.Integer(),
                sa.ForeignKey("organizations.id", ondelete="CASCADE"),
                nullable=False,
            ),
            sa.Column(
                "source_unit_id",
                sa.String(36),
                sa.ForeignKey("organization_units.id", ondelete="CASCADE"),
                nullable=False,
            ),
            sa.Column(
                "target_unit_id",
                sa.String(36),
                sa.ForeignKey("organization_units.id", ondelete="CASCADE"),
                nullable=False,
            ),
            sa.Column("relationship_type", sa.String(30), nullable=False),
            sa.Column("status", sa.String(20), nullable=False),
            sa.Column("source", sa.String(30), nullable=False),
            sa.Column("confidence", sa.Float(), nullable=True),
            sa.Column(
                "confirmed_by_user_id",
                sa.Integer(),
                sa.ForeignKey("users.id", ondelete="SET NULL"),
                nullable=True,
            ),
            sa.Column("confirmed_at", sa.DateTime(), nullable=True),
            sa.Column("created_at", sa.DateTime(), nullable=False, server_default=sa.func.now()),
            sa.UniqueConstraint(
                "source_unit_id", "target_unit_id", "relationship_type", name="uq_org_unit_relationship"
            ),
        )
        op.create_index(
            "ix_org_unit_relationships_org_source",
            "organization_unit_relationships",
            ["organization_id", "source_unit_id"],
        )

    if not _table_exists(conn, "organization_locations"):
        op.create_table(
            "organization_locations",
            sa.Column("id", sa.String(36), primary_key=True),
            sa.Column(
                "organization_id",
                sa.Integer(),
                sa.ForeignKey("organizations.id", ondelete="CASCADE"),
                nullable=False,
            ),
            sa.Column(
                "organization_unit_id",
                sa.String(36),
                sa.ForeignKey("organization_units.id", ondelete="SET NULL"),
                nullable=True,
            ),
            sa.Column("name", sa.String(255), nullable=False),
            sa.Column("location_type", sa.String(20), nullable=False),
            sa.Column("country_code", sa.String(2), nullable=True),
            sa.Column("region", sa.String(100), nullable=True),
            sa.Column("city", sa.String(100), nullable=True),
            sa.Column("address_reference", sa.String(255), nullable=True),
            sa.Column("status", sa.String(20), nullable=False),
            sa.Column("created_at", sa.DateTime(), nullable=False, server_default=sa.func.now()),
        )
        op.create_index(
            "ix_organization_locations_org_unit",
            "organization_locations",
            ["organization_id", "organization_unit_id"],
        )

    if not _table_exists(conn, "organization_unit_memberships"):
        op.create_table(
            "organization_unit_memberships",
            sa.Column("id", sa.String(36), primary_key=True),
            sa.Column(
                "organization_id",
                sa.Integer(),
                sa.ForeignKey("organizations.id", ondelete="CASCADE"),
                nullable=False,
            ),
            sa.Column(
                "organization_unit_id",
                sa.String(36),
                sa.ForeignKey("organization_units.id", ondelete="CASCADE"),
                nullable=False,
            ),
            sa.Column("user_id", sa.Integer(), sa.ForeignKey("users.id", ondelete="CASCADE"), nullable=False),
            sa.Column("membership_role", sa.String(30), nullable=False),
            sa.Column("source", sa.String(30), nullable=False),
            sa.Column("status", sa.String(20), nullable=False),
            sa.Column("effective_from", sa.DateTime(), nullable=True),
            sa.Column("effective_to", sa.DateTime(), nullable=True),
            sa.Column("created_at", sa.DateTime(), nullable=False, server_default=sa.func.now()),
        )
        op.create_index(
            "ix_org_unit_memberships_org_unit",
            "organization_unit_memberships",
            ["organization_id", "organization_unit_id"],
        )
        op.create_index(
            "ix_org_unit_memberships_org_user",
            "organization_unit_memberships",
            ["organization_id", "user_id"],
        )

    if not _table_exists(conn, "organization_unit_match_suggestions"):
        op.create_table(
            "organization_unit_match_suggestions",
            sa.Column("id", sa.String(36), primary_key=True),
            sa.Column(
                "organization_id",
                sa.Integer(),
                sa.ForeignKey("organizations.id", ondelete="CASCADE"),
                nullable=False,
            ),
            sa.Column(
                "unit_a_id",
                sa.String(36),
                sa.ForeignKey("organization_units.id", ondelete="CASCADE"),
                nullable=False,
            ),
            sa.Column(
                "unit_b_id",
                sa.String(36),
                sa.ForeignKey("organization_units.id", ondelete="CASCADE"),
                nullable=False,
            ),
            sa.Column("match_confidence", sa.Float(), nullable=False),
            sa.Column("matching_reasons", JSONB(), nullable=False, server_default="[]"),
            sa.Column("status", sa.String(20), nullable=False),
            sa.Column(
                "decided_by_user_id",
                sa.Integer(),
                sa.ForeignKey("users.id", ondelete="SET NULL"),
                nullable=True,
            ),
            sa.Column("decided_at", sa.DateTime(), nullable=True),
            sa.Column("created_at", sa.DateTime(), nullable=False, server_default=sa.func.now()),
            sa.UniqueConstraint(
                "organization_id", "unit_a_id", "unit_b_id", name="uq_org_unit_match_pair"
            ),
        )


def downgrade() -> None:
    conn = op.get_bind()
    if _col_exists(conn, "organizations", "technical_setup_owner_user_id"):
        op.drop_column("organizations", "technical_setup_owner_user_id")
    if _table_exists(conn, "organization_unit_match_suggestions"):
        op.drop_table("organization_unit_match_suggestions")
    if _table_exists(conn, "organization_unit_memberships"):
        op.drop_index("ix_org_unit_memberships_org_user", table_name="organization_unit_memberships")
        op.drop_index("ix_org_unit_memberships_org_unit", table_name="organization_unit_memberships")
        op.drop_table("organization_unit_memberships")
    if _table_exists(conn, "organization_locations"):
        op.drop_index("ix_organization_locations_org_unit", table_name="organization_locations")
        op.drop_table("organization_locations")
    if _table_exists(conn, "organization_unit_relationships"):
        op.drop_index(
            "ix_org_unit_relationships_org_source", table_name="organization_unit_relationships"
        )
        op.drop_table("organization_unit_relationships")
    if _table_exists(conn, "organization_units"):
        op.drop_index("ix_organization_units_org_parent", table_name="organization_units")
        op.drop_index("ix_organization_units_org_status", table_name="organization_units")
        op.drop_table("organization_units")

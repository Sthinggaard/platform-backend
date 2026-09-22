"""add value stream foundation

Adds the value_streams table and extends organizations and business_services
with the columns needed for the value stream layer.

Revision ID: 20250407_value_stream_foundation
Revises: 20250403_add_dependency_bundle_versions
Create Date: 2026-04-07 00:00:00.000000
"""

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import JSONB

# revision identifiers, used by Alembic.
revision = "20250407_value_stream_foundation"
down_revision = ("20250403_add_dependency_bundle_versions", "20250324_asset_level_spof")
branch_labels = None
depends_on = None


def _col_exists(conn, table: str, col: str) -> bool:
    return conn.execute(
        sa.text(
            "SELECT 1 FROM information_schema.columns "
            "WHERE table_name=:t AND column_name=:c"
        ),
        {"t": table, "c": col},
    ).fetchone() is not None


def _table_exists(conn, table: str) -> bool:
    return conn.execute(
        sa.text(
            "SELECT 1 FROM information_schema.tables "
            "WHERE table_name=:t"
        ),
        {"t": table},
    ).fetchone() is not None


def upgrade() -> None:
    conn = op.get_bind()

    # -------------------------------------------------------------------------
    # 1. Extend organizations with CVR / NACE / value stream profile
    # -------------------------------------------------------------------------
    if not _col_exists(conn, "organizations", "cvr_number"):
        op.add_column("organizations", sa.Column("cvr_number", sa.String(20), nullable=True))

    if not _col_exists(conn, "organizations", "nace_code"):
        op.add_column("organizations", sa.Column("nace_code", sa.String(10), nullable=True))

    if not _col_exists(conn, "organizations", "org_value_stream_profile"):
        op.add_column(
            "organizations",
            sa.Column("org_value_stream_profile", JSONB, nullable=True),
        )

    # -------------------------------------------------------------------------
    # 2. Create value_streams table (idempotent)
    # -------------------------------------------------------------------------
    if not _table_exists(conn, "value_streams"):
        op.create_table(
            "value_streams",
            sa.Column("id", sa.String(36), primary_key=True),
            sa.Column(
                "organization_id",
                sa.Integer,
                sa.ForeignKey("organizations.id", ondelete="CASCADE"),
                nullable=False,
            ),
            sa.Column("library_item_id", sa.String(100), nullable=True),
            sa.Column("name", sa.String(200), nullable=False),
            sa.Column("priority", sa.String(20), nullable=False, server_default="standard"),
            sa.Column("source", sa.String(30), nullable=False, server_default="inferred"),
            sa.Column("created_at", sa.DateTime, nullable=False, server_default=sa.text("now()")),
            sa.Column("updated_at", sa.DateTime, nullable=False, server_default=sa.text("now()")),
        )

    # Create index only if it doesn't exist
    index_exists = conn.execute(
        sa.text("SELECT 1 FROM pg_indexes WHERE indexname = 'ix_value_streams_org'")
    ).fetchone()
    if not index_exists:
        op.create_index("ix_value_streams_org", "value_streams", ["organization_id"])

    # -------------------------------------------------------------------------
    # 3. Extend business_services with value_stream_ids
    # -------------------------------------------------------------------------
    if not _col_exists(conn, "business_services", "value_stream_ids"):
        op.add_column(
            "business_services",
            sa.Column(
                "value_stream_ids",
                sa.ARRAY(sa.String(36)),
                nullable=False,
                server_default="{}",
            ),
        )


def downgrade() -> None:
    op.drop_column("business_services", "value_stream_ids")
    op.drop_index("ix_value_streams_org", table_name="value_streams")
    op.drop_table("value_streams")
    op.drop_column("organizations", "org_value_stream_profile")
    op.drop_column("organizations", "nace_code")
    op.drop_column("organizations", "cvr_number")

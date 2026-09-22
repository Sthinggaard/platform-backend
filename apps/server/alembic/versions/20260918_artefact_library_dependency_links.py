"""Add verified Artefact categories and reusable Business Service links (#493)."""

import sqlalchemy as sa
from alembic import op


revision = "20260918_artefact_library_dependency_links"
down_revision = "20260918_merge_dependency_heads"
branch_labels = None
depends_on = None


def _column_exists(conn, table: str, column: str) -> bool:
    return conn.execute(
        sa.text("SELECT 1 FROM information_schema.columns WHERE table_name=:table AND column_name=:column"),
        {"table": table, "column": column},
    ).fetchone() is not None


def _table_exists(conn, table: str) -> bool:
    return conn.execute(
        sa.text("SELECT 1 FROM information_schema.tables WHERE table_name=:table"), {"table": table}
    ).fetchone() is not None


def upgrade() -> None:
    conn = op.get_bind()
    if not _column_exists(conn, "assets", "dependency_category"):
        op.add_column("assets", sa.Column("dependency_category", sa.String(length=30), nullable=True))
        op.create_index("ix_assets_dependency_category", "assets", ["dependency_category"])
    if not _table_exists(conn, "service_artefact_dependency_links"):
        op.create_table(
            "service_artefact_dependency_links",
            sa.Column("id", sa.String(length=36), primary_key=True),
            sa.Column("organization_id", sa.Integer(), sa.ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False),
            sa.Column("service_id", sa.String(length=36), sa.ForeignKey("business_services.id", ondelete="CASCADE"), nullable=False),
            sa.Column("asset_id", sa.Integer(), sa.ForeignKey("assets.id", ondelete="CASCADE"), nullable=False),
            sa.Column("dependency_category", sa.String(length=30), nullable=False),
            sa.Column("linked_by_user_id", sa.Integer(), sa.ForeignKey("users.id", ondelete="SET NULL")),
            sa.Column("linked_at", sa.DateTime(), nullable=False),
            sa.UniqueConstraint("organization_id", "service_id", "asset_id", name="uq_service_artefact_dependency_link"),
        )
        op.create_index("ix_service_artefact_dependency_links_org_service", "service_artefact_dependency_links", ["organization_id", "service_id"])
        op.create_index("ix_service_artefact_dependency_links_org_asset", "service_artefact_dependency_links", ["organization_id", "asset_id"])


def downgrade() -> None:
    conn = op.get_bind()
    if _table_exists(conn, "service_artefact_dependency_links"):
        op.drop_table("service_artefact_dependency_links")
    if _column_exists(conn, "assets", "dependency_category"):
        op.drop_index("ix_assets_dependency_category", table_name="assets")
        op.drop_column("assets", "dependency_category")

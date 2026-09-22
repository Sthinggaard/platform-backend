"""Canonical identity and lifecycle fields on assets (Step 4.1A)

Revision ID: 20260719_asset_identity_lifecycle
Revises: 20260719_operating_context_suggestions
Create Date: 2026-07-19 00:00:00.000000
"""

from alembic import op
import sqlalchemy as sa

revision = "20260719_asset_identity_lifecycle"
down_revision = "20260719_operating_context_suggestions"
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


def _index_exists(conn, index_name: str) -> bool:
    return conn.execute(
        sa.text("SELECT 1 FROM pg_indexes WHERE indexname=:i"),
        {"i": index_name},
    ).fetchone() is not None


COLUMNS: list[sa.Column] = [
    sa.Column("canonical_identity_key", sa.String(500), nullable=True),
    sa.Column("lifecycle_state", sa.String(20), nullable=False, server_default="active"),
    sa.Column("merged_into_asset_id", sa.Integer(), nullable=True),
]


def upgrade() -> None:
    conn = op.get_bind()
    for column in COLUMNS:
        if not _col_exists(conn, "assets", column.name):
            op.add_column("assets", column.copy())

    if not _index_exists(conn, "ix_assets_org_identity_key"):
        op.create_index(
            "ix_assets_org_identity_key",
            "assets",
            ["organization_id", "canonical_identity_key"],
        )

    # merged_into_asset_id references another row in the same table — add
    # the FK separately so column creation above stays simple/uniform.
    op.execute(
        """
        DO $$
        BEGIN
            IF NOT EXISTS (
                SELECT 1 FROM information_schema.table_constraints
                WHERE constraint_name = 'fk_assets_merged_into_asset_id'
            ) THEN
                ALTER TABLE assets
                ADD CONSTRAINT fk_assets_merged_into_asset_id
                FOREIGN KEY (merged_into_asset_id) REFERENCES assets(id);
            END IF;
        END $$;
        """
    )


def downgrade() -> None:
    conn = op.get_bind()
    op.execute("ALTER TABLE assets DROP CONSTRAINT IF EXISTS fk_assets_merged_into_asset_id")
    if _index_exists(conn, "ix_assets_org_identity_key"):
        op.drop_index("ix_assets_org_identity_key", table_name="assets")
    for column in COLUMNS:
        if _col_exists(conn, "assets", column.name):
            op.drop_column("assets", column.name)

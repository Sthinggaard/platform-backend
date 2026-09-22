"""Merge the two heads left when #63 and #64 both built on the schema baseline.

``20260911_process_appetite_fk`` (the process records its Risk Appetite decision,
PR #63) and ``20260913_asset_link_spelling`` (one stored spelling for an asset
link, #363, PR #64) both revise ``20260910_schema_baseline``. PR #64 merged to
``dev`` first, so this branch carries the join. Pure history merge — no schema
change.

Revision ID: 20260914_merge_heads
Revises: 20260911_process_appetite_fk, 20260913_asset_link_spelling
Create Date: 2026-09-14 00:00:00.000000
"""

# ⚠️ 32 characters is the hard limit for `alembic_version.version_num`; this is 20.
revision = "20260914_merge_heads"
down_revision = ("20260911_process_appetite_fk", "20260913_asset_link_spelling")
branch_labels = None
depends_on = None


def upgrade() -> None:
    pass


def downgrade() -> None:
    pass

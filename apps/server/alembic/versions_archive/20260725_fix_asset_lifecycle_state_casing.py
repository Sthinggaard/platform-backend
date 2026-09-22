"""Fix assets.lifecycle_state casing mismatch

20260719_asset_identity_lifecycle added this column with
server_default="active" (lowercase), but AssetLifecycleState's members are
all uppercase ("ACTIVE", "INACTIVE", ...) and the SQLAlchemy Enum column
validates strictly against those on read. Every row backfilled by that
migration's server_default -- every asset in the database -- ended up with
a value the application can no longer read back, breaking
/process-dashboard, /threats, and the asset-monitoring background tick.

Revision ID: 20260725_fix_asset_lifecycle_state_casing
Revises: 20260719_slot_mapping_reason_code
Create Date: 2026-07-25 00:00:00.000000
"""

from alembic import op
import sqlalchemy as sa

revision = "20260725_fix_asset_lifecycle_state_casing"
down_revision = "20260719_slot_mapping_reason_code"
branch_labels = None
depends_on = None


def upgrade() -> None:
    conn = op.get_bind()

    # Idempotent: only ever uppercases values that aren't already correct.
    conn.execute(
        sa.text(
            "UPDATE assets SET lifecycle_state = UPPER(lifecycle_state) "
            "WHERE lifecycle_state <> UPPER(lifecycle_state)"
        )
    )

    op.alter_column(
        "assets",
        "lifecycle_state",
        server_default="ACTIVE",
    )


def downgrade() -> None:
    op.alter_column(
        "assets",
        "lifecycle_state",
        server_default="active",
    )

"""Merge the two unresolved migration heads.

`e5f6a7b8c9d0` (Step 4.2 Part 2 / ScannerCommand-ProviderExecution branch)
and `20260726_discovery_run_cancellation_reason` (DISC-44/DISC-46 branch)
both descend from `20260719_slot_mapping_reason_code` and were both applied
independently in the dev database (both rows present in `alembic_version`),
so this is a real dual-head state, not just a local file artifact. Pure
history merge — no schema change.

Revision ID: af8f00af46fe
Revises: e5f6a7b8c9d0, 20260726_discovery_run_cancellation_reason
Create Date: 2026-08-02 00:00:00.000000
"""

revision = "af8f00af46fe"
down_revision = ("e5f6a7b8c9d0", "20260726_discovery_run_cancellation_reason")
branch_labels = None
depends_on = None


def upgrade() -> None:
    pass


def downgrade() -> None:
    pass

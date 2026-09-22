"""Merge the two heads left after PR #47/#48 both merged to dev.

`a52dba017ea6` (scanner credential validity_custom_days, from the
credential-lifecycle branch) and `c8a1f3e6b2d4` (evidence_sources.
business_service_id, from the business-process-scanner-evidence branch)
both descend from `af8f00af46fe` and were both applied independently.
Pure history merge — no schema change.

Revision ID: e1b4a09c5f37
Revises: a52dba017ea6, c8a1f3e6b2d4
Create Date: 2026-08-03 00:00:00.000000
"""

revision = "e1b4a09c5f37"
down_revision = ("a52dba017ea6", "c8a1f3e6b2d4")
branch_labels = None
depends_on = None


def upgrade() -> None:
    pass


def downgrade() -> None:
    pass

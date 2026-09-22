"""Merge the #463 and #464 schema branches.

Revision ID: 20260918_merge_dependency_heads
Revises: 20260915_service_bia_exceptions, 20260918_dependency_categories
Create Date: 2026-09-18 00:00:00.000000
"""

revision = "20260918_merge_dependency_heads"
down_revision = ("20260915_service_bia_exceptions", "20260918_dependency_categories")
branch_labels = None
depends_on = None


def upgrade() -> None:
    pass


def downgrade() -> None:
    pass

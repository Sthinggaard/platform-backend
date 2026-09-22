"""Service change notices — telling owners who depend on a service (#375).

Revision ID: 20260904_notices
Revises: 20260830_asset_refs
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "20260904_notices"
down_revision = "20260830_asset_refs"
branch_labels = None
depends_on = None

_TABLE = "service_change_notices"


def _table_exists(name: str) -> bool:
    """Guarded DDL — the dev database was created out-of-band with
    ``create_all``, so a table can already exist at any revision (AGENTS.md)."""
    return sa.inspect(op.get_bind()).has_table(name)


def upgrade() -> None:
    if _table_exists(_TABLE):
        return
    op.create_table(
        _TABLE,
        sa.Column("id", sa.String(length=36), primary_key=True),
        sa.Column(
            "organization_id",
            sa.Integer(),
            sa.ForeignKey("organizations.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column(
            "service_id",
            sa.String(length=36),
            sa.ForeignKey("business_services.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column(
            "process_id",
            sa.String(length=36),
            sa.ForeignKey("value_streams.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column(
            "recipient_user_id",
            sa.Integer(),
            sa.ForeignKey("users.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("kind", sa.String(length=20), nullable=False),
        sa.Column("title", sa.String(length=255), nullable=False),
        sa.Column("description", sa.Text(), nullable=True),
        sa.Column("owner_comment", sa.Text(), nullable=True),
        sa.Column(
            "actor_user_id",
            sa.Integer(),
            sa.ForeignKey("users.id", ondelete="SET NULL"),
            nullable=True,
        ),
        sa.Column("decision_record_id", sa.String(length=36), nullable=True),
        # Opened — clears the map badge, and nothing more.
        sa.Column("viewed_at", sa.DateTime(), nullable=True),
        # Explicitly marked read and informed — the governance record.
        sa.Column("acknowledged_at", sa.DateTime(), nullable=True),
        # Closed by the owning team; the only thing that clears an issue.
        sa.Column("resolved_at", sa.DateTime(), nullable=True),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.Column("updated_at", sa.DateTime(), nullable=False),
    )
    op.create_index(
        "ix_service_change_notices_recipient", _TABLE, ["organization_id", "recipient_user_id"]
    )
    op.create_index(
        "ix_service_change_notices_process", _TABLE, ["organization_id", "process_id"]
    )
    op.create_index(
        "ix_service_change_notices_service", _TABLE, ["organization_id", "service_id"]
    )


def downgrade() -> None:
    if not _table_exists(_TABLE):
        return
    op.drop_index("ix_service_change_notices_service", table_name=_TABLE)
    op.drop_index("ix_service_change_notices_process", table_name=_TABLE)
    op.drop_index("ix_service_change_notices_recipient", table_name=_TABLE)
    op.drop_table(_TABLE)

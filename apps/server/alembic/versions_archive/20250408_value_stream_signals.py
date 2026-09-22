"""add value stream signals

Creates append-only value_stream_signals table for in-platform process learning signals.

Revision ID: 20250408_value_stream_signals
Revises: 20250407_value_stream_foundation
Create Date: 2026-04-08 00:00:00.000000
"""

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import JSONB

# revision identifiers, used by Alembic.
revision = "20250408_value_stream_signals"
down_revision = "20250407_value_stream_foundation"
branch_labels = None
depends_on = None


def _table_exists(conn, table: str) -> bool:
    return conn.execute(
        sa.text(
            "SELECT 1 FROM information_schema.tables "
            "WHERE table_name=:t"
        ),
        {"t": table},
    ).fetchone() is not None


def _index_exists(conn, index_name: str) -> bool:
    return conn.execute(
        sa.text("SELECT 1 FROM pg_indexes WHERE indexname = :i"),
        {"i": index_name},
    ).fetchone() is not None


def upgrade() -> None:
    conn = op.get_bind()

    if not _table_exists(conn, "value_stream_signals"):
        op.create_table(
            "value_stream_signals",
            sa.Column("id", sa.Integer, primary_key=True),
            sa.Column(
                "organization_id",
                sa.Integer,
                sa.ForeignKey("organizations.id", ondelete="CASCADE"),
                nullable=False,
            ),
            sa.Column("user_id", sa.Integer, nullable=False),
            sa.Column("event", sa.String(50), nullable=False),
            sa.Column("stream_id", sa.String(36), nullable=True),
            sa.Column("library_item_id", sa.String(100), nullable=True),
            sa.Column("stream_key", sa.String(100), nullable=True),
            sa.Column("name", sa.String(200), nullable=True),
            sa.Column("priority", sa.String(20), nullable=True),
            sa.Column("source", sa.String(30), nullable=True),
            sa.Column("payload", JSONB, nullable=False, server_default=sa.text("'{}'::jsonb")),
            sa.Column("created_at", sa.DateTime, nullable=False, server_default=sa.text("now()")),
        )

    if not _index_exists(conn, "ix_value_stream_signals_org_event"):
        op.create_index(
            "ix_value_stream_signals_org_event",
            "value_stream_signals",
            ["organization_id", "event"],
        )

    if not _index_exists(conn, "ix_value_stream_signals_stream"):
        op.create_index(
            "ix_value_stream_signals_stream",
            "value_stream_signals",
            ["stream_id"],
        )

    if not _index_exists(conn, "ix_value_stream_signals_library_item"):
        op.create_index(
            "ix_value_stream_signals_library_item",
            "value_stream_signals",
            ["library_item_id"],
        )


def downgrade() -> None:
    op.drop_index("ix_value_stream_signals_library_item", table_name="value_stream_signals")
    op.drop_index("ix_value_stream_signals_stream", table_name="value_stream_signals")
    op.drop_index("ix_value_stream_signals_org_event", table_name="value_stream_signals")
    op.drop_table("value_stream_signals")


"""#284 (TZ-6) — an audit event records where the actor was and what clock they read.

Copied onto the event rather than joined from the user, because the user row
changes. Somebody who relocates would otherwise retroactively change where a
past decision was made, and an audit trail that rewrites itself when a profile
is edited is not evidence.

**Existing rows stay null, and that is the correct value.** Nobody recorded
where those actors were, and filling it in from today's profile would be
inventing a fact about the past — the precise failure these columns exist to
prevent. A null reads as "not recorded".

Revision ID: 20260820_audit_actor_time_and_place
Revises: 20260820_user_timezone_and_location
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "20260820_audit_actor_time_and_place"
down_revision = "20260820_user_timezone_and_location"
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


def upgrade() -> None:
    conn = op.get_bind()
    for column, size in (
        ("actor_timezone", 64),
        ("actor_location_country", 2),
        ("actor_location_city", 120),
    ):
        if not _col_exists(conn, "audit_events", column):
            op.add_column("audit_events", sa.Column(column, sa.String(size), nullable=True))
    # No backfill. See the module docstring: a null here is a fact, not a gap.


def downgrade() -> None:
    conn = op.get_bind()
    for column in ("actor_location_city", "actor_location_country", "actor_timezone"):
        if _col_exists(conn, "audit_events", column):
            op.drop_column("audit_events", column)

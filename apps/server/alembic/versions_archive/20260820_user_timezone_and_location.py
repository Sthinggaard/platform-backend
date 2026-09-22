"""#279 (TZ-1) — a person has a location and a timezone.

Additive and nullable, so nothing existing has to be rewritten and the column
can be added while the application is running.

**The backfill is a decision, not a default.** Every existing user is set to
``Europe/Copenhagen`` because the first market is Denmark and every account
today belongs to it. That is a statement about who exists right now, and it
stops being true the first time somebody signs up from another country — which
is why TZ-2 asks each person to confirm their own zone rather than letting this
value stand unexamined. Recorded here so the next reader knows it was chosen
rather than inherited.

Revision ID: 20260820_user_timezone_and_location
Revises: f3a91c05de84
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "20260820_user_timezone_and_location"
down_revision = "f3a91c05de84"
branch_labels = None
depends_on = None

_DEFAULT_TIMEZONE = "Europe/Copenhagen"


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

    if not _col_exists(conn, "users", "timezone"):
        op.add_column("users", sa.Column("timezone", sa.String(64), nullable=True))
        # Only rows that predate the column. A user who has already chosen is
        # never overwritten by a migration re-run.
        conn.execute(
            sa.text("UPDATE users SET timezone = :tz WHERE timezone IS NULL"),
            {"tz": _DEFAULT_TIMEZONE},
        )

    if not _col_exists(conn, "users", "location_country"):
        op.add_column("users", sa.Column("location_country", sa.String(2), nullable=True))

    # Left NULL on purpose. A city is not derivable from anything the platform
    # already knows, and inventing one would put a fact in an audit record that
    # nobody stated.
    if not _col_exists(conn, "users", "location_city"):
        op.add_column("users", sa.Column("location_city", sa.String(120), nullable=True))


def downgrade() -> None:
    conn = op.get_bind()
    for column in ("location_city", "location_country", "timezone"):
        if _col_exists(conn, "users", column):
            op.drop_column("users", column)

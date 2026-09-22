"""#246 — a cadence can say "every Monday", not only "every N days".

Additive, and that is the point: ``cadence_type`` carries a server default of
``interval_days``, so every schedule created before this column existed reads
back as exactly what it was. No backfill, no rewrite of live rows.

``cadence_weekday`` is nullable because an interval cadence genuinely has no
weekday — null here means "this shape does not have one", not "unknown".

``cadence_days`` stays NOT NULL and carries 7 for a weekday schedule. The sweep
never reads it in that case, but a nullable column would leave every reader to
decide what a null cadence meant, and one of them would decide wrongly.

Idempotent per the repo's rules: guarded on each column.

Revision ID: e2f84b16cd73
Revises: d1e73a05fc92
Create Date: 2026-08-19 00:00:00.000000
"""

from alembic import op
import sqlalchemy as sa

revision = "e2f84b16cd73"
down_revision = "d1e73a05fc92"
branch_labels = None
depends_on = None

_TABLE = "recurrence_schedules"


def _column_exists(conn, table: str, column: str) -> bool:
    return conn.execute(
        sa.text(
            "SELECT 1 FROM information_schema.columns "
            "WHERE table_name = :t AND column_name = :c"
        ),
        {"t": table, "c": column},
    ).fetchone() is not None


def upgrade() -> None:
    conn = op.get_bind()
    if not _column_exists(conn, _TABLE, "cadence_type"):
        op.add_column(
            _TABLE,
            sa.Column(
                "cadence_type",
                sa.String(20),
                nullable=False,
                server_default="interval_days",
            ),
        )
    if not _column_exists(conn, _TABLE, "cadence_weekday"):
        op.add_column(_TABLE, sa.Column("cadence_weekday", sa.Integer(), nullable=True))


def downgrade() -> None:
    conn = op.get_bind()
    if _column_exists(conn, _TABLE, "cadence_weekday"):
        op.drop_column(_TABLE, "cadence_weekday")
    if _column_exists(conn, _TABLE, "cadence_type"):
        op.drop_column(_TABLE, "cadence_type")

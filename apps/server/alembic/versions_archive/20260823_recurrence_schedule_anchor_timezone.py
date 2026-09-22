"""#285 (TZ-7) — a schedule carries the zone its cadence is computed in.

The values already in the table were computed on naive UTC, so ``UTC`` is what
they meant and the backfill says so rather than inferring a place. Naming a city
would move every existing schedule by that city's offset while looking like a
documentation change.

Additive and guarded: the column is added only if absent, and the server default
does the backfill, so re-running this changes nothing.
"""

from alembic import op
import sqlalchemy as sa

revision = "20260823_recurrence_schedule_anchor_timezone"
down_revision = "20260821_discovery_capabilities_permission_profiles"
branch_labels = None
depends_on = None

_TABLE = "recurrence_schedules"
_COLUMN = "anchor_timezone"
#: Mirrors ``RECURRENCE_LEGACY_ANCHOR_TIMEZONE``. Repeated as a literal because a
#: migration must keep meaning the same thing after the constant is edited.
_ASSUMED_SOURCE_ZONE = "UTC"


def _column_exists(conn, column: str) -> bool:
    return conn.execute(
        sa.text(
            "SELECT 1 FROM information_schema.columns "
            "WHERE table_name = :table AND column_name = :column"
        ),
        {"table": _TABLE, "column": column},
    ).fetchone() is not None


def _table_exists(conn) -> bool:
    return conn.execute(
        sa.text("SELECT 1 FROM information_schema.tables WHERE table_name = :table"),
        {"table": _TABLE},
    ).fetchone() is not None


def upgrade() -> None:
    conn = op.get_bind()
    if not _table_exists(conn):
        return
    if _column_exists(conn, _COLUMN):
        return
    op.add_column(
        _TABLE,
        sa.Column(
            _COLUMN,
            sa.String(64),
            nullable=False,
            server_default=_ASSUMED_SOURCE_ZONE,
        ),
    )


def downgrade() -> None:
    conn = op.get_bind()
    if _table_exists(conn) and _column_exists(conn, _COLUMN):
        op.drop_column(_TABLE, _COLUMN)

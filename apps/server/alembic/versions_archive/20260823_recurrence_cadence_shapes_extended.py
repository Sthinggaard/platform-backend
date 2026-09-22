"""#265 — the cadence model reaches the shapes the schedule editor offers.

Four of the seven shapes the editor offers could not be stored: several weekdays
at once, an interval on the frequency rather than only on days, monthly on a
named day, and yearly on a named date.

**Existing rows keep their meaning without a backfill script.** ``cadence_days``
becomes ``cadence_interval`` and the two disagree in exactly one case, which the
data migration handles: a weekday schedule carried ``cadence_days = 7`` as a
placeholder, and "every 7 weeks" is not what it meant. Those rows become
``cadence_interval = 1`` — every 1 week — which is what they always did.

``cadence_weekday`` (one nullable day) becomes ``cadence_weekdays`` (a set), and
an existing day becomes a set of one.

The old columns are dropped rather than kept: the criterion was that
``cadence_days`` keep one meaning or be migrated with every caller updated in the
same change, and leaving both would give "how often" two homes.

Idempotent throughout — every step is guarded on the column's presence, so a
re-run is a no-op.

**On the inline ``nosemgrep`` suppressions.** Semgrep's ``avoid-sqlalchemy-text``
rule fires on every ``sa.text()`` here. Each one is a literal SQL string written
in this file, with the only interpolation being a table or column name held in a
module constant — never a value a request could reach. Where a value does vary it
is bound as a parameter, not formatted in. Suppressed at each site with the rule
id rather than excluded wholesale, per the security gate's own narrow-exception
rule.
"""

from alembic import op
import sqlalchemy as sa

revision = "20260823_recurrence_cadence_shapes_extended"
down_revision = "20260823_recurrence_schedule_anchor_timezone"
branch_labels = None
depends_on = None

_TABLE = "recurrence_schedules"
#: Mirrors ``RecurrenceCadenceType.DAY_OF_WEEK``. Repeated as a literal because a
#: migration must keep meaning the same thing after the enum is edited.
_DAY_OF_WEEK = "day_of_week"


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

    if not _column_exists(conn, "cadence_interval"):
        op.add_column(
            _TABLE,
            sa.Column("cadence_interval", sa.Integer(), nullable=False, server_default="1"),
        )
        if _column_exists(conn, "cadence_days"):
            # An interval schedule meant its days; a weekday schedule's 7 was a
            # placeholder for a NOT NULL column and means one week.
            conn.execute(
                sa.text(  # nosemgrep: python.sqlalchemy.security.audit.avoid-sqlalchemy-text.avoid-sqlalchemy-text
                    f"UPDATE {_TABLE} SET cadence_interval = cadence_days "
                    "WHERE cadence_type <> :weekly"
                ),
                {"weekly": _DAY_OF_WEEK},
            )

    if not _column_exists(conn, "cadence_weekdays"):
        op.add_column(
            _TABLE,
            sa.Column("cadence_weekdays", sa.JSON(), nullable=False, server_default="[]"),
        )
        if _column_exists(conn, "cadence_weekday"):
            conn.execute(
                sa.text(  # nosemgrep: python.sqlalchemy.security.audit.avoid-sqlalchemy-text.avoid-sqlalchemy-text
                    f"UPDATE {_TABLE} "
                    "SET cadence_weekdays = json_build_array(cadence_weekday)::json "
                    "WHERE cadence_weekday IS NOT NULL"
                )
            )

    for column in ("cadence_day_of_month", "cadence_month"):
        if not _column_exists(conn, column):
            op.add_column(_TABLE, sa.Column(column, sa.Integer(), nullable=True))

    for column in ("cadence_days", "cadence_weekday"):
        if _column_exists(conn, column):
            op.drop_column(_TABLE, column)


def downgrade() -> None:
    conn = op.get_bind()
    if not _table_exists(conn):
        return

    if not _column_exists(conn, "cadence_days"):
        op.add_column(
            _TABLE, sa.Column("cadence_days", sa.Integer(), nullable=False, server_default="7")
        )
        if _column_exists(conn, "cadence_interval"):
            conn.execute(
                sa.text(  # nosemgrep: python.sqlalchemy.security.audit.avoid-sqlalchemy-text.avoid-sqlalchemy-text
                    f"UPDATE {_TABLE} SET cadence_days = CASE "
                    "WHEN cadence_type = :weekly THEN 7 ELSE cadence_interval END"
                ),
                {"weekly": _DAY_OF_WEEK},
            )

    if not _column_exists(conn, "cadence_weekday"):
        op.add_column(_TABLE, sa.Column("cadence_weekday", sa.Integer(), nullable=True))
        if _column_exists(conn, "cadence_weekdays"):
            # Only the first survives — the shapes this reverts to cannot hold a
            # set, which is why the downgrade loses information and says so.
            conn.execute(
                sa.text(  # nosemgrep: python.sqlalchemy.security.audit.avoid-sqlalchemy-text.avoid-sqlalchemy-text
                    f"UPDATE {_TABLE} "
                    "SET cadence_weekday = (cadence_weekdays->>0)::int "
                    "WHERE json_array_length(cadence_weekdays) > 0"
                )
            )

    for column in ("cadence_month", "cadence_day_of_month", "cadence_weekdays", "cadence_interval"):
        if _column_exists(conn, column):
            op.drop_column(_TABLE, column)

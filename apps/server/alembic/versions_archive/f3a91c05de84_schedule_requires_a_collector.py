"""#260 — a schedule is made for a Collector, so it must name one.

Søren, 2026-08-19: *"the schedule is made for the scanner, not the other way
around, so having a schedule with no collector makes no sense."*

``scanner_instance_id`` was nullable on the reasoning that the recurrence
primitive did not require a Collector. That was true of the primitive and false
of the product: a schedule with no Collector runs nothing, and — since #260 put
the schedule on the Collector's own page — it would also have nowhere to be read.

**The foreign key changes with it.** ``ON DELETE SET NULL`` is impossible against
a NOT NULL column, and CASCADE would take the occurrence ledger with it — the
audit record of everything the cadence ever did. ``RESTRICT`` follows the
instinct CA-07.5 already recorded (*a completed access journey must outlive the
Connector it went through*) and costs nothing in practice: a Collector is
**retired**, which is a status change, never a row deletion.

**Guarded on the data, not only on the schema.** The NOT NULL is only applied
when no orphan rows exist; if any do, the migration raises rather than inventing
a Collector for them or deleting somebody's schedule. Verified before writing:
0 schedules, 0 without a Collector.

Revision ID: f3a91c05de84
Revises: e2f84b16cd73
Create Date: 2026-08-19 00:00:00.000000

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

revision = "f3a91c05de84"
down_revision = "e2f84b16cd73"
branch_labels = None
depends_on = None

_TABLE = "recurrence_schedules"
_COLUMN = "scanner_instance_id"
_FK = "recurrence_schedules_scanner_instance_id_fkey"


def _is_nullable(conn) -> bool:
    row = conn.execute(
        sa.text(
            "SELECT is_nullable FROM information_schema.columns "
            "WHERE table_name = :t AND column_name = :c"
        ),
        {"t": _TABLE, "c": _COLUMN},
    ).fetchone()
    return bool(row) and row[0] == "YES"


def upgrade() -> None:
    conn = op.get_bind()
    if not _is_nullable(conn):
        return

    orphans = conn.execute(
        sa.text(f"SELECT count(*) FROM {_TABLE} WHERE {_COLUMN} IS NULL")  # nosemgrep: python.sqlalchemy.security.audit.avoid-sqlalchemy-text.avoid-sqlalchemy-text
    ).scalar_one()
    if orphans:
        # Neither inventing a Collector nor deleting a schedule somebody created
        # is this migration's call to make.
        raise RuntimeError(
            f"{orphans} recurrence schedule(s) have no collector. Decide what becomes of them "
            "before making the column NOT NULL."
        )

    op.alter_column(_TABLE, _COLUMN, existing_type=sa.String(36), nullable=False)

    # Re-point the foreign key: SET NULL cannot hold against NOT NULL.
    op.drop_constraint(_FK, _TABLE, type_="foreignkey")
    op.create_foreign_key(
        _FK, _TABLE, "scanner_instances", [_COLUMN], ["id"], ondelete="RESTRICT"
    )


def downgrade() -> None:
    conn = op.get_bind()
    if _is_nullable(conn):
        return
    op.drop_constraint(_FK, _TABLE, type_="foreignkey")
    op.create_foreign_key(
        _FK, _TABLE, "scanner_instances", [_COLUMN], ["id"], ondelete="SET NULL"
    )
    op.alter_column(_TABLE, _COLUMN, existing_type=sa.String(36), nullable=True)

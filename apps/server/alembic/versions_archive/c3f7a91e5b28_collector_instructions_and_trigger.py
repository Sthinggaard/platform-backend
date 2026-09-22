"""Operational instructions to a Collector, and why a self-check ran (CA-02.3 slice 3).

Two additive changes, both in service of the same question this story keeps
asking: *can this be attributed to someone?*

1. ``scanner_instances`` gains one pending operational instruction. A single
   nullable column rather than a queue table, deliberately — these instructions
   coalesce by nature (pressing "Run self-check again" five times wants one
   fresh answer, not five checks), and a queue would faithfully deliver five and
   grow unbounded while a Collector is offline.

   Kept out of ``scanner_commands`` on domain grounds: a discovery command
   carries authority to act on approved external targets, which is why it is
   signed, scope-bound, and NOT NULL on ``discovery_run_id``. An operational
   instruction touches nothing outside the Collector, so reusing that envelope
   would force a required invariant to be dropped in exchange for security
   machinery it never uses.

2. ``collector_readiness_reports`` gains ``trigger`` and ``requested_by_user_id``.
   A report previously could not say whether it was a routine measurement or the
   answer to a named person pressing a button — the same
   assertion-vs-measurement ambiguity CA-02.3 exists to remove, one level up.

Both nullable: every existing row predates the distinction and must not be
retroactively labelled. A NULL ``trigger`` means "this report predates trigger
recording", which is honest, where defaulting it to 'periodic' would be an
invented fact.

Revision ID: c3f7a91e5b28
Revises: b8e1d4a72f95
Create Date: 2026-08-14 00:00:00.000000
"""

from alembic import op
import sqlalchemy as sa

revision = "c3f7a91e5b28"
down_revision = "b8e1d4a72f95"
branch_labels = None
depends_on = None

_INSTANCES = "scanner_instances"
_REPORTS = "collector_readiness_reports"

_INSTANCE_COLUMNS = (
    ("pending_instruction", sa.String(30)),
    ("pending_instruction_requested_at", sa.DateTime()),
    ("pending_instruction_requested_by_user_id", sa.Integer()),
)
_REPORT_COLUMNS = (
    ("trigger", sa.String(20)),
    ("requested_by_user_id", sa.Integer()),
)


def _table_exists(conn, table: str) -> bool:
    return conn.execute(
        sa.text("SELECT 1 FROM information_schema.tables WHERE table_name = :t"),
        {"t": table},
    ).fetchone() is not None


def _col_exists(conn, table: str, column: str) -> bool:
    return conn.execute(
        sa.text(
            "SELECT 1 FROM information_schema.columns "
            "WHERE table_name = :t AND column_name = :c"
        ),
        {"t": table, "c": column},
    ).fetchone() is not None


def upgrade() -> None:
    conn = op.get_bind()

    for table, columns in ((_INSTANCES, _INSTANCE_COLUMNS), (_REPORTS, _REPORT_COLUMNS)):
        if not _table_exists(conn, table):
            continue
        for name, type_ in columns:
            if not _col_exists(conn, table, name):
                op.add_column(table, sa.Column(name, type_, nullable=True))

    # Foreign keys added separately and guarded: the columns above may already
    # exist from a partial run, and add_column would not have created these.
    if _table_exists(conn, "users"):
        for table, column, fk_name in (
            (_INSTANCES, "pending_instruction_requested_by_user_id", "fk_scanner_instances_instruction_user"),
            (_REPORTS, "requested_by_user_id", "fk_collector_readiness_requested_by"),
        ):
            if not _table_exists(conn, table) or not _col_exists(conn, table, column):
                continue
            existing = conn.execute(
                sa.text("SELECT 1 FROM pg_constraint WHERE conname = :n"), {"n": fk_name}
            ).fetchone()
            if existing is None:
                op.create_foreign_key(fk_name, table, "users", [column], ["id"], ondelete="SET NULL")


def downgrade() -> None:
    conn = op.get_bind()

    for fk_name, table in (
        ("fk_scanner_instances_instruction_user", _INSTANCES),
        ("fk_collector_readiness_requested_by", _REPORTS),
    ):
        existing = conn.execute(
            sa.text("SELECT 1 FROM pg_constraint WHERE conname = :n"), {"n": fk_name}
        ).fetchone()
        if existing is not None:
            op.drop_constraint(fk_name, table, type_="foreignkey")

    for table, columns in ((_INSTANCES, _INSTANCE_COLUMNS), (_REPORTS, _REPORT_COLUMNS)):
        if not _table_exists(conn, table):
            continue
        for name, _type in columns:
            if _col_exists(conn, table, name):
                op.drop_column(table, name)

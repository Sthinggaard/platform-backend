"""Repair discovery schema drift between the models and deployed databases.

Local databases here are created by ``Base.metadata.create_all()`` at API
startup (``src/core/database.py``), not by alembic — the alembic history has
several heads and only one applied revision. ``create_all`` creates missing
*tables* but never adds a column to a table that already exists, so every
additive column shipped since ``discovery_runs`` was first created is silently
absent, and the code then fails at runtime with e.g.

    UndefinedColumn: column discovery_runs.business_process_id does not exist

Confirmed on a working local database 2026-08-12: eight columns missing across
three tables, which stopped the discovery execution worker dead on every job.

Every statement is additive and idempotent (``ADD COLUMN IF NOT EXISTS``,
nullable), so this is safe to run on a database that already has them — a
database built correctly by CA-04.7/CA-04.8's own migrations is unaffected.
Nothing is dropped and no data is rewritten.

This does not reconcile the multiple alembic heads; that is a separate,
larger piece of work.

Revision ID: b3d7e1c95a20
Revises: 9c1e7b4a2f05
Create Date: 2026-08-12 00:00:00.000000
"""

from alembic import op
import sqlalchemy as sa

revision = "b3d7e1c95a20"
down_revision = "9c1e7b4a2f05"
branch_labels = None
depends_on = None


# (table, column, type) — nullable by design: these tables already hold rows,
# so a NOT NULL addition without a default would fail on a populated database.
# Typed as real SQLAlchemy types rather than SQL type strings so the columns can
# be added through ``op.add_column`` — see the note on _col_exists below.
_ADDITIVE_COLUMNS: list[tuple[str, str, sa.types.TypeEngine]] = [
    # CA-04.7 — process-aware execution context
    ("discovery_runs", "business_process_id", sa.String(36)),
    ("discovery_runs", "business_service_id", sa.String(36)),
    ("discovery_runs", "process_scan_scope_id", sa.String(36)),
    ("discovery_runs", "process_scan_scope_revision", sa.Integer()),
    ("scanner_commands", "business_process_id", sa.String(36)),
    ("scanner_commands", "business_service_id", sa.String(36)),
    # CA-04.2 — real check-key vocabulary on the command envelope
    ("scanner_commands", "check_key", sa.String(30)),
    # CA-04.1 — per-instance command signing key
    ("scanner_instances", "command_signing_key_encrypted", sa.LargeBinary()),
]


def _table_exists(conn, table: str) -> bool:
    return conn.execute(
        sa.text("SELECT 1 FROM information_schema.tables WHERE table_name=:t"),
        {"t": table},
    ).fetchone() is not None


def _col_exists(conn, table: str, col: str) -> bool:
    return conn.execute(
        sa.text(
            "SELECT 1 FROM information_schema.columns WHERE table_name=:t AND column_name=:c"
        ),
        {"t": table, "c": col},
    ).fetchone() is not None


def upgrade() -> None:
    # Idempotency now comes from the repo's own _table_exists/_col_exists guards
    # plus op.add_column, rather than a formatted ``ADD COLUMN IF NOT EXISTS``
    # string. Behaviour is identical and still additive-only; the string form
    # was flagged by Semgrep (avoid-sqlalchemy-text) and, although nothing
    # user-supplied could reach it — every value comes from the module-level
    # constant above — it also diverged from the guarded-DDL pattern every other
    # migration in this directory uses.
    conn = op.get_bind()
    for table, column, column_type in _ADDITIVE_COLUMNS:
        if not _table_exists(conn, table):
            # The table itself is created elsewhere (its own migration, or
            # create_all). Nothing to repair here if it is not present yet.
            continue
        if _col_exists(conn, table, column):
            continue
        op.add_column(table, sa.Column(column, column_type, nullable=True))


def downgrade() -> None:
    # Deliberately not reversed. These columns are part of the current models;
    # dropping them would break the running application, and this migration
    # exists to close a gap rather than to introduce anything new.
    pass

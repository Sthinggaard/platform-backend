"""Index the signal batch lookup, which needs payload_json to be jsonb.

BUG-DISC-18. Normalisation finds the signals already written for an ingestion
batch by reading ``payload_json->'ingestionBatchId'``. There was no index that
could serve it, so every batch cost a sequential scan of the whole table — the
same table that had grown to 14.5 million rows, which is how BUG-DISC-12 ended
up unable to finish at all.

An expression index cannot be built over ``json``: the type has no equality
operator, so there is nothing for an index to order by. ``jsonb`` does, which is
why the column type changes here rather than in a separate step — the migration
exists *for* the index, and converting without adding it would be all of the
risk and none of the benefit.

**Order matters.** The fabricated simulator rows are removed first, by
``scripts/purge_simulated_signals.py``, precisely so this runs against a small
table: converting 3.6 GB of json in place would hold an ACCESS EXCLUSIVE lock
for minutes on a table the discovery pipeline writes to. Against the real
evidence that remains it is effectively instant. If this migration is ever run
on a database where the purge has not happened, it will still be correct — just
slow — so the ordering is a performance property, not a correctness one.

Idempotent per the repo's rules: the column change is skipped when the type is
already ``jsonb``, and the index is created ``IF NOT EXISTS``.

Expressed with Alembic's own ``alter_column`` / ``create_index`` operations
rather than formatted ``sa.text`` DDL. Nothing user-supplied could ever reach
those strings — every interpolated value was a module-level constant — but the
formatted form was flagged by Semgrep (``avoid-sqlalchemy-text``) and diverged
from the guarded-DDL pattern the rest of this directory uses, exactly as
``b3d7e1c95a20`` did. The emitted SQL is unchanged.

Revision ID: a2d5f9c31b70
Revises: f1c8b3e07a95
Create Date: 2026-08-13 00:00:00.000000
"""

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision = "a2d5f9c31b70"
down_revision = "f1c8b3e07a95"
branch_labels = None
depends_on = None

_TABLE = "asset_evidence_signals"
_INDEX = "ix_asset_signals_ingestion_batch"


def _table_exists(conn, table: str) -> bool:
    return conn.execute(
        sa.text("SELECT 1 FROM information_schema.tables WHERE table_name = :t"),
        {"t": table},
    ).fetchone() is not None


def _column_type(conn, table: str, column: str) -> str | None:
    row = conn.execute(
        sa.text(
            "SELECT data_type FROM information_schema.columns "
            "WHERE table_name = :t AND column_name = :c"
        ),
        {"t": table, "c": column},
    ).fetchone()
    return row[0] if row else None


def upgrade() -> None:
    conn = op.get_bind()
    if conn.dialect.name != "postgresql":
        # SQLite (the test database) has no jsonb and needs no index to stay
        # fast at test volumes. Skipping keeps the suite running against the
        # same migration chain rather than a divergent one.
        return
    if not _table_exists(conn, _TABLE):
        return

    if _column_type(conn, _TABLE, "payload_json") == "json":
        op.alter_column(
            _TABLE,
            "payload_json",
            existing_type=postgresql.JSON(),
            type_=postgresql.JSONB(),
            postgresql_using="payload_json::jsonb",
        )

    # The expression must match what the ORM actually emits, character for
    # character, or the planner will not use it. `payload_json['x'].as_integer()`
    # compiles to `CAST((payload_json ->> 'x') AS INTEGER)` — the ->> text
    # accessor and a cast, not the -> object accessor. An index on the latter
    # looks plausible, is accepted without complaint, and is never used.
    #
    # Composite with organization_id because normalisation always filters both,
    # and tenant scoping is not optional anywhere in this codebase.
    #
    # The cast is safe to index: `ingestionBatchId` is written only by
    # risk_intelligence_normalization_service, always from `batch.id`, and rows
    # of other kinds simply have no such key (->> yields NULL, which casts
    # cleanly). A non-numeric value would already have broken this query at read
    # time; indexing it means the failure would surface on write instead.
    op.create_index(
        _INDEX,
        _TABLE,
        [
            "organization_id",
            sa.text("(CAST((payload_json ->> 'ingestionBatchId') AS INTEGER))"),
        ],
        if_not_exists=True,
    )


def downgrade() -> None:
    conn = op.get_bind()
    if conn.dialect.name != "postgresql":
        return
    op.drop_index(_INDEX, table_name=_TABLE, if_exists=True)
    if _column_type(conn, _TABLE, "payload_json") == "jsonb":
        op.alter_column(
            _TABLE,
            "payload_json",
            existing_type=postgresql.JSONB(),
            type_=postgresql.JSON(),
            postgresql_using="payload_json::json",
        )

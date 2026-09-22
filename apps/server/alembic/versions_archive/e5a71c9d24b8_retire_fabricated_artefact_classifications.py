"""Replace fabricated discovery classifications with an honest "Unknown".

BUG-DISC-15. Discovery used to record ``layer`` as "Application" whenever a host
had any open port and "Network" when it had none — whether the scan found ports,
not what the thing is — and ``type`` from a key nmap never emits, so every
discovered artefact was a "Service". Søren's router came out "Service ·
Application".

The code no longer does that. These are the rows it already wrote. They cannot
be re-derived by re-scanning, because the matched-asset path in normalisation
deliberately never overwrites an existing row (that is what makes a human
correction survive), so without this they would assert a fabricated class
forever.

Scope is deliberately narrow:

* only ``provider = 'collector'`` — rows this platform invented, never a
  customer's own asset;
* only the exact value pair the old inference could produce —
  ``type = 'Service'`` with ``layer`` in ('Application', 'Network'). No human
  correction produces that combination, because correcting a classification
  replaces both fields with real ones.

Deliberately **not** guarded on ``reviewed_at``. Confirming an artefact means
"yes, this is ours" — it says nothing about whether the label is right, and
treating it as approval of the classification would leave a fabricated class in
place precisely on the rows someone had already looked at. The value guard above
is what protects a genuine correction.

Setting them to "Unknown" is not a loss of information. The previous values
carried none: every row said the same thing regardless of what was observed.
"Unknown" is the honest state, it is visible in the review list, and a reviewer
can correct it.

Revision ID: e5a71c9d24b8
Revises: d7e93c1f80a4
Create Date: 2026-08-13 00:00:00.000000
"""

from alembic import op
import sqlalchemy as sa

revision = "e5a71c9d24b8"
down_revision = "d7e93c1f80a4"
branch_labels = None
depends_on = None


def _col_exists(conn, table: str, col: str) -> bool:
    return conn.execute(
        sa.text(
            "SELECT 1 FROM information_schema.columns WHERE table_name=:t AND column_name=:c"
        ),
        {"t": table, "c": col},
    ).fetchone() is not None


def upgrade() -> None:
    conn = op.get_bind()
    if not _col_exists(conn, "assets", "reviewed_at"):
        return  # d7e93c1f80a4 has not run; nothing to reason about safely

    conn.execute(
        sa.text(
            """
            UPDATE assets
               SET layer = 'Unknown',
                   type  = 'Unknown'
             WHERE provider = 'collector'
               AND type = 'Service'
               AND layer IN ('Application', 'Network')
            """
        )
    )


def downgrade() -> None:
    # Deliberately not reversed: the previous values were fabricated, and
    # restoring them would reassert a claim the evidence never supported.
    pass

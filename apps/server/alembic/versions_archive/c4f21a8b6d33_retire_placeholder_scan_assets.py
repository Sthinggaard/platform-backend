"""Retire the placeholder assets discovery invented for empty scans.

BUG-DISC-14: a provider that returned no host records used to have one
synthesised for it, which became a real ``Asset`` row named after an internal
evidence-package id — ``subfinder-scan-a55ee57c`` — or, one layer down, after
the batch source (``discovery_execution:subfinder``). Those rows describe a
scan, not anything the organisation owns, and they appeared on the screen where
an executive approves their own inventory.

The code no longer creates them. This retires the ones already on record.

**Marked, never deleted.** These rows are set to ``REMOVED``, the same state a
human rejection produces, so:

* the evidence and audit trail that produced them stay intact;
* a reviewer who disagrees can restore one through the normal review action
  (#150) — this migration is not a decision that cannot be undone;
* nothing is destroyed by a schema migration, which is not the place for it.

Matching is deliberately narrow — the exact ``<provider>-scan-<8 hex>`` shape
this bug produced, plus the ``discovery_execution:`` prefix, and only rows this
platform created itself (``provider = 'collector'``). A customer asset that
happens to be named like a scan is not touched.

Revision ID: c4f21a8b6d33
Revises: b3d7e1c95a20
Create Date: 2026-08-13 00:00:00.000000
"""

from alembic import op
import sqlalchemy as sa

revision = "c4f21a8b6d33"
down_revision = "b3d7e1c95a20"
branch_labels = None
depends_on = None


def _table_exists(conn, table: str) -> bool:
    return conn.execute(
        sa.text("SELECT 1 FROM information_schema.tables WHERE table_name=:t"),
        {"t": table},
    ).fetchone() is not None


def upgrade() -> None:
    conn = op.get_bind()
    if not _table_exists(conn, "assets"):
        return

    # Idempotent: re-running only re-matches rows already REMOVED, and changes
    # nothing.
    conn.execute(
        sa.text(
            """
            UPDATE assets
               SET lifecycle_state = 'REMOVED'
             WHERE provider = 'collector'
               AND lifecycle_state <> 'REMOVED'
               AND (
                     display_name ~ '^[a-z0-9_]+-scan-[0-9a-f]{8}$'
                  OR display_name LIKE 'discovery\\_execution:%'
               )
            """
        )
    )


def downgrade() -> None:
    # Deliberately not reversed. Restoring every matching row to ACTIVE would
    # also resurrect any a human had genuinely rejected, and this migration
    # cannot tell the two apart. Individual rows can be restored through the
    # artefact review action.
    pass

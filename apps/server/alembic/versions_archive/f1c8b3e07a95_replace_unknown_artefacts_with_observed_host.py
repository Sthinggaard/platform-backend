"""Say "Observed host" where discovery previously said "Unknown".

Follow-up to e5a71c9d24b8, which replaced a fabricated classification with
"Unknown" — honest, but it made a real inventory read as a failed one: every row
in the review list said "Unknown · Unknown" and the discovery looked useless.

A host that answered a scan *is* a host. That is observed, not inferred, so the
floor is now L1 Infrastructure / "Observed host" and only what a host is *for*
is left unstated when the evidence does not support it.

These rows cannot be re-derived by re-scanning — the matched-asset path never
overwrites an existing row, which is what makes a human correction survive — so
they are updated here. Scoped to rows this platform created itself and to the
exact placeholder pair the previous migration wrote, so nothing a person set is
touched.

The services each host was observed on cannot be recovered for these rows: they
were never persisted before this change. The next discovery that observes them
refreshes that evidence in place.

Revision ID: f1c8b3e07a95
Revises: e5a71c9d24b8
Create Date: 2026-08-13 00:00:00.000000
"""

from alembic import op
import sqlalchemy as sa

revision = "f1c8b3e07a95"
down_revision = "e5a71c9d24b8"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.get_bind().execute(
        sa.text(
            """
            UPDATE assets
               SET layer = 'L1',
                   type  = 'Observed host'
             WHERE provider = 'collector'
               AND type = 'Unknown'
               AND layer = 'Unknown'
            """
        )
    )


def downgrade() -> None:
    # Deliberately not reversed: "Unknown" said less than the evidence supports.
    pass

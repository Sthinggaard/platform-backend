"""An excluded target leaves the inventory, and says why (CA-06.5).

``DiscoveryScopeProposal.exclusions`` is the boundary a human signed off, and
discovery already refuses to *scan* an excluded target. Nothing applied that
boundary to the **inventory**, so approving an exclusion changed what would be
scanned next and nothing about what the organisation was looking at.

Two columns, because a withdrawal nobody can explain is indistinguishable from a
bug: ``withdrawn_by_exclusion`` names the pattern that caught the artefact and
``withdrawn_at`` says when. The reviewer gets the answer on the row rather than
having to go and find the audit event.

No column is added for the state itself — ``assets.lifecycle_state`` is a plain
VARCHAR (``native_enum=False``) with no CHECK constraint on it, which is why
``NOT_USED`` was added to the enum without a migration too. Verified against the
live schema rather than assumed.

Idempotent per the repo's rules: guarded with ``_column_exists``.

Revision ID: b7e5c02a9d41
Revises: a4d1c86f2e93
Create Date: 2026-08-16 00:00:00.000000
"""

from alembic import op
import sqlalchemy as sa

revision = "b7e5c02a9d41"
down_revision = "a4d1c86f2e93"
branch_labels = None
depends_on = None

_TABLE = "assets"
_EXCLUSION_COLUMN = "withdrawn_by_exclusion"
_WITHDRAWN_AT_COLUMN = "withdrawn_at"


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

    if not _column_exists(conn, _TABLE, _EXCLUSION_COLUMN):
        op.add_column(_TABLE, sa.Column(_EXCLUSION_COLUMN, sa.String(255), nullable=True))
    if not _column_exists(conn, _TABLE, _WITHDRAWN_AT_COLUMN):
        op.add_column(_TABLE, sa.Column(_WITHDRAWN_AT_COLUMN, sa.DateTime(), nullable=True))


def downgrade() -> None:
    conn = op.get_bind()

    # Any artefact currently withdrawn goes back to review rather than being
    # left in a state whose explanation this migration is about to delete.
    # Downgrading must not leave records that say "withdrawn" with nothing
    # saying why.
    conn.execute(
        sa.text(
            "UPDATE assets SET lifecycle_state = 'UNCONFIRMED' WHERE lifecycle_state = 'WITHDRAWN'"
        )
    )

    if _column_exists(conn, _TABLE, _WITHDRAWN_AT_COLUMN):
        op.drop_column(_TABLE, _WITHDRAWN_AT_COLUMN)
    if _column_exists(conn, _TABLE, _EXCLUSION_COLUMN):
        op.drop_column(_TABLE, _EXCLUSION_COLUMN)

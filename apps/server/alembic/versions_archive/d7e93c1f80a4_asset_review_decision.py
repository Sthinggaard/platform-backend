"""Record that a human reviewed a discovered artefact.

#150 gave people Confirm / Not ours, but confirming left no trace: most
discovered rows are created ``ACTIVE``, so confirming one changed no state and
the row re-rendered identically. The decision existed only in the audit trail —
invisible to the screen that asked for it, so a reviewer could not tell which
artefacts they had already dealt with.

``reviewed_at``/``reviewed_by_user_id`` make the decision a fact about the
record. Deliberately separate from ``lifecycle_state``: "a person agreed this is
ours" and "this row is active" are different statements, and collapsing them is
what hid the decision in the first place.

Revision ID: d7e93c1f80a4
Revises: c4f21a8b6d33
Create Date: 2026-08-13 00:00:00.000000
"""

from alembic import op
import sqlalchemy as sa

revision = "d7e93c1f80a4"
down_revision = "c4f21a8b6d33"
branch_labels = None
depends_on = None


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
    conn = op.get_bind()
    if not _table_exists(conn, "assets"):
        return
    if not _col_exists(conn, "assets", "reviewed_at"):
        op.add_column("assets", sa.Column("reviewed_at", sa.DateTime(), nullable=True))
    if not _col_exists(conn, "assets", "reviewed_by_user_id"):
        op.add_column(
            "assets",
            sa.Column(
                "reviewed_by_user_id",
                sa.Integer(),
                sa.ForeignKey("users.id", ondelete="SET NULL"),
                nullable=True,
            ),
        )


def downgrade() -> None:
    conn = op.get_bind()
    if not _table_exists(conn, "assets"):
        return
    # Dropping these discards a record of human decisions, so it is done only on
    # an explicit downgrade and never as a side effect.
    if _col_exists(conn, "assets", "reviewed_by_user_id"):
        op.drop_column("assets", "reviewed_by_user_id")
    if _col_exists(conn, "assets", "reviewed_at"):
        op.drop_column("assets", "reviewed_at")

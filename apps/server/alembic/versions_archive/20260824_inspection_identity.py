"""CA-08.4 (#292) — what an inspection established, recorded beside it.

Four additive columns on ``verification_inspection_commands``:

- ``asset_id`` — denormalised from the run, because both identity recording and
  the verification surface ask "what is known about *this artefact*", and
  joining through the run for every such question buys nothing.
- ``identity_name`` / ``identity_basis`` / ``identity_evidence`` — the name this
  run read out of the host, how, and the line of output supporting it.

There is still **no ``stdout`` column**, deliberately. What the output
established is recorded; the output itself is read, used and dropped.

Guarded per column, so a re-run is a no-op.

**On the inline ``nosemgrep``**: ``avoid-sqlalchemy-text`` fires on the
existence check. It is a literal string with no interpolation — table and column
names are module constants — so nothing a request can reach.
"""

from alembic import op
import sqlalchemy as sa

revision = "20260824_inspection_identity"
down_revision = "20260824_verification_inspection_commands"
branch_labels = None
depends_on = None

_TABLE = "verification_inspection_commands"


def _col_exists(conn, column: str) -> bool:
    return conn.execute(
        sa.text(  # nosemgrep: python.sqlalchemy.security.audit.avoid-sqlalchemy-text.avoid-sqlalchemy-text
            "SELECT 1 FROM information_schema.columns "
            "WHERE table_name = :table AND column_name = :column"
        ),
        {"table": _TABLE, "column": column},
    ).fetchone() is not None


def upgrade() -> None:
    conn = op.get_bind()

    # Nullable on arrival even though the model requires it: existing rows have
    # no value, and a NOT NULL with a fabricated default would invent an
    # artefact association that was never true. The table is days old and
    # carries only this epic's own rows.
    if not _col_exists(conn, "asset_id"):
        op.add_column(
            _TABLE,
            sa.Column(
                "asset_id",
                sa.Integer(),
                sa.ForeignKey("assets.id", ondelete="CASCADE"),
                nullable=True,
            ),
        )
    for column, length in (
        ("identity_name", 200),
        ("identity_basis", 30),
        ("identity_evidence", 200),
    ):
        if not _col_exists(conn, column):
            op.add_column(_TABLE, sa.Column(column, sa.String(length), nullable=True))


def downgrade() -> None:
    conn = op.get_bind()
    for column in ("identity_evidence", "identity_basis", "identity_name", "asset_id"):
        if _col_exists(conn, column):
            op.drop_column(_TABLE, column)

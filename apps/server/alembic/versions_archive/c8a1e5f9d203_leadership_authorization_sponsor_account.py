"""Leadership authorisation sponsor becomes a real account, not free text

Accountability requires the ability to actually see and act on what you're
named accountable for. sponsor_name/sponsor_title were free text with no
link to a platform account; replaced with sponsor_user_id (FK to users,
nullable). Only that named user may approve/reject the record going
forward. Display name/title are derived from the User row at read time.
Nullable because a backfilled/legacy record must never invent a sponsor
that was never actually named.

No production data exists for this table yet (created same day as this
migration).

Revision ID: c8a1e5f9d203
Revises: b3f0d1a2c9e5
Create Date: 2026-07-15 00:00:00.000000
"""

from alembic import op
import sqlalchemy as sa

revision = "c8a1e5f9d203"
down_revision = "b3f0d1a2c9e5"
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
    if not _table_exists(conn, "leadership_authorizations"):
        return

    if not _col_exists(conn, "leadership_authorizations", "sponsor_user_id"):
        op.add_column(
            "leadership_authorizations",
            sa.Column(
                "sponsor_user_id",
                sa.Integer(),
                sa.ForeignKey("users.id", ondelete="RESTRICT"),
                nullable=True,
            ),
        )
        conn.execute(
            sa.text(
                "UPDATE leadership_authorizations "
                "SET sponsor_user_id = CAST(prepared_by AS INTEGER) "
                "WHERE prepared_by ~ '^[0-9]+$' AND backfilled = false"
            )
        )

    if _col_exists(conn, "leadership_authorizations", "sponsor_name"):
        op.drop_column("leadership_authorizations", "sponsor_name")
    if _col_exists(conn, "leadership_authorizations", "sponsor_title"):
        op.drop_column("leadership_authorizations", "sponsor_title")


def downgrade() -> None:
    conn = op.get_bind()
    if not _table_exists(conn, "leadership_authorizations"):
        return
    if not _col_exists(conn, "leadership_authorizations", "sponsor_name"):
        op.add_column("leadership_authorizations", sa.Column("sponsor_name", sa.String(255), nullable=True))
    if not _col_exists(conn, "leadership_authorizations", "sponsor_title"):
        op.add_column("leadership_authorizations", sa.Column("sponsor_title", sa.String(255), nullable=True))
    if _col_exists(conn, "leadership_authorizations", "sponsor_user_id"):
        op.drop_column("leadership_authorizations", "sponsor_user_id")

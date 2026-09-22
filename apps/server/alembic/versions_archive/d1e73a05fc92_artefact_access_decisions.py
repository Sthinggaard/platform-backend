"""CA-07.1 (#235) — every answer about deeper access, including the ones that ask for nothing.

Its own table rather than rows in ``artefact_access_lifecycles``. That table is a
*journey*: one row per artefact, a state machine, and CHECK constraints that only
make sense for access being sought. This is a *history*: many rows per artefact,
one per answer, and three of the five choices — ``network_only``, ``exclude`` and
``review_later`` — never start a journey at all.

Without it, "we decided network-only in August" and "nobody has looked at this"
are the same absence of data. That is the failure the standing-policy amendment
warns about in as many words: a default must never turn a real gap into an
invisible one.

``standing_default`` and ``identity_undetermined_reason`` are **snapshots, not
lookups**. The policy is versioned and can be superseded, and a later scan can
name an artefact that was anonymous when somebody decided about it. An auditor
asking "was this a deviation, and what were they looking at?" must get the answer
that was true at the moment of the decision.

``decided_by_user_id`` is ON DELETE SET NULL, never CASCADE, on the precedent
CA-07.5 set: a decision that loses its author is still a decision that was taken.
``asset_id`` is CASCADE — a decision about an artefact that no longer exists has
nothing left to be about.

Idempotent per the repo's rules: guarded on the table and on each index.

Revision ID: d1e73a05fc92
Revises: c9f31a70de85
Create Date: 2026-08-19 00:00:00.000000
"""

from alembic import op
import sqlalchemy as sa

revision = "d1e73a05fc92"
down_revision = "c9f31a70de85"
branch_labels = None
depends_on = None

_TABLE = "artefact_access_decisions"
_ORG_ASSET_INDEX = "ix_artefact_access_decisions_org_asset"
_ORG_COLUMN_INDEX = "ix_artefact_access_decisions_organization_id"


def _table_exists(conn, table: str) -> bool:
    return conn.execute(
        sa.text("SELECT 1 FROM information_schema.tables WHERE table_name = :t"),
        {"t": table},
    ).fetchone() is not None


def _index_exists(conn, index: str) -> bool:
    return conn.execute(
        sa.text("SELECT 1 FROM pg_indexes WHERE indexname = :i"),
        {"i": index},
    ).fetchone() is not None


def upgrade() -> None:
    conn = op.get_bind()

    if not _table_exists(conn, _TABLE):
        op.create_table(
            _TABLE,
            sa.Column("id", sa.String(36), primary_key=True),
            sa.Column(
                "organization_id",
                sa.Integer(),
                sa.ForeignKey("organizations.id"),
                nullable=False,
            ),
            sa.Column(
                "asset_id",
                sa.Integer(),
                sa.ForeignKey("assets.id", ondelete="CASCADE"),
                nullable=False,
            ),
            sa.Column("choice", sa.String(30), nullable=False),
            sa.Column("standing_default", sa.String(30), nullable=True),
            sa.Column("deviation_reason", sa.Text(), nullable=True),
            sa.Column("identity_undetermined_reason", sa.String(40), nullable=True),
            sa.Column("decided_at", sa.DateTime(), nullable=False),
            sa.Column(
                "decided_by_user_id",
                sa.Integer(),
                sa.ForeignKey("users.id", ondelete="SET NULL"),
                nullable=True,
            ),
            sa.Column("created_at", sa.DateTime(), nullable=False),
        )

    if not _index_exists(conn, _ORG_ASSET_INDEX):
        op.create_index(_ORG_ASSET_INDEX, _TABLE, ["organization_id", "asset_id"])
    if not _index_exists(conn, _ORG_COLUMN_INDEX):
        op.create_index(_ORG_COLUMN_INDEX, _TABLE, ["organization_id"])


def downgrade() -> None:
    conn = op.get_bind()
    if _index_exists(conn, _ORG_COLUMN_INDEX):
        op.drop_index(_ORG_COLUMN_INDEX, table_name=_TABLE)
    if _index_exists(conn, _ORG_ASSET_INDEX):
        op.drop_index(_ORG_ASSET_INDEX, table_name=_TABLE)
    if _table_exists(conn, _TABLE):
        op.drop_table(_TABLE)

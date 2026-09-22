"""A person resolves an uncertain match, and the merge is reversible (CA-06.4).

Identity resolution has always refused to guess — a candidate whose identifiers
are spread across two artefacts comes back as POSSIBLE_MATCH — but that refusal
had nowhere to go. The question lived in ``Asset.intent`` and an audit event, and
no code path could answer it. ``AssetLifecycleState.MERGED`` and
``Asset.merged_into_asset_id`` had existed since 20260719 with nothing writing
either one.

Two tables, because they answer two different questions:

``artefact_identity_conflicts`` — "the platform is unsure whether these two are
the same thing, and here is why." The pair is stored **ordered**
(lower_asset_id < higher_asset_id) with a unique index, so A-vs-B and B-vs-A are
one conflict; without that, a person could dismiss the pair in one direction and
be asked again in the other. The resolution is durable: a conflict resolved as
``resolved_separate`` is never re-raised, or the platform would overrule the
person every scan.

``artefact_merge_records`` — "a person decided they were the same thing, and this
is exactly what moved." ``moved`` holds re-pointed ids *and full snapshots* of
rows that had to be collapsed because the survivor already held the equivalent
identifier, port or relationship edge. Ids alone cannot restore those: the row is
gone, so an undo would be guesswork. A reversed merge keeps its record — "merged
on the 3rd, undone on the 5th" is what an audit asks about, and deleting the row
would erase the decision along with its reversal.

Idempotent per the repo's rules: guarded on each table and on each index.

Revision ID: a4d1c86f2e93
Revises: f3b6d09c4a17
Create Date: 2026-08-16 00:00:00.000000
"""

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision = "a4d1c86f2e93"
down_revision = "f3b6d09c4a17"
branch_labels = None
depends_on = None

_CONFLICTS = "artefact_identity_conflicts"
_MERGES = "artefact_merge_records"

_CONFLICT_PAIR_INDEX = "uq_artefact_identity_conflicts_pair"
_CONFLICT_STATE_INDEX = "ix_artefact_identity_conflicts_org_state"
_CONFLICT_ORG_INDEX = "ix_artefact_identity_conflicts_organization_id"
_CONFLICT_LOWER_INDEX = "ix_artefact_identity_conflicts_lower_asset_id"
_CONFLICT_HIGHER_INDEX = "ix_artefact_identity_conflicts_higher_asset_id"

_MERGE_SURVIVOR_INDEX = "ix_artefact_merge_records_org_survivor"
_MERGE_MERGED_INDEX = "ix_artefact_merge_records_org_merged"
_MERGE_ORG_INDEX = "ix_artefact_merge_records_organization_id"
_MERGE_SURVIVOR_COLUMN_INDEX = "ix_artefact_merge_records_survivor_asset_id"
_MERGE_MERGED_COLUMN_INDEX = "ix_artefact_merge_records_merged_asset_id"


def _table_exists(conn, table: str) -> bool:
    return conn.execute(
        sa.text("SELECT 1 FROM information_schema.tables WHERE table_name = :t"),
        {"t": table},
    ).fetchone() is not None


def upgrade() -> None:
    conn = op.get_bind()

    if not _table_exists(conn, _CONFLICTS):
        op.create_table(
            _CONFLICTS,
            sa.Column("id", sa.Integer(), primary_key=True),
            sa.Column(
                "organization_id", sa.Integer(), sa.ForeignKey("organizations.id"), nullable=False
            ),
            # Ordered pair. The ordering is what makes the unique index below
            # mean "one question per pair" rather than "one per direction".
            sa.Column(
                "lower_asset_id",
                sa.Integer(),
                sa.ForeignKey("assets.id", ondelete="CASCADE"),
                nullable=False,
            ),
            sa.Column(
                "higher_asset_id",
                sa.Integer(),
                sa.ForeignKey("assets.id", ondelete="CASCADE"),
                nullable=False,
            ),
            sa.Column("state", sa.String(30), nullable=False),
            # Why the platform is unsure, in words a reviewer can act on — never
            # a bare "these might match", which is a question nobody can answer.
            sa.Column("reason", sa.Text(), nullable=False),
            sa.Column("evidence", postgresql.JSONB(astext_type=sa.Text()), nullable=True),
            sa.Column("raised_at", sa.DateTime(), nullable=False),
            # Bumped when reconciliation sees the same ambiguity again while the
            # conflict is still open: not a new question, but not a stale one.
            sa.Column("last_raised_at", sa.DateTime(), nullable=False),
            sa.Column("resolved_at", sa.DateTime(), nullable=True),
            sa.Column(
                "resolved_by_user_id",
                sa.Integer(),
                sa.ForeignKey("users.id", ondelete="SET NULL"),
                nullable=True,
            ),
            sa.Column("resolution_reason", sa.Text(), nullable=True),
        )

    op.create_index(
        _CONFLICT_PAIR_INDEX,
        _CONFLICTS,
        ["organization_id", "lower_asset_id", "higher_asset_id"],
        unique=True,
        if_not_exists=True,
    )
    op.create_index(_CONFLICT_STATE_INDEX, _CONFLICTS, ["organization_id", "state"], if_not_exists=True)
    op.create_index(_CONFLICT_ORG_INDEX, _CONFLICTS, ["organization_id"], if_not_exists=True)
    op.create_index(_CONFLICT_LOWER_INDEX, _CONFLICTS, ["lower_asset_id"], if_not_exists=True)
    op.create_index(_CONFLICT_HIGHER_INDEX, _CONFLICTS, ["higher_asset_id"], if_not_exists=True)

    if not _table_exists(conn, _MERGES):
        op.create_table(
            _MERGES,
            sa.Column("id", sa.Integer(), primary_key=True),
            sa.Column(
                "organization_id", sa.Integer(), sa.ForeignKey("organizations.id"), nullable=False
            ),
            sa.Column(
                "survivor_asset_id",
                sa.Integer(),
                sa.ForeignKey("assets.id", ondelete="CASCADE"),
                nullable=False,
            ),
            # Still present, in MERGED — a merge never deletes anything.
            sa.Column(
                "merged_asset_id",
                sa.Integer(),
                sa.ForeignKey("assets.id", ondelete="CASCADE"),
                nullable=False,
            ),
            sa.Column(
                "conflict_id",
                sa.Integer(),
                sa.ForeignKey(f"{_CONFLICTS}.id", ondelete="SET NULL"),
                nullable=True,
            ),
            sa.Column(
                "decided_by_user_id",
                sa.Integer(),
                sa.ForeignKey("users.id", ondelete="SET NULL"),
                nullable=True,
            ),
            sa.Column("decided_at", sa.DateTime(), nullable=False),
            sa.Column("reason", sa.Text(), nullable=True),
            # So undoing restores what the record was, rather than assuming
            # ACTIVE and quietly promoting a row that had been UNCONFIRMED.
            sa.Column("previous_lifecycle_state", sa.String(20), nullable=False),
            sa.Column("moved", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
            sa.Column("reversed_at", sa.DateTime(), nullable=True),
            sa.Column(
                "reversed_by_user_id",
                sa.Integer(),
                sa.ForeignKey("users.id", ondelete="SET NULL"),
                nullable=True,
            ),
            sa.Column("reversal_reason", sa.Text(), nullable=True),
        )

    op.create_index(
        _MERGE_SURVIVOR_INDEX, _MERGES, ["organization_id", "survivor_asset_id"], if_not_exists=True
    )
    op.create_index(
        _MERGE_MERGED_INDEX, _MERGES, ["organization_id", "merged_asset_id"], if_not_exists=True
    )
    op.create_index(_MERGE_ORG_INDEX, _MERGES, ["organization_id"], if_not_exists=True)
    op.create_index(_MERGE_SURVIVOR_COLUMN_INDEX, _MERGES, ["survivor_asset_id"], if_not_exists=True)
    op.create_index(_MERGE_MERGED_COLUMN_INDEX, _MERGES, ["merged_asset_id"], if_not_exists=True)


def downgrade() -> None:
    conn = op.get_bind()

    # Merges first: its conflict_id references the conflicts table.
    if _table_exists(conn, _MERGES):
        for index in (
            _MERGE_SURVIVOR_INDEX,
            _MERGE_MERGED_INDEX,
            _MERGE_ORG_INDEX,
            _MERGE_SURVIVOR_COLUMN_INDEX,
            _MERGE_MERGED_COLUMN_INDEX,
        ):
            op.drop_index(index, table_name=_MERGES, if_exists=True)
        op.drop_table(_MERGES)

    if _table_exists(conn, _CONFLICTS):
        for index in (
            _CONFLICT_PAIR_INDEX,
            _CONFLICT_STATE_INDEX,
            _CONFLICT_ORG_INDEX,
            _CONFLICT_LOWER_INDEX,
            _CONFLICT_HIGHER_INDEX,
        ):
            op.drop_index(index, table_name=_CONFLICTS, if_exists=True)
        op.drop_table(_CONFLICTS)

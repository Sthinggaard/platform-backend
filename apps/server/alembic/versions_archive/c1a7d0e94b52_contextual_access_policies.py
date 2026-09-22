"""The organisation's governed contextual-access decisions (CA-07.0).

Whether deeper access runs unattended on a cadence or only when a person
triggers it is a governance decision about the organisation's own risk, not a
product default. So is which of the five per-artefact access choices is the
standing default answer. Both live here, under one lifecycle, because they are
the same kind of decision: organisation-scoped, humanly approved, versioned, and
superseded rather than edited.

Shape reused from ``risk_appetite_policies`` and ``leadership_authorizations``
rather than invented: prepared/submitted/approved attribution with timestamps,
``effective_from``/``effective_to``/``review_at``, and a self-referencing
``superseded_by_id``. There is no update path — history stays readable.

Two columns carry the story's substance:

- ``consequence_statement`` is NOT NULL and snapshots the business-language
  consequence the approver actually saw. The audit question is "what were they
  told?", and that must not change when the wording is later improved.
- ``consequence_acknowledged`` records that they accepted it. Defaulted false so
  an unacknowledged row can never look approved.

Deliberately absent: any cadence (that belongs to the recurrence schedule, which
must honour this record's ``effective_to``), and any permitted-choice set — a
standing default supplies the answer without withdrawing an option.

Idempotent per the repo's rules: guarded on the table and on each index.

Revision ID: c1a7d0e94b52
Revises: b7e5c02a9d41
Create Date: 2026-08-18 00:00:00.000000
"""

from alembic import op
import sqlalchemy as sa

revision = "c1a7d0e94b52"
down_revision = "b7e5c02a9d41"
branch_labels = None
depends_on = None

_TABLE = "contextual_access_policies"

_DECISION_INDEX = "ix_contextual_access_policies_org_decision"
_ORG_COLUMN_INDEX = "ix_contextual_access_policies_organization_id"


def _table_exists(conn, table: str) -> bool:
    return conn.execute(
        sa.text("SELECT 1 FROM information_schema.tables WHERE table_name = :t"),
        {"t": table},
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
                sa.ForeignKey("organizations.id", ondelete="CASCADE"),
                nullable=False,
            ),
            sa.Column("decision", sa.String(40), nullable=False),
            sa.Column("choice", sa.String(40), nullable=False),
            sa.Column("status", sa.String(20), nullable=False),
            sa.Column("version", sa.Integer(), nullable=False),
            sa.Column("consequence_statement", sa.Text(), nullable=False),
            sa.Column(
                "consequence_acknowledged",
                sa.Boolean(),
                nullable=False,
                server_default=sa.false(),
            ),
            sa.Column("prepared_by", sa.String(255), nullable=True),
            sa.Column("submitted_by", sa.String(255), nullable=True),
            sa.Column("submitted_at", sa.DateTime(), nullable=True),
            sa.Column("approved_by", sa.String(255), nullable=True),
            sa.Column("approved_at", sa.DateTime(), nullable=True),
            sa.Column("approval_reference", sa.String(500), nullable=True),
            sa.Column("rejected_by", sa.String(255), nullable=True),
            sa.Column("rejected_at", sa.DateTime(), nullable=True),
            sa.Column("rejection_reason", sa.Text(), nullable=True),
            sa.Column("note", sa.Text(), nullable=True),
            sa.Column("effective_from", sa.DateTime(), nullable=True),
            sa.Column("effective_to", sa.DateTime(), nullable=True),
            sa.Column("review_at", sa.DateTime(), nullable=True),
            sa.Column(
                "superseded_by_id",
                sa.String(36),
                sa.ForeignKey(f"{_TABLE}.id", ondelete="SET NULL"),
                nullable=True,
            ),
            sa.Column("created_at", sa.DateTime(), nullable=False),
            sa.Column("updated_at", sa.DateTime(), nullable=False),
        )

    op.create_index(
        _DECISION_INDEX, _TABLE, ["organization_id", "decision", "status"], if_not_exists=True
    )
    op.create_index(_ORG_COLUMN_INDEX, _TABLE, ["organization_id"], if_not_exists=True)


def downgrade() -> None:
    conn = op.get_bind()
    if not _table_exists(conn, _TABLE):
        return
    for index in (_ORG_COLUMN_INDEX, _DECISION_INDEX):
        op.drop_index(index, table_name=_TABLE, if_exists=True)
    op.drop_table(_TABLE)

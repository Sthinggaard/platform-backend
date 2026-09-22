"""CA-05.B — discovery_scope_proposals: the human-approved discovery boundary.

One row is one proposed boundary and its approval decision. Inclusions,
exclusions, checks and the (deliberately minimal) permission profile are stored
as snapshots rather than references, so an approved boundary cannot drift when
the underlying target rows change — the same principle as discovery_runs' own
profile/target snapshots.

Revision ID: 9c1e7b4a2f05
Revises: 226fe5c79ac5
Create Date: 2026-08-11 00:00:00.000000
"""

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import JSONB

revision = "9c1e7b4a2f05"
down_revision = "226fe5c79ac5"
branch_labels = None
depends_on = None


def _table_exists(conn, table: str) -> bool:
    return conn.execute(
        sa.text("SELECT 1 FROM information_schema.tables WHERE table_name=:t"),
        {"t": table},
    ).fetchone() is not None


def upgrade() -> None:
    conn = op.get_bind()

    if not _table_exists(conn, "discovery_scope_proposals"):
        op.create_table(
            "discovery_scope_proposals",
            sa.Column("id", sa.String(36), primary_key=True),
            sa.Column(
                "organization_id",
                sa.Integer(),
                sa.ForeignKey("organizations.id", ondelete="CASCADE"),
                nullable=False,
            ),
            sa.Column(
                "evidence_source_id",
                sa.String(36),
                sa.ForeignKey("evidence_sources.id", ondelete="CASCADE"),
                nullable=False,
            ),
            sa.Column("status", sa.String(30), nullable=False),
            sa.Column("inclusions", JSONB, nullable=False),
            sa.Column("exclusions", JSONB, nullable=False),
            sa.Column("checks", JSONB, nullable=False),
            sa.Column("permission_profile", JSONB, nullable=False),
            sa.Column("rationale", JSONB, nullable=False),
            sa.Column("proposed_at", sa.DateTime(), nullable=False),
            sa.Column(
                "decided_by_user_id",
                sa.Integer(),
                sa.ForeignKey("users.id", ondelete="SET NULL"),
                nullable=True,
            ),
            sa.Column("decided_at", sa.DateTime(), nullable=True),
            sa.Column("decision_note", sa.Text(), nullable=True),
            sa.Column("superseded_by_proposal_id", sa.String(36), nullable=True),
            sa.Column("created_at", sa.DateTime(), nullable=False),
            sa.Column("updated_at", sa.DateTime(), nullable=False),
        )
        op.create_index(
            "ix_discovery_scope_proposals_org_source_status",
            "discovery_scope_proposals",
            ["organization_id", "evidence_source_id", "status"],
        )


def downgrade() -> None:
    conn = op.get_bind()
    if _table_exists(conn, "discovery_scope_proposals"):
        op.drop_index(
            "ix_discovery_scope_proposals_org_source_status",
            table_name="discovery_scope_proposals",
        )
        op.drop_table("discovery_scope_proposals")

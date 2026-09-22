"""Leadership authorisation of the onboarding programme (onboarding governance, phase 1)

The first gate in the canonical staged onboarding sequence: leadership or an
authorised governance body must sponsor and approve the onboarding programme
before a Technical Setup Owner is assigned or a process workspace is
prepared. Mirrors risk_appetite_policies' append-only draft -> review ->
active -> superseded/withdrawn lifecycle.

Revision ID: a7c92e6f1d34
Revises: e3a41f9c7d5b
Create Date: 2026-07-14 00:00:00.000000
"""

from alembic import op
import sqlalchemy as sa

revision = "a7c92e6f1d34"
down_revision = "e3a41f9c7d5b"
branch_labels = None
depends_on = None


def _table_exists(conn, table: str) -> bool:
    return conn.execute(
        sa.text("SELECT 1 FROM information_schema.tables WHERE table_name=:t"),
        {"t": table},
    ).fetchone() is not None


def upgrade() -> None:
    conn = op.get_bind()
    if _table_exists(conn, "leadership_authorizations"):
        return
    op.create_table(
        "leadership_authorizations",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column(
            "organization_id",
            sa.Integer(),
            sa.ForeignKey("organizations.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("status", sa.String(20), nullable=False, server_default="draft"),
        sa.Column("version", sa.Integer(), nullable=False, server_default="1"),
        sa.Column("sponsor_name", sa.String(255), nullable=False),
        sa.Column("sponsor_title", sa.String(255), nullable=True),
        sa.Column("approving_body", sa.String(30), nullable=False),
        sa.Column("authorized_scope", sa.Text(), nullable=False),
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
        sa.Column(
            "superseded_by_id",
            sa.String(36),
            sa.ForeignKey("leadership_authorizations.id", ondelete="SET NULL"),
            nullable=True,
        ),
        sa.Column("backfilled", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("created_at", sa.DateTime(), nullable=False, server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(), nullable=False, server_default=sa.func.now()),
    )
    op.create_index(
        "ix_leadership_authorizations_org_status",
        "leadership_authorizations",
        ["organization_id", "status"],
    )


def downgrade() -> None:
    conn = op.get_bind()
    if _table_exists(conn, "leadership_authorizations"):
        op.drop_index("ix_leadership_authorizations_org_status", table_name="leadership_authorizations")
        op.drop_table("leadership_authorizations")

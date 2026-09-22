"""ONB-08B (#17) — structured, append-only process-tailoring signals.

Creates `process_tailoring_signals`: one row per approved tailoring decision (a
service excluded, re-included, or a custom service added to a Business
Process), carrying only controlled keys/codes — never a tenant, asset, or
service *name* — so a later cohort-learning pipeline (ONB-08C) has something
structured to read. `note` is the one free-text column and must stay excluded
from any such export.

No backfill: this is new, event-driven capture going forward. Nothing today
recorded a structured predecessor of these facts to carry over.

Revision ID: 20260922_process_tailoring_signals
Revises: 20260918_remove_inferred_artefact_category_links
Create Date: 2026-09-22 00:00:00.000000
"""

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

from alembic import op

revision = "20260922_process_tailoring_signals"
down_revision = "20260918_remove_inferred_artefact_category_links"
branch_labels = None
depends_on = None

TABLE = "process_tailoring_signals"
INDEXES: tuple[tuple[str, tuple[str, ...]], ...] = (
    ("ix_process_tailoring_signals_org", ("organization_id",)),
    ("ix_process_tailoring_signals_process", ("process_id",)),
    ("ix_process_tailoring_signals_template", ("template_key",)),
    ("ix_process_tailoring_signals_created", ("created_at",)),
)


def columns() -> list[sa.Column]:
    """The table's columns. One definition, so a test can hold it against the model."""
    return [
        sa.Column("id", sa.String(length=36), primary_key=True),
        sa.Column(
            "organization_id",
            sa.Integer(),
            sa.ForeignKey("organizations.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column(
            "process_id",
            sa.String(length=36),
            sa.ForeignKey("value_streams.id", ondelete="SET NULL"),
            nullable=True,
        ),
        sa.Column("template_key", sa.String(length=100), nullable=True),
        sa.Column("template_version", sa.Integer(), nullable=True),
        sa.Column("change_type", sa.String(length=40), nullable=False),
        sa.Column("affected_service_keys", sa.ARRAY(sa.String()), nullable=False),
        sa.Column("detail", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("rationale_code", sa.String(length=60), nullable=False),
        sa.Column("evidence_state", sa.String(length=30), nullable=False),
        sa.Column(
            "actor_user_id",
            sa.Integer(),
            sa.ForeignKey("users.id", ondelete="SET NULL"),
            nullable=True,
        ),
        sa.Column("is_process_boundary_change", sa.Boolean(), nullable=False),
        sa.Column("is_critical_service_change", sa.Boolean(), nullable=False),
        sa.Column("invalidated_activation", sa.Boolean(), nullable=False),
        sa.Column(
            "audit_event_id",
            sa.Integer(),
            sa.ForeignKey("audit_events.id", ondelete="SET NULL"),
            nullable=True,
        ),
        sa.Column("note", sa.Text(), nullable=True),
        sa.Column("created_at", sa.DateTime(), nullable=False),
    ]


def _table_exists(conn, table: str) -> bool:
    return (
        conn.execute(
            sa.text("SELECT 1 FROM information_schema.tables WHERE table_name = :t"), {"t": table}
        ).first()
        is not None
    )


def upgrade() -> None:
    conn = op.get_bind()
    if not _table_exists(conn, TABLE):
        op.create_table(TABLE, *columns())
        for name, index_columns in INDEXES:
            op.create_index(name, TABLE, list(index_columns))


def downgrade() -> None:
    conn = op.get_bind()
    if _table_exists(conn, TABLE):
        for name, _ in INDEXES:
            op.drop_index(name, table_name=TABLE)
        op.drop_table(TABLE)

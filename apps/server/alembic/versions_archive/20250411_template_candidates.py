"""Add template_learning_runs and template_candidates tables

Revision ID: 20250411_template_candidates
Revises: 20250411_slot_instances_and_service_template_fields
Create Date: 2026-04-11 00:00:00.000000
"""

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import ARRAY, JSONB

revision = "20250411_template_candidates"
down_revision = "20250411_slot_instances_and_service_template_fields"
branch_labels = None
depends_on = None


def _col_exists(conn, table: str, col: str) -> bool:
    return conn.execute(
        sa.text(
            "SELECT 1 FROM information_schema.columns "
            "WHERE table_name=:t AND column_name=:c"
        ),
        {"t": table, "c": col},
    ).fetchone() is not None


def _table_exists(conn, table: str) -> bool:
    return conn.execute(
        sa.text(
            "SELECT 1 FROM information_schema.tables "
            "WHERE table_name=:t"
        ),
        {"t": table},
    ).fetchone() is not None


def _index_exists(conn, index_name: str) -> bool:
    return conn.execute(
        sa.text("SELECT 1 FROM pg_indexes WHERE indexname = :i"),
        {"i": index_name},
    ).fetchone() is not None


def upgrade() -> None:
    conn = op.get_bind()

    # ── template_learning_runs ─────────────────────────────────────────────────
    if not _table_exists(conn, "template_learning_runs"):
        op.create_table(
            "template_learning_runs",
            sa.Column("id", sa.String(36), primary_key=True),
            sa.Column("status", sa.String(20), nullable=False, server_default="running"),
            sa.Column("triggered_by", sa.String(30), nullable=False, server_default="manual"),
            sa.Column("service_keys_analysed", ARRAY(sa.String()), nullable=False, server_default="{}"),
            sa.Column("candidates_generated", sa.Integer(), nullable=False, server_default="0"),
            sa.Column("candidates_auto_staged", sa.Integer(), nullable=False, server_default="0"),
            sa.Column("summary", JSONB(), nullable=False, server_default="{}"),
            sa.Column("error", sa.Text(), nullable=True),
            sa.Column("started_at", sa.DateTime(), nullable=False),
            sa.Column("finished_at", sa.DateTime(), nullable=True),
        )

    if not _index_exists(conn, "ix_template_learning_runs_status"):
        op.create_index(
            "ix_template_learning_runs_status",
            "template_learning_runs",
            ["status"],
        )
    if not _index_exists(conn, "ix_template_learning_runs_started_at"):
        op.create_index(
            "ix_template_learning_runs_started_at",
            "template_learning_runs",
            ["started_at"],
        )

    # ── template_candidates ────────────────────────────────────────────────────
    if not _table_exists(conn, "template_candidates"):
        op.create_table(
            "template_candidates",
            sa.Column("id", sa.String(36), primary_key=True),
            sa.Column(
                "run_id",
                sa.String(36),
                sa.ForeignKey("template_learning_runs.id", ondelete="CASCADE"),
                nullable=False,
            ),
            sa.Column("service_key", sa.String(100), nullable=False),
            sa.Column("current_version", sa.Integer(), nullable=False),
            sa.Column("candidate_version", sa.Integer(), nullable=False),
            sa.Column("governance_class", sa.String(1), nullable=False),
            sa.Column("status", sa.String(20), nullable=False, server_default="pending"),
            sa.Column("analysis", JSONB(), nullable=False, server_default="{}"),
            sa.Column("proposed_changes", JSONB(), nullable=False, server_default="[]"),
            sa.Column("reviewed_by", sa.String(255), nullable=True),
            sa.Column("review_note", sa.Text(), nullable=True),
            sa.Column("published_template_id", sa.String(36), nullable=True),
            sa.Column("created_at", sa.DateTime(), nullable=False),
            sa.Column("updated_at", sa.DateTime(), nullable=False),
        )

    if not _index_exists(conn, "ix_template_candidates_service_key"):
        op.create_index(
            "ix_template_candidates_service_key",
            "template_candidates",
            ["service_key"],
        )
    if not _index_exists(conn, "ix_template_candidates_status"):
        op.create_index(
            "ix_template_candidates_status",
            "template_candidates",
            ["status"],
        )
    if not _index_exists(conn, "ix_template_candidates_run"):
        op.create_index(
            "ix_template_candidates_run",
            "template_candidates",
            ["run_id"],
        )
    if not _index_exists(conn, "ix_template_candidates_governance_class"):
        op.create_index(
            "ix_template_candidates_governance_class",
            "template_candidates",
            ["governance_class"],
        )


def downgrade() -> None:
    conn = op.get_bind()
    if _table_exists(conn, "template_candidates"):
        op.drop_table("template_candidates")
    if _table_exists(conn, "template_learning_runs"):
        op.drop_table("template_learning_runs")

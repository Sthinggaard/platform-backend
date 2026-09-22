"""Add learning loop foundation tables

Revision ID: 20250421_learning_loop_foundation
Revises: 20250420_verification_records
Create Date: 2026-04-21 00:00:00.000000
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision = "20250421_learning_loop_foundation"
down_revision = "20250420_verification_records"
branch_labels = None
depends_on = None


def _table_exists(conn, table: str) -> bool:
    return conn.execute(
        sa.text("SELECT 1 FROM information_schema.tables WHERE table_name = :t"),
        {"t": table},
    ).fetchone() is not None


def _index_exists(conn, index_name: str) -> bool:
    return conn.execute(
        sa.text("SELECT 1 FROM pg_indexes WHERE indexname = :i"),
        {"i": index_name},
    ).fetchone() is not None


def _constraint_exists(conn, table_name: str, constraint_name: str) -> bool:
    return conn.execute(
        sa.text(
            """
            SELECT 1
            FROM information_schema.table_constraints
            WHERE table_name = :table_name
              AND constraint_name = :constraint_name
            """
        ),
        {"table_name": table_name, "constraint_name": constraint_name},
    ).fetchone() is not None


def upgrade() -> None:
    conn = op.get_bind()

    if not _table_exists(conn, "learning_loop_runs"):
        op.create_table(
            "learning_loop_runs",
            sa.Column("id", sa.String(36), primary_key=True),
            sa.Column("status", sa.String(20), nullable=False),
            sa.Column("triggered_by", sa.String(30), nullable=False),
            sa.Column("since", sa.DateTime(), nullable=True),
            sa.Column("signals_ingested", sa.Integer(), nullable=False, server_default="0"),
            sa.Column("candidates_generated", sa.Integer(), nullable=False, server_default="0"),
            sa.Column("candidates_auto_staged", sa.Integer(), nullable=False, server_default="0"),
            sa.Column(
                "summary",
                postgresql.JSONB(astext_type=sa.Text()),
                nullable=False,
                server_default=sa.text("'{}'::jsonb"),
            ),
            sa.Column("error", sa.Text(), nullable=True),
            sa.Column("started_at", sa.DateTime(), nullable=False),
            sa.Column("finished_at", sa.DateTime(), nullable=True),
        )

    if not _table_exists(conn, "training_signals"):
        op.create_table(
            "training_signals",
            sa.Column("id", sa.String(36), primary_key=True),
            sa.Column(
                "run_id",
                sa.String(36),
                sa.ForeignKey("learning_loop_runs.id", ondelete="CASCADE"),
                nullable=False,
            ),
            sa.Column(
                "organization_id",
                sa.Integer(),
                sa.ForeignKey("organizations.id", ondelete="CASCADE"),
                nullable=False,
            ),
            sa.Column("source_type", sa.String(40), nullable=False),
            sa.Column("source_id", sa.String(64), nullable=False),
            sa.Column("signal_type", sa.String(50), nullable=False),
            sa.Column("target_type", sa.String(40), nullable=False),
            sa.Column("target_key", sa.String(200), nullable=False),
            sa.Column("outcome", sa.String(50), nullable=False),
            sa.Column(
                "payload",
                postgresql.JSONB(astext_type=sa.Text()),
                nullable=False,
                server_default=sa.text("'{}'::jsonb"),
            ),
            sa.Column("source_created_at", sa.DateTime(), nullable=False),
            sa.Column("created_at", sa.DateTime(), nullable=False),
        )

    if not _constraint_exists(conn, "training_signals", "uq_training_signals_source"):
        op.create_unique_constraint(
            "uq_training_signals_source",
            "training_signals",
            ["source_type", "source_id"],
        )

    if not _table_exists(conn, "learning_improvement_candidates"):
        op.create_table(
            "learning_improvement_candidates",
            sa.Column("id", sa.String(36), primary_key=True),
            sa.Column(
                "run_id",
                sa.String(36),
                sa.ForeignKey("learning_loop_runs.id", ondelete="CASCADE"),
                nullable=False,
            ),
            sa.Column("candidate_type", sa.String(50), nullable=False),
            sa.Column("target_type", sa.String(40), nullable=False),
            sa.Column("target_key", sa.String(200), nullable=False),
            sa.Column("governance_class", sa.String(1), nullable=False),
            sa.Column("status", sa.String(20), nullable=False),
            sa.Column("sample_size", sa.Integer(), nullable=False, server_default="0"),
            sa.Column("confidence_score", sa.Integer(), nullable=False, server_default="0"),
            sa.Column(
                "summary",
                postgresql.JSONB(astext_type=sa.Text()),
                nullable=False,
                server_default=sa.text("'{}'::jsonb"),
            ),
            sa.Column(
                "proposed_changes",
                postgresql.JSONB(astext_type=sa.Text()),
                nullable=False,
                server_default=sa.text("'[]'::jsonb"),
            ),
            sa.Column("reviewed_by", sa.String(255), nullable=True),
            sa.Column("review_note", sa.Text(), nullable=True),
            sa.Column("created_at", sa.DateTime(), nullable=False),
            sa.Column("updated_at", sa.DateTime(), nullable=False),
        )

    if not _index_exists(conn, "ix_learning_loop_runs_status"):
        op.create_index("ix_learning_loop_runs_status", "learning_loop_runs", ["status"])
    if not _index_exists(conn, "ix_learning_loop_runs_started_at"):
        op.create_index("ix_learning_loop_runs_started_at", "learning_loop_runs", ["started_at"])

    if not _index_exists(conn, "ix_training_signals_signal_type"):
        op.create_index("ix_training_signals_signal_type", "training_signals", ["signal_type"])
    if not _index_exists(conn, "ix_training_signals_target"):
        op.create_index("ix_training_signals_target", "training_signals", ["target_type", "target_key"])
    if not _index_exists(conn, "ix_training_signals_source_created"):
        op.create_index("ix_training_signals_source_created", "training_signals", ["source_created_at"])
    if not _index_exists(conn, "ix_training_signals_run"):
        op.create_index("ix_training_signals_run", "training_signals", ["run_id"])
    if not _index_exists(conn, "ix_training_signals_org"):
        op.create_index("ix_training_signals_org", "training_signals", ["organization_id"])

    if not _index_exists(conn, "ix_learning_improvement_candidates_status"):
        op.create_index(
            "ix_learning_improvement_candidates_status",
            "learning_improvement_candidates",
            ["status"],
        )
    if not _index_exists(conn, "ix_learning_improvement_candidates_type"):
        op.create_index(
            "ix_learning_improvement_candidates_type",
            "learning_improvement_candidates",
            ["candidate_type"],
        )
    if not _index_exists(conn, "ix_learning_improvement_candidates_target"):
        op.create_index(
            "ix_learning_improvement_candidates_target",
            "learning_improvement_candidates",
            ["target_type", "target_key"],
        )
    if not _index_exists(conn, "ix_learning_improvement_candidates_run"):
        op.create_index(
            "ix_learning_improvement_candidates_run",
            "learning_improvement_candidates",
            ["run_id"],
        )
    if not _index_exists(conn, "ix_learning_improvement_candidates_governance"):
        op.create_index(
            "ix_learning_improvement_candidates_governance",
            "learning_improvement_candidates",
            ["governance_class"],
        )


def downgrade() -> None:
    conn = op.get_bind()

    for index_name in (
        "ix_learning_improvement_candidates_governance",
        "ix_learning_improvement_candidates_run",
        "ix_learning_improvement_candidates_target",
        "ix_learning_improvement_candidates_type",
        "ix_learning_improvement_candidates_status",
    ):
        if _index_exists(conn, index_name):
            op.drop_index(index_name, table_name="learning_improvement_candidates")

    for index_name in (
        "ix_training_signals_org",
        "ix_training_signals_run",
        "ix_training_signals_source_created",
        "ix_training_signals_target",
        "ix_training_signals_signal_type",
    ):
        if _index_exists(conn, index_name):
            op.drop_index(index_name, table_name="training_signals")

    for index_name in (
        "ix_learning_loop_runs_started_at",
        "ix_learning_loop_runs_status",
    ):
        if _index_exists(conn, index_name):
            op.drop_index(index_name, table_name="learning_loop_runs")

    if _constraint_exists(conn, "training_signals", "uq_training_signals_source"):
        op.drop_constraint("uq_training_signals_source", "training_signals", type_="unique")

    if _table_exists(conn, "learning_improvement_candidates"):
        op.drop_table("learning_improvement_candidates")
    if _table_exists(conn, "training_signals"):
        op.drop_table("training_signals")
    if _table_exists(conn, "learning_loop_runs"):
        op.drop_table("learning_loop_runs")

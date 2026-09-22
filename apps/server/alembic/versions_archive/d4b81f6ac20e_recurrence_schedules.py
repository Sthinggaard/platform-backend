"""A recurrence an organisation can see, and that cannot outlive its approval (#242).

Celery beat already existed, and every entry in it was a *platform* cadence —
dispatch every 15 seconds, normalise every 60, prune every hour. Identical for
every tenant and invisible to all of them. Nothing could express "this
organisation approved deeper access every 30 days", which is why #242 recorded
the primitive as absent rather than as a configuration gap.

Two tables, because a schedule and its occurrences answer different questions:

- ``recurrence_schedules`` — what is meant to happen, and when next. Owned by
  whoever approved it, pausable and cancellable without touching the access it
  runs under.
- ``recurrence_occurrences`` — what actually came round, and what became of it,
  **including the ones nobody claimed**. A single ``last_run_at`` column on the
  schedule could never answer "what did not happen", which is the answer the
  missed-occurrence criterion asks for.

``authorizing_policy_id`` is NOT NULL and is the point of the story rather than a
convenience: the schedule reads its authority live instead of copying
``effective_to`` onto itself, so the two cannot drift and a schedule cannot keep
running on permission that lapsed. ``ondelete=CASCADE`` for the same reason — an
approval that is gone leaves no schedule behind it.

``created_work_ref`` is a plain string, not a foreign key: recurrence creates
work without knowing what kind of work it is, and a FK here would make it know.

Idempotent per the repo's rules: guarded on each table and on each index.

Revision ID: d4b81f6ac20e
Revises: c1a7d0e94b52
Create Date: 2026-08-18 00:00:00.000000
"""

from alembic import op
import sqlalchemy as sa

revision = "d4b81f6ac20e"
down_revision = "c1a7d0e94b52"
branch_labels = None
depends_on = None

_SCHEDULES = "recurrence_schedules"
_OCCURRENCES = "recurrence_occurrences"

_SCHEDULE_ORG_STATUS_INDEX = "ix_recurrence_schedules_org_status"
_SCHEDULE_DUE_INDEX = "ix_recurrence_schedules_due"
_SCHEDULE_ORG_COLUMN_INDEX = "ix_recurrence_schedules_organization_id"
_OCCURRENCE_SCHEDULE_INDEX = "ix_recurrence_occurrences_schedule"
_OCCURRENCE_ORG_STATUS_INDEX = "ix_recurrence_occurrences_org_status"
_OCCURRENCE_ORG_COLUMN_INDEX = "ix_recurrence_occurrences_organization_id"


def _table_exists(conn, table: str) -> bool:
    return conn.execute(
        sa.text("SELECT 1 FROM information_schema.tables WHERE table_name = :t"),
        {"t": table},
    ).fetchone() is not None


def upgrade() -> None:
    conn = op.get_bind()

    if not _table_exists(conn, _SCHEDULES):
        op.create_table(
            _SCHEDULES,
            sa.Column("id", sa.String(36), primary_key=True),
            sa.Column(
                "organization_id",
                sa.Integer(),
                sa.ForeignKey("organizations.id", ondelete="CASCADE"),
                nullable=False,
            ),
            sa.Column(
                "authorizing_policy_id",
                sa.String(36),
                sa.ForeignKey("contextual_access_policies.id", ondelete="CASCADE"),
                nullable=False,
            ),
            sa.Column(
                "scanner_instance_id",
                sa.String(36),
                sa.ForeignKey("scanner_instances.id", ondelete="SET NULL"),
                nullable=True,
            ),
            sa.Column("cadence_days", sa.Integer(), nullable=False),
            sa.Column("status", sa.String(20), nullable=False),
            sa.Column("next_occurrence_at", sa.DateTime(), nullable=False),
            sa.Column("last_occurrence_at", sa.DateTime(), nullable=True),
            sa.Column("purpose", sa.Text(), nullable=True),
            sa.Column(
                "created_by_user_id",
                sa.Integer(),
                sa.ForeignKey("users.id", ondelete="SET NULL"),
                nullable=True,
            ),
            sa.Column("paused_at", sa.DateTime(), nullable=True),
            sa.Column(
                "paused_by_user_id",
                sa.Integer(),
                sa.ForeignKey("users.id", ondelete="SET NULL"),
                nullable=True,
            ),
            sa.Column("cancelled_at", sa.DateTime(), nullable=True),
            sa.Column(
                "cancelled_by_user_id",
                sa.Integer(),
                sa.ForeignKey("users.id", ondelete="SET NULL"),
                nullable=True,
            ),
            sa.Column("lapsed_at", sa.DateTime(), nullable=True),
            sa.Column("lapsed_reason", sa.Text(), nullable=True),
            sa.Column("created_at", sa.DateTime(), nullable=False),
            sa.Column("updated_at", sa.DateTime(), nullable=False),
            # A cadence outside this range is not an organisational schedule —
            # anything faster is a platform sweep and belongs in beat.
            sa.CheckConstraint(
                "cadence_days >= 1 AND cadence_days <= 365",
                name="ck_recurrence_schedule_cadence_range",
            ),
        )

    if not _table_exists(conn, _OCCURRENCES):
        op.create_table(
            _OCCURRENCES,
            sa.Column("id", sa.String(36), primary_key=True),
            sa.Column(
                "organization_id",
                sa.Integer(),
                sa.ForeignKey("organizations.id", ondelete="CASCADE"),
                nullable=False,
            ),
            sa.Column(
                "schedule_id",
                sa.String(36),
                sa.ForeignKey(f"{_SCHEDULES}.id", ondelete="CASCADE"),
                nullable=False,
            ),
            # When it was due, not when the sweep noticed. A sweep running late
            # must not make an occurrence look punctual.
            sa.Column("scheduled_for", sa.DateTime(), nullable=False),
            sa.Column("materialized_at", sa.DateTime(), nullable=False),
            sa.Column("status", sa.String(20), nullable=False),
            sa.Column("claimed_at", sa.DateTime(), nullable=True),
            sa.Column("created_work_ref", sa.String(255), nullable=True),
            sa.Column("resolved_at", sa.DateTime(), nullable=True),
            sa.Column("failure_reason", sa.Text(), nullable=True),
            sa.Column("created_at", sa.DateTime(), nullable=False),
        )

    op.create_index(
        _SCHEDULE_ORG_STATUS_INDEX, _SCHEDULES, ["organization_id", "status"], if_not_exists=True
    )
    # The sweep's own query: active schedules whose next occurrence is due.
    op.create_index(
        _SCHEDULE_DUE_INDEX, _SCHEDULES, ["status", "next_occurrence_at"], if_not_exists=True
    )
    op.create_index(
        _SCHEDULE_ORG_COLUMN_INDEX, _SCHEDULES, ["organization_id"], if_not_exists=True
    )
    op.create_index(
        _OCCURRENCE_SCHEDULE_INDEX, _OCCURRENCES, ["schedule_id", "status"], if_not_exists=True
    )
    op.create_index(
        _OCCURRENCE_ORG_STATUS_INDEX,
        _OCCURRENCES,
        ["organization_id", "status"],
        if_not_exists=True,
    )
    op.create_index(
        _OCCURRENCE_ORG_COLUMN_INDEX, _OCCURRENCES, ["organization_id"], if_not_exists=True
    )


def downgrade() -> None:
    conn = op.get_bind()
    if _table_exists(conn, _OCCURRENCES):
        for index in (
            _OCCURRENCE_ORG_COLUMN_INDEX,
            _OCCURRENCE_ORG_STATUS_INDEX,
            _OCCURRENCE_SCHEDULE_INDEX,
        ):
            op.drop_index(index, table_name=_OCCURRENCES, if_exists=True)
        op.drop_table(_OCCURRENCES)
    if _table_exists(conn, _SCHEDULES):
        for index in (
            _SCHEDULE_ORG_COLUMN_INDEX,
            _SCHEDULE_DUE_INDEX,
            _SCHEDULE_ORG_STATUS_INDEX,
        ):
            op.drop_index(index, table_name=_SCHEDULES, if_exists=True)
        op.drop_table(_SCHEDULES)

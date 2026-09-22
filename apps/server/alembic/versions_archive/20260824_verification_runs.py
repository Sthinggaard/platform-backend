"""CA-08.1 (#289) — a verification that happened, recorded as its own thing.

The access lifecycle could reach ``RUNNING`` and say nothing about what ran.
This table is the account: which artefact, under whose approval, bounded by which
permission profile, and what came of it.

Additive and guarded, so a re-run is a no-op.

**On the inline ``nosemgrep``**: Semgrep's ``avoid-sqlalchemy-text`` rule fires
on the existence check below. It is a literal string with no interpolation at
all — the table name is a module constant — so there is nothing a request could
reach. Suppressed at the site with the rule id, per the security gate's own
narrow-exception rule.
"""

from alembic import op
import sqlalchemy as sa

revision = "20260824_verification_runs"
down_revision = "20260823_recurrence_cadence_shapes_extended"
branch_labels = None
depends_on = None

_TABLE = "verification_runs"


def _table_exists(conn) -> bool:
    return conn.execute(
        sa.text("SELECT 1 FROM information_schema.tables WHERE table_name = :table"),  # nosemgrep: python.sqlalchemy.security.audit.avoid-sqlalchemy-text.avoid-sqlalchemy-text
        {"table": _TABLE},
    ).fetchone() is not None


def upgrade() -> None:
    conn = op.get_bind()
    if _table_exists(conn):
        return

    op.create_table(
        _TABLE,
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column(
            "organization_id",
            sa.Integer(),
            sa.ForeignKey("organizations.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column(
            "asset_id", sa.Integer(), sa.ForeignKey("assets.id", ondelete="CASCADE"), nullable=False
        ),
        # RESTRICT: a completed verification outlives the journey that permitted
        # it, the same instinct CA-07.5 recorded about connectors.
        sa.Column(
            "lifecycle_id",
            sa.String(36),
            sa.ForeignKey("artefact_access_lifecycles.id", ondelete="RESTRICT"),
            nullable=False,
        ),
        sa.Column("approval_source", sa.String(30), nullable=False),
        sa.Column(
            "approved_by_user_id",
            sa.Integer(),
            sa.ForeignKey("users.id", ondelete="SET NULL"),
            nullable=True,
        ),
        sa.Column("approved_at", sa.DateTime(), nullable=True),
        sa.Column(
            "permission_profile_id",
            sa.String(36),
            sa.ForeignKey("permission_profiles.id", ondelete="RESTRICT"),
            nullable=False,
        ),
        sa.Column("status", sa.String(20), nullable=False, server_default="running"),
        sa.Column("began_at", sa.DateTime(), nullable=False),
        sa.Column("finished_at", sa.DateTime(), nullable=True),
        sa.Column("failure_reason", sa.Text(), nullable=True),
        sa.Column(
            "began_by_user_id",
            sa.Integer(),
            sa.ForeignKey("users.id", ondelete="SET NULL"),
            nullable=True,
        ),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.Column("updated_at", sa.DateTime(), nullable=False),
    )
    op.create_index("ix_verification_runs_org_status", _TABLE, ["organization_id", "status"])
    op.create_index(
        "ix_verification_runs_asset", _TABLE, ["organization_id", "asset_id", "began_at"]
    )


def downgrade() -> None:
    conn = op.get_bind()
    if _table_exists(conn):
        op.drop_table(_TABLE)

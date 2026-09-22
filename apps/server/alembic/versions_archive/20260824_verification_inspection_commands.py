"""CA-08.2 (#290) — queued inspections, so a Collector has somewhere to fetch them from.

Its own table rather than a row in ``scanner_commands``:
``ScannerCommand.discovery_run_id`` is NOT NULL with a foreign key to
``discovery_runs``, and an inspection belongs to a ``VerificationRun`` instead.
Making that column nullable would reshape a heavily indexed table many readers
already assume is non-null. Additive is the smaller change, and the Collector
still polls the one endpoint it always did.

Guarded, so a re-run is a no-op.

**On the inline ``nosemgrep``**: ``avoid-sqlalchemy-text`` fires on the existence
check. It is a literal string with no interpolation — the table name is a module
constant — so nothing a request can reach. Suppressed at the site with the rule
id, exactly as ``20260824_verification_runs`` does.
"""

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision = "20260824_verification_inspection_commands"
down_revision = "20260824_service_config_approval"
branch_labels = None
depends_on = None

_TABLE = "verification_inspection_commands"


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
            "verification_run_id",
            sa.String(36),
            sa.ForeignKey("verification_runs.id", ondelete="CASCADE"),
            nullable=False,
        ),
        # RESTRICT: a completed inspection must outlive the connector that ran
        # it, the same instinct CA-07.5 recorded about connectors generally.
        sa.Column(
            "connector_id",
            sa.String(36),
            sa.ForeignKey("access_connectors.id", ondelete="RESTRICT"),
            nullable=False,
        ),
        sa.Column(
            "scanner_instance_id",
            sa.String(36),
            sa.ForeignKey("scanner_instances.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("capability", sa.String(50), nullable=False),
        sa.Column("platform", sa.String(20), nullable=False),
        sa.Column("argv", postgresql.JSONB(), nullable=False),
        sa.Column(
            "permission_profile_id",
            sa.String(36),
            sa.ForeignKey("permission_profiles.id", ondelete="RESTRICT"),
            nullable=False,
        ),
        sa.Column("signature", sa.String(128), nullable=False),
        sa.Column("signature_version", sa.String(30), nullable=False),
        sa.Column("status", sa.String(20), nullable=False, server_default="pending"),
        sa.Column("issued_at", sa.DateTime(), nullable=False),
        sa.Column("expires_at", sa.DateTime(), nullable=False),
        sa.Column("delivered_at", sa.DateTime(), nullable=True),
        sa.Column("completed_at", sa.DateTime(), nullable=True),
        sa.Column("exit_code", sa.Integer(), nullable=True),
        sa.Column("stderr", sa.Text(), nullable=True),
        sa.Column("outcome", sa.String(30), nullable=True),
        sa.Column("created_at", sa.DateTime(), nullable=False, server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(), nullable=False, server_default=sa.func.now()),
    )
    op.create_index(
        "ix_verification_inspection_commands_instance",
        _TABLE,
        ["scanner_instance_id", "status", "issued_at"],
    )
    op.create_index(
        "ix_verification_inspection_commands_run", _TABLE, ["verification_run_id"]
    )


def downgrade() -> None:
    conn = op.get_bind()
    if not _table_exists(conn):
        return
    op.drop_index("ix_verification_inspection_commands_run", table_name=_TABLE)
    op.drop_index("ix_verification_inspection_commands_instance", table_name=_TABLE)
    op.drop_table(_TABLE)

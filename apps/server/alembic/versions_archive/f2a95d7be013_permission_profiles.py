"""What a Connector may do, as an object a person approved (CA-07.3).

Epic C4's `PermissionProfile`, landing here scoped to one Connector. The
programme roadmap owns the general model under C4 — *"missing — no
PermissionProfile model; only flat roles today"*, High security, defining *"what
a Collector/connector may do"*, with D6 blocked on it. Building a second,
connector-only profile would leave three permission models to reconcile: this
one, C4's, and the JSONB bag on `discovery_scope_proposals`. Widening
`connector_id` to a general subject later is a migration, not a rewrite.

**Docker socket approval is two columns, not a capability**, and that is the
point of the table's shape. The contract makes socket access its own decision;
had it been a member of `capabilities`, approving the profile would have granted
it in the same click — the precise failure the rule exists to prevent. A reader
can therefore see a profile in force while socket access is not.

`capabilities` is JSONB, but unlike the precedent it replaces it is validated
against `ConnectorCapability` on every write, attached to an approvable object,
and enforced server-side by `permission_enforcement_service`. The original's
problem was never the column type — it was being a bag on a proposal that
nothing checked.

Versioned and superseded rather than edited: a profile that could be widened in
place would make "what was permitted when this ran?" unanswerable afterwards.

Idempotent per the repo's rules: guarded on the table and on each index.

Revision ID: f2a95d7be013
Revises: e6c3f80b1d47
Create Date: 2026-08-18 00:00:00.000000
"""

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision = "f2a95d7be013"
down_revision = "e6c3f80b1d47"
branch_labels = None
depends_on = None

_TABLE = "permission_profiles"

_ORG_STATUS_INDEX = "ix_permission_profiles_org_status"
_CONNECTOR_INDEX = "ix_permission_profiles_connector"
_ORG_COLUMN_INDEX = "ix_permission_profiles_organization_id"


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
            # NOT NULL: a profile that bounds nothing would be approvable
            # without ever taking effect.
            sa.Column(
                "connector_id",
                sa.String(36),
                sa.ForeignKey("access_connectors.id", ondelete="CASCADE"),
                nullable=False,
            ),
            sa.Column("name", sa.String(255), nullable=False),
            sa.Column(
                "capabilities",
                postgresql.JSONB(astext_type=sa.Text()),
                nullable=False,
                server_default="[]",
            ),
            sa.Column("status", sa.String(30), nullable=False),
            sa.Column("version", sa.Integer(), nullable=False),
            sa.Column(
                "prepared_by_user_id",
                sa.Integer(),
                sa.ForeignKey("users.id", ondelete="SET NULL"),
                nullable=True,
            ),
            sa.Column("submitted_at", sa.DateTime(), nullable=True),
            sa.Column(
                "approved_by_user_id",
                sa.Integer(),
                sa.ForeignKey("users.id", ondelete="SET NULL"),
                nullable=True,
            ),
            sa.Column("approved_at", sa.DateTime(), nullable=True),
            sa.Column(
                "rejected_by_user_id",
                sa.Integer(),
                sa.ForeignKey("users.id", ondelete="SET NULL"),
                nullable=True,
            ),
            sa.Column("rejected_at", sa.DateTime(), nullable=True),
            sa.Column("rejection_reason", sa.Text(), nullable=True),
            # Its own approver and its own timestamp — never set by approving
            # the profile itself.
            sa.Column(
                "docker_socket_approved_by_user_id",
                sa.Integer(),
                sa.ForeignKey("users.id", ondelete="SET NULL"),
                nullable=True,
            ),
            sa.Column("docker_socket_approved_at", sa.DateTime(), nullable=True),
            sa.Column("note", sa.Text(), nullable=True),
            sa.Column(
                "superseded_by_id",
                sa.String(36),
                sa.ForeignKey(f"{_TABLE}.id", ondelete="SET NULL"),
                nullable=True,
            ),
            sa.Column("created_at", sa.DateTime(), nullable=False),
            sa.Column("updated_at", sa.DateTime(), nullable=False),
            # Socket approval is meaningless without an approver, and an
            # approver without a timestamp cannot be placed in the trail.
            sa.CheckConstraint(
                "(docker_socket_approved_at IS NULL) = "
                "(docker_socket_approved_by_user_id IS NULL)",
                name="ck_permission_profile_docker_socket_approval_complete",
            ),
        )

    op.create_index(_ORG_STATUS_INDEX, _TABLE, ["organization_id", "status"], if_not_exists=True)
    op.create_index(_CONNECTOR_INDEX, _TABLE, ["connector_id", "status"], if_not_exists=True)
    op.create_index(_ORG_COLUMN_INDEX, _TABLE, ["organization_id"], if_not_exists=True)


def downgrade() -> None:
    conn = op.get_bind()
    if not _table_exists(conn, _TABLE):
        return
    for index in (_ORG_COLUMN_INDEX, _CONNECTOR_INDEX, _ORG_STATUS_INDEX):
        op.drop_index(index, table_name=_TABLE, if_exists=True)
    op.drop_table(_TABLE)

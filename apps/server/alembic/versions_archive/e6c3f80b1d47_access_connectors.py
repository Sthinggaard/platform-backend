"""Restricted access the platform can describe but never perform (CA-07.2).

The contract: *"Support restricted SSH, read-only Docker and service Connectors;
keep credentials local and platform-visible metadata only."*

**The columns that are absent are the design.** There is no
``encrypted_credentials``, no ``encryption_key_id``, no ``token_hash``, and
nothing else that could carry secret material even reversibly. Compare
``cloud_credentials``, which has exactly those and which this story names as an
explicit non-goal — reusing it would satisfy "do not duplicate" while breaking
the contract, which is why the refinement recorded it as the trap it is.

``credential_fingerprint`` is not a hash of a secret kept for comparison. It is
the kind of identifier SSH already publishes for a key pair: derived from public
material, meaningful to whoever holds the private half, useless otherwise.
Nullable, because an operator-supplied credential (Mode B) leaves nothing durable
behind at all — not even an identifier.

``scanner_instance_id`` is NOT NULL and ``ondelete=CASCADE``: a credential stays
local to the Collector that uses it, so a Connector with no Collector would be a
credential with nowhere local to be.

``requires_docker_socket`` records a *declared requirement*, never a grant. The
contract calls out Docker socket access as needing explicit approval, and that
approval is CA-07.3's permission profile.

Idempotent per the repo's rules: guarded on the table and on each index.

Revision ID: e6c3f80b1d47
Revises: d4b81f6ac20e
Create Date: 2026-08-18 00:00:00.000000
"""

from alembic import op
import sqlalchemy as sa

revision = "e6c3f80b1d47"
down_revision = "d4b81f6ac20e"
branch_labels = None
depends_on = None

_TABLE = "access_connectors"

_ORG_STATUS_INDEX = "ix_access_connectors_org_status"
_INSTANCE_INDEX = "ix_access_connectors_instance"
_ASSET_INDEX = "ix_access_connectors_asset"
_ORG_COLUMN_INDEX = "ix_access_connectors_organization_id"


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
            sa.Column(
                "scanner_instance_id",
                sa.String(36),
                sa.ForeignKey("scanner_instances.id", ondelete="CASCADE"),
                nullable=False,
            ),
            sa.Column(
                "asset_id",
                sa.Integer(),
                sa.ForeignKey("assets.id", ondelete="SET NULL"),
                nullable=True,
            ),
            sa.Column("connector_type", sa.String(30), nullable=False),
            sa.Column("credential_model", sa.String(30), nullable=False),
            # Addressing and identity metadata — the only things stored.
            sa.Column("target_host", sa.String(255), nullable=False),
            sa.Column("target_port", sa.Integer(), nullable=True),
            sa.Column("target_username", sa.String(255), nullable=True),
            # Public identifying material. Never a credential.
            sa.Column("credential_fingerprint", sa.String(128), nullable=True),
            sa.Column("credential_registered_at", sa.DateTime(), nullable=True),
            sa.Column("credential_rotated_at", sa.DateTime(), nullable=True),
            sa.Column(
                "requires_docker_socket", sa.Boolean(), nullable=False, server_default=sa.false()
            ),
            sa.Column("status", sa.String(20), nullable=False),
            sa.Column("note", sa.Text(), nullable=True),
            sa.Column(
                "created_by_user_id",
                sa.Integer(),
                sa.ForeignKey("users.id", ondelete="SET NULL"),
                nullable=True,
            ),
            sa.Column("created_at", sa.DateTime(), nullable=False),
            sa.Column("updated_at", sa.DateTime(), nullable=False),
            # An operator-supplied credential is never stored, so there is
            # nothing to identify. Enforced here as well as in the service:
            # "nothing durable is held" is the promise this story makes, and a
            # promise worth making is worth making unbreakable.
            sa.CheckConstraint(
                "credential_model <> 'operator_supplied' OR credential_fingerprint IS NULL",
                name="ck_access_connector_operator_supplied_holds_nothing",
            ),
        )

    op.create_index(_ORG_STATUS_INDEX, _TABLE, ["organization_id", "status"], if_not_exists=True)
    op.create_index(
        _INSTANCE_INDEX, _TABLE, ["scanner_instance_id", "status"], if_not_exists=True
    )
    op.create_index(_ASSET_INDEX, _TABLE, ["organization_id", "asset_id"], if_not_exists=True)
    op.create_index(_ORG_COLUMN_INDEX, _TABLE, ["organization_id"], if_not_exists=True)


def downgrade() -> None:
    conn = op.get_bind()
    if not _table_exists(conn, _TABLE):
        return
    for index in (_ORG_COLUMN_INDEX, _ASSET_INDEX, _INSTANCE_INDEX, _ORG_STATUS_INDEX):
        op.drop_index(index, table_name=_TABLE, if_exists=True)
    op.drop_table(_TABLE)

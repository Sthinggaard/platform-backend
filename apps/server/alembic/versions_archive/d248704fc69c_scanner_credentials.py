"""Named, independently-managed scanner credentials (TENANT-83).

Additive: ``scanner_instances.activation_token_hash`` and its existing
rotate/pause/revoke routes are untouched and keep working — the frontend
migrates onto this table separately (TENANT-85). Backfills each existing
instance's current token into its first named credential row so every
scanner has at least one credential record post-migration, matching the
design's "every scanner already shows one default named credential"
baseline. Backfilled rows get ``validity_policy="custom"`` with
``expires_at=NULL`` (custom + null expiry = never expires), preserving the
old model's actual behaviour exactly rather than inventing an expiry that
never existed.

Revision ID: d248704fc69c
Revises: af8f00af46fe
Create Date: 2026-08-02 00:00:00.000000
"""

import hashlib
import uuid

from alembic import op
import sqlalchemy as sa

revision = "d248704fc69c"
down_revision = "af8f00af46fe"
branch_labels = None
depends_on = None


def _table_exists(conn, table: str) -> bool:
    return conn.execute(
        sa.text("SELECT 1 FROM information_schema.tables WHERE table_name=:t"),
        {"t": table},
    ).fetchone() is not None


def upgrade() -> None:
    conn = op.get_bind()

    if not _table_exists(conn, "scanner_credentials"):
        op.create_table(
            "scanner_credentials",
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
            sa.Column("name", sa.String(255), nullable=False),
            sa.Column("token_hash", sa.String(64), nullable=False, unique=True),
            sa.Column("validity_policy", sa.String(20), nullable=False),
            sa.Column("status", sa.String(20), nullable=False, server_default="active"),
            sa.Column("created_at", sa.DateTime(), nullable=False, server_default=sa.func.now()),
            sa.Column(
                "created_by_user_id", sa.Integer(), sa.ForeignKey("users.id", ondelete="SET NULL"), nullable=True
            ),
            sa.Column("expires_at", sa.DateTime(), nullable=True),
            sa.Column("consumed_at", sa.DateTime(), nullable=True),
            sa.Column("last_rotated_at", sa.DateTime(), nullable=True),
            sa.Column("paused_at", sa.DateTime(), nullable=True),
            sa.Column("revoked_at", sa.DateTime(), nullable=True),
            sa.Column(
                "revoked_by_user_id", sa.Integer(), sa.ForeignKey("users.id", ondelete="SET NULL"), nullable=True
            ),
            sa.Column("deleted_at", sa.DateTime(), nullable=True),
        )
        op.create_index(
            "ix_scanner_credentials_instance", "scanner_credentials", ["scanner_instance_id", "status"]
        )

    # Backfill: one credential per existing instance, only if it doesn't
    # already have one (idempotent re-run safe).
    instances = conn.execute(
        sa.text(
            "SELECT id, organization_id, name, activation_token_hash, status, activation_revoked_at, activated_at "
            "FROM scanner_instances"
        )
    ).fetchall()
    for instance in instances:
        existing = conn.execute(
            sa.text("SELECT 1 FROM scanner_credentials WHERE scanner_instance_id=:sid"),
            {"sid": instance.id},
        ).fetchone()
        if existing is not None:
            continue
        credential_status = "revoked" if instance.status == "revoked" else "active"
        conn.execute(
            sa.text(
                "INSERT INTO scanner_credentials "
                "(id, organization_id, scanner_instance_id, name, token_hash, validity_policy, status, "
                "created_at, expires_at, revoked_at) "
                "VALUES (:id, :org_id, :sid, :name, :token_hash, 'custom', :status, :created_at, NULL, :revoked_at)"
            ),
            {
                "id": str(uuid.uuid4()),
                "org_id": instance.organization_id,
                "sid": instance.id,
                "name": f"{instance.name} credential",
                "token_hash": instance.activation_token_hash
                or hashlib.sha256(f"backfill:{instance.id}".encode("utf-8")).hexdigest(),
                "status": credential_status,
                "created_at": instance.activated_at,
                "revoked_at": instance.activation_revoked_at,
            },
        )


def downgrade() -> None:
    conn = op.get_bind()
    if _table_exists(conn, "scanner_credentials"):
        op.drop_index("ix_scanner_credentials_instance", table_name="scanner_credentials")
        op.drop_table("scanner_credentials")

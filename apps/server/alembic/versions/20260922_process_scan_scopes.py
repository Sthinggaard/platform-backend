"""CA-10 (#50) — ProcessScanScope: an approved recurring assurance scope per
active Business Process (Programme Epic G7).

Column set matches the pre-existing `process_scan_scopes` table found in
the shared dev Postgres container 2026-09-22 (0 rows, not referenced
anywhere in git history on any branch — see process_scan_scope_enums.py's
docstring) and read back column-for-column with `\\d process_scan_scopes`
before writing this. `_table_exists` guards mean this migration is a no-op
against that dev database and a real `CREATE TABLE` against a clean one
(staging, production, a fresh test database).

Also creates `process_scanner_links` (CA-04.6), found missing entirely by
the same investigation: `ProcessScannerLink` was never imported by
`model_defs/__init__.py` or `models.py`, so `alembic/env.py`'s
`target_metadata` never saw the table and no migration for it existed — it
only ever worked against a dev database built out-of-band with
`create_all()`. Registered now and created here since `ProcessScanScope`
immediately depends on rows in it existing.

Revision ID: 20260922_process_scan_scopes
Revises: 20260922_process_tailoring_signals
Create Date: 2026-09-22 00:00:00.000000
"""

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

from alembic import op

revision = "20260922_process_scan_scopes"
down_revision = "20260922_process_tailoring_signals"
branch_labels = None
depends_on = None

LINK_TABLE = "process_scanner_links"
LINK_INDEXES: tuple[tuple[str, tuple[str, ...], bool], ...] = (
    ("ix_process_scanner_links_instance", ("scanner_instance_id", "status"), False),
    ("ix_process_scanner_links_process", ("business_process_id", "status"), False),
)

SCOPE_TABLE = "process_scan_scopes"
SCOPE_INDEXES: tuple[tuple[str, tuple[str, ...], bool], ...] = (
    ("ix_process_scan_scopes_org_process_status", ("organization_id", "business_process_id", "status"), False),
    ("ix_process_scan_scopes_process_revision", ("business_process_id", "revision"), True),
)


def link_columns() -> list[sa.Column]:
    return [
        sa.Column("id", sa.String(length=36), primary_key=True),
        sa.Column(
            "organization_id", sa.Integer(), sa.ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False
        ),
        sa.Column(
            "scanner_instance_id",
            sa.String(length=36),
            sa.ForeignKey("scanner_instances.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column(
            "business_process_id",
            sa.String(length=36),
            sa.ForeignKey("value_streams.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column(
            "business_service_id",
            sa.String(length=36),
            sa.ForeignKey("business_services.id", ondelete="SET NULL"),
            nullable=True,
        ),
        sa.Column("status", sa.String(length=20), nullable=False, server_default="active"),
        sa.Column("linked_by_user_id", sa.Integer(), sa.ForeignKey("users.id", ondelete="SET NULL"), nullable=True),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.Column("paused_at", sa.DateTime(), nullable=True),
        sa.Column("revoked_at", sa.DateTime(), nullable=True),
        sa.Column("revoked_by_user_id", sa.Integer(), sa.ForeignKey("users.id", ondelete="SET NULL"), nullable=True),
    ]


def scope_columns() -> list[sa.Column]:
    jsonb = lambda: postgresql.JSONB(astext_type=sa.Text())  # noqa: E731
    return [
        sa.Column("id", sa.String(length=36), primary_key=True),
        sa.Column(
            "organization_id", sa.Integer(), sa.ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False
        ),
        sa.Column(
            "business_process_id",
            sa.String(length=36),
            sa.ForeignKey("value_streams.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("revision", sa.Integer(), nullable=False),
        sa.Column("status", sa.String(length=30), nullable=False, server_default="draft"),
        sa.Column("bundle_version_ids", jsonb(), nullable=False, server_default="[]"),
        sa.Column("artefacts", jsonb(), nullable=False, server_default="[]"),
        sa.Column("connectors", jsonb(), nullable=False, server_default="[]"),
        sa.Column("checks", jsonb(), nullable=False, server_default="[]"),
        sa.Column("profile_versions", jsonb(), nullable=False, server_default="{}"),
        sa.Column("rationale", jsonb(), nullable=False, server_default="{}"),
        sa.Column("derived_at", sa.DateTime(), nullable=False),
        sa.Column(
            "submitted_by_user_id", sa.Integer(), sa.ForeignKey("users.id", ondelete="SET NULL"), nullable=True
        ),
        sa.Column("submitted_at", sa.DateTime(), nullable=True),
        sa.Column(
            "approved_by_user_id", sa.Integer(), sa.ForeignKey("users.id", ondelete="SET NULL"), nullable=True
        ),
        sa.Column("approved_at", sa.DateTime(), nullable=True),
        sa.Column("decision_note", sa.Text(), nullable=True),
        sa.Column("outdated_at", sa.DateTime(), nullable=True),
        sa.Column("outdated_reason", sa.String(length=200), nullable=True),
        sa.Column(
            "revoked_by_user_id", sa.Integer(), sa.ForeignKey("users.id", ondelete="SET NULL"), nullable=True
        ),
        sa.Column("revoked_at", sa.DateTime(), nullable=True),
        # No FK — matches the live table exactly (verified 2026-09-22).
        sa.Column("superseded_by_scope_id", sa.String(length=36), nullable=True),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.Column("updated_at", sa.DateTime(), nullable=False),
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
    if not _table_exists(conn, LINK_TABLE):
        op.create_table(LINK_TABLE, *link_columns())
        for name, index_columns, unique in LINK_INDEXES:
            op.create_index(name, LINK_TABLE, list(index_columns), unique=unique)
    if not _table_exists(conn, SCOPE_TABLE):
        op.create_table(SCOPE_TABLE, *scope_columns())
        for name, index_columns, unique in SCOPE_INDEXES:
            op.create_index(name, SCOPE_TABLE, list(index_columns), unique=unique)


def downgrade() -> None:
    conn = op.get_bind()
    if _table_exists(conn, SCOPE_TABLE):
        for name, _, _unique in SCOPE_INDEXES:
            op.drop_index(name, table_name=SCOPE_TABLE)
        op.drop_table(SCOPE_TABLE)
    if _table_exists(conn, LINK_TABLE):
        for name, _, _unique in LINK_INDEXES:
            op.drop_index(name, table_name=LINK_TABLE)
        op.drop_table(LINK_TABLE)

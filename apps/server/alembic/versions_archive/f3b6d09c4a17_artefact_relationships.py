"""Artefacts can record how they relate to one another (CA-06.3).

The inventory was a flat list: it could say what an organisation has, but not
that this application runs on that host, or that this name resolves to that
address. The CA-06 checklist names artefact relationships in its first line, and
no artefact→artefact model existed anywhere (``OrganizationUnitRelationship`` is
organisation structure, unrelated).

One table rather than one per relationship type, so "what is connected to this?"
stays a single query. Direction is meaningful and read from the source's side —
*source RUNS_ON target* is not the reverse statement — and uniqueness is on
(source, target, type) because two artefacts can legitimately be related in more
than one way at once.

Every row carries **who says so** (``origin``) and **how sure** (``confidence``),
both NOT NULL, because a relationship the platform inferred is a different kind
of claim from one a person asserted, and a surface that cannot tell them apart
would present an inference as established fact.

``state`` + ``withdrawn_at`` rather than deletion, following the same rule as
the rest of CA-06: a relationship that stops being observed is withdrawn, so
"these two were connected until the 14th" stays answerable.

Strictly artefact-to-artefact. Business Service dependency mapping is CA-09A's
``SlotInstance`` and is untouched by this.

Idempotent per the repo's rules: guarded on the table and on each index.

Revision ID: f3b6d09c4a17
Revises: e2c7a48f13bd
Create Date: 2026-08-15 00:00:00.000000
"""

from alembic import op
import sqlalchemy as sa

revision = "f3b6d09c4a17"
down_revision = "e2c7a48f13bd"
branch_labels = None
depends_on = None

_TABLE = "artefact_relationships"

_UNIQUE_INDEX = "uq_artefact_relationships_source_target_type"
_SOURCE_INDEX = "ix_artefact_relationships_org_source"
_TARGET_INDEX = "ix_artefact_relationships_org_target"
_STATE_INDEX = "ix_artefact_relationships_org_state"
_ORG_COLUMN_INDEX = "ix_artefact_relationships_organization_id"
_SOURCE_COLUMN_INDEX = "ix_artefact_relationships_source_asset_id"
_TARGET_COLUMN_INDEX = "ix_artefact_relationships_target_asset_id"


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
            sa.Column("id", sa.Integer(), primary_key=True),
            sa.Column(
                "organization_id", sa.Integer(), sa.ForeignKey("organizations.id"), nullable=False
            ),
            sa.Column(
                "source_asset_id",
                sa.Integer(),
                sa.ForeignKey("assets.id", ondelete="CASCADE"),
                nullable=False,
            ),
            sa.Column(
                "target_asset_id",
                sa.Integer(),
                sa.ForeignKey("assets.id", ondelete="CASCADE"),
                nullable=False,
            ),
            sa.Column("relationship_type", sa.String(40), nullable=False),
            # NOT NULL on purpose: a relationship that cannot say who claimed it
            # or how sure they were is the exact ambiguity this story prevents.
            sa.Column("origin", sa.String(30), nullable=False),
            sa.Column("confidence", sa.String(10), nullable=False),
            sa.Column("state", sa.String(20), nullable=False),
            sa.Column("reason", sa.Text(), nullable=True),
            # Provenance, same rule as CA-06.2: nullable, never backfilled, and
            # absent reads as absent. A person's assertion has no evidence
            # package; a scan's observation has no asserting user.
            sa.Column(
                "evidence_package_id",
                sa.String(36),
                sa.ForeignKey("evidence_packages.id", ondelete="SET NULL"),
                nullable=True,
            ),
            sa.Column(
                "scanner_instance_id",
                sa.String(36),
                sa.ForeignKey("scanner_instances.id", ondelete="SET NULL"),
                nullable=True,
            ),
            sa.Column("observed_by_source", sa.String(255), nullable=True),
            sa.Column(
                "asserted_by_user_id",
                sa.Integer(),
                sa.ForeignKey("users.id", ondelete="SET NULL"),
                nullable=True,
            ),
            sa.Column("first_seen_at", sa.DateTime(), nullable=False),
            sa.Column("last_seen_at", sa.DateTime(), nullable=False),
            sa.Column("withdrawn_at", sa.DateTime(), nullable=True),
            sa.Column("created_at", sa.DateTime(), nullable=False),
            sa.Column("updated_at", sa.DateTime(), nullable=False),
            # A self-edge is not a data-quality nuisance — it is a cycle every
            # traversal built on this table would have to defend against.
            sa.CheckConstraint(
                "source_asset_id <> target_asset_id", name="ck_artefact_relationship_not_self"
            ),
        )

    op.create_index(
        _UNIQUE_INDEX,
        _TABLE,
        ["source_asset_id", "target_asset_id", "relationship_type"],
        unique=True,
        if_not_exists=True,
    )
    op.create_index(_SOURCE_INDEX, _TABLE, ["organization_id", "source_asset_id"], if_not_exists=True)
    op.create_index(_TARGET_INDEX, _TABLE, ["organization_id", "target_asset_id"], if_not_exists=True)
    op.create_index(_STATE_INDEX, _TABLE, ["organization_id", "state"], if_not_exists=True)
    op.create_index(_ORG_COLUMN_INDEX, _TABLE, ["organization_id"], if_not_exists=True)
    op.create_index(_SOURCE_COLUMN_INDEX, _TABLE, ["source_asset_id"], if_not_exists=True)
    op.create_index(_TARGET_COLUMN_INDEX, _TABLE, ["target_asset_id"], if_not_exists=True)


def downgrade() -> None:
    conn = op.get_bind()
    if not _table_exists(conn, _TABLE):
        return
    for index in (
        _TARGET_COLUMN_INDEX,
        _SOURCE_COLUMN_INDEX,
        _ORG_COLUMN_INDEX,
        _STATE_INDEX,
        _TARGET_INDEX,
        _SOURCE_INDEX,
        _UNIQUE_INDEX,
    ):
        op.drop_index(index, table_name=_TABLE, if_exists=True)
    op.drop_table(_TABLE)

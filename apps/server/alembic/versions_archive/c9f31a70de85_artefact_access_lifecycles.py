"""CA-07.5 — the seven access states, as a second lifecycle on an artefact.

Its own table rather than columns on ``assets``, because CA-06 already gives an
artefact an *identity* lifecycle and the two do not line up: an artefact can be
confirmed with no access, or unconfirmed with access already approved.
Overloading one column would make two questions look like one answer.

``verification_ready_at`` and ``verification_approved_at`` are **two columns, and
that is the contract's headline rule in the schema**. Being ready for verification
is not being allowed to verify. If one column carried both, arriving at readiness
would *be* permission, and *"access does not start verification"* would have
nowhere left to live.

``uq_artefact_access_lifecycle_artefact`` keeps it to one row per artefact: two
journeys for one artefact would mean two answers to "may this be verified?" and
nothing to say which governs.

Every foreign key out to a decision is ``ON DELETE SET NULL``, never CASCADE. A
completed access journey must outlive the Connector it went through and the
policy it inherited approval from — deleting either would otherwise erase the
record that verification was ever authorised.

Idempotent per the repo's rules: guarded on the table and on each index.

Revision ID: c9f31a70de85
Revises: b7e42c1f80da
Create Date: 2026-08-18 00:00:00.000000
"""

from alembic import op
import sqlalchemy as sa

revision = "c9f31a70de85"
down_revision = "b7e42c1f80da"
branch_labels = None
depends_on = None

_TABLE = "artefact_access_lifecycles"

_ORG_STATE_INDEX = "ix_artefact_access_lifecycles_org_state"
_ORG_COLUMN_INDEX = "ix_artefact_access_lifecycles_organization_id"


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
                "asset_id",
                sa.Integer(),
                sa.ForeignKey("assets.id", ondelete="CASCADE"),
                nullable=False,
            ),
            sa.Column("state", sa.String(30), nullable=False),
            sa.Column("requested_choice", sa.String(30), nullable=False),
            sa.Column("deviation_reason", sa.Text(), nullable=True),
            sa.Column("requested_at", sa.DateTime(), nullable=False),
            sa.Column(
                "requested_by_user_id",
                sa.Integer(),
                sa.ForeignKey("users.id", ondelete="SET NULL"),
                nullable=True,
            ),
            sa.Column(
                "connector_id",
                sa.String(36),
                sa.ForeignKey("access_connectors.id", ondelete="SET NULL"),
                nullable=True,
            ),
            sa.Column("configured_at", sa.DateTime(), nullable=True),
            sa.Column(
                "access_test_id",
                sa.String(36),
                sa.ForeignKey("connector_access_tests.id", ondelete="SET NULL"),
                nullable=True,
            ),
            sa.Column("tested_at", sa.DateTime(), nullable=True),
            # Two columns, deliberately. See the module docstring.
            sa.Column("verification_ready_at", sa.DateTime(), nullable=True),
            sa.Column("verification_approved_at", sa.DateTime(), nullable=True),
            sa.Column(
                "verification_approved_by_user_id",
                sa.Integer(),
                sa.ForeignKey("users.id", ondelete="SET NULL"),
                nullable=True,
            ),
            sa.Column("verification_approved_source", sa.String(30), nullable=True),
            sa.Column(
                "verification_approval_policy_id",
                sa.String(36),
                sa.ForeignKey("contextual_access_policies.id", ondelete="SET NULL"),
                nullable=True,
            ),
            sa.Column("running_at", sa.DateTime(), nullable=True),
            sa.Column("completed_at", sa.DateTime(), nullable=True),
            sa.Column("created_at", sa.DateTime(), nullable=False),
            sa.Column("updated_at", sa.DateTime(), nullable=False),
            sa.UniqueConstraint(
                "organization_id", "asset_id", name="uq_artefact_access_lifecycle_artefact"
            ),
            # The contract's rule, enforced by the database as well as by the
            # service: an artefact cannot be running or complete unless a human
            # approval is stamped on the row. A future writer that bypasses
            # `mark_running` still cannot record a run nobody authorised.
            sa.CheckConstraint(
                "state NOT IN ('running', 'complete') OR verification_approved_at IS NOT NULL",
                name="ck_artefact_access_run_requires_approval",
            ),
            # And approval cannot be stamped without saying which kind of "yes"
            # it was, so "who approved this?" is always answerable.
            sa.CheckConstraint(
                "verification_approved_at IS NULL OR verification_approved_source IS NOT NULL",
                name="ck_artefact_access_approval_names_its_source",
            ),
        )

    op.create_index(_ORG_STATE_INDEX, _TABLE, ["organization_id", "state"], if_not_exists=True)
    op.create_index(_ORG_COLUMN_INDEX, _TABLE, ["organization_id"], if_not_exists=True)


def downgrade() -> None:
    conn = op.get_bind()
    if not _table_exists(conn, _TABLE):
        return
    for index in (_ORG_COLUMN_INDEX, _ORG_STATE_INDEX):
        op.drop_index(index, table_name=_TABLE, if_exists=True)
    op.drop_table(_TABLE)

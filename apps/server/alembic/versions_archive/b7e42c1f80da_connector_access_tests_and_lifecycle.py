"""CA-07.4 — access tests as history, and the three withdrawal verbs as three facts.

``connector_access_tests`` is a table rather than columns on the Connector for the
reason ``collector_readiness_reports`` is one: *"when did this stop working, and
what did it say at the time?"* is a question an operator will ask, and each result
overwriting the last would destroy the answer.

``reachable`` and ``permissions_adequate`` are two nullable booleans, not one
verdict. A Connector can be perfectly reachable and still unable to do what its
approved profile grants; collapsing that into "failed" would send someone to the
network when the problem is an account's rights. Both stay NULL until the
Collector reports — and for the two failures the platform can state on its own
(withdrawn Connector, no approved profile), they stay NULL for good, because
nothing was ever measured.

``permission_profile_id`` is ``ON DELETE SET NULL`` rather than CASCADE: profiles
supersede and are never edited, and a test result must outlive the grant it was
measured against instead of vanishing with it.

The new columns on ``access_connectors`` exist because ``status`` alone cannot
hold three independent acts. Revocation and disconnection genuinely co-occur — a
Connector can be revoked while its credential still sits on the Collector awaiting
cleanup — so ``status`` carries the strongest standing withdrawal while each
timestamp records its own act. ``revocation_reason`` is required by the service,
not by the column, because existing rows predate the rule and a NOT NULL here
would make the migration unrunnable rather than making the rule truer.

Idempotent per the repo's rules: guarded on the table, on each column and on each
index.

Revision ID: b7e42c1f80da
Revises: a3d17e8c94b2
Create Date: 2026-08-18 00:00:00.000000
"""

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision = "b7e42c1f80da"
down_revision = "a3d17e8c94b2"
branch_labels = None
depends_on = None

_TESTS_TABLE = "connector_access_tests"
_CONNECTORS_TABLE = "access_connectors"

_CONNECTOR_INDEX = "ix_connector_access_tests_connector"
_ORG_STATUS_INDEX = "ix_connector_access_tests_org_status"
_ORG_COLUMN_INDEX = "ix_connector_access_tests_organization_id"

# CA-07.4's additions to the Connector itself. Every one nullable: they record
# that something happened, and nothing has happened to a Connector in use.
_LIFECYCLE_COLUMNS = (
    ("paused_at", sa.DateTime()),
    ("revoked_at", sa.DateTime()),
    ("revocation_reason", sa.Text()),
    ("disconnected_at", sa.DateTime()),
)


def _table_exists(conn, table: str) -> bool:
    return conn.execute(
        sa.text("SELECT 1 FROM information_schema.tables WHERE table_name = :t"),
        {"t": table},
    ).fetchone() is not None


def _col_exists(conn, table: str, col: str) -> bool:
    return conn.execute(
        sa.text("SELECT 1 FROM information_schema.columns WHERE table_name=:t AND column_name=:c"),
        {"t": table, "c": col},
    ).fetchone() is not None


def upgrade() -> None:
    conn = op.get_bind()

    if not _table_exists(conn, _TESTS_TABLE):
        op.create_table(
            _TESTS_TABLE,
            sa.Column("id", sa.String(36), primary_key=True),
            sa.Column(
                "organization_id",
                sa.Integer(),
                sa.ForeignKey("organizations.id", ondelete="CASCADE"),
                nullable=False,
            ),
            sa.Column(
                "connector_id",
                sa.String(36),
                sa.ForeignKey("access_connectors.id", ondelete="CASCADE"),
                nullable=False,
            ),
            sa.Column(
                "permission_profile_id",
                sa.String(36),
                sa.ForeignKey("permission_profiles.id", ondelete="SET NULL"),
                nullable=True,
            ),
            sa.Column("status", sa.String(20), nullable=False),
            sa.Column("requested_at", sa.DateTime(), nullable=False),
            sa.Column(
                "requested_by_user_id",
                sa.Integer(),
                sa.ForeignKey("users.id", ondelete="SET NULL"),
                nullable=True,
            ),
            sa.Column("completed_at", sa.DateTime(), nullable=True),
            # Two answers, not one verdict.
            sa.Column("reachable", sa.Boolean(), nullable=True),
            sa.Column("permissions_adequate", sa.Boolean(), nullable=True),
            sa.Column(
                "capabilities_confirmed",
                postgresql.JSONB(astext_type=sa.Text()),
                nullable=False,
                server_default=sa.text("'[]'::jsonb"),
            ),
            sa.Column("failure_code", sa.String(50), nullable=True),
            sa.Column("failure_detail", sa.Text(), nullable=True),
            sa.Column("created_at", sa.DateTime(), nullable=False),
            # A test that failed must say why, in the closed vocabulary — the
            # story's fourth criterion made a database rule as well as a service
            # one, because "connection error" is what happens when nothing stops
            # it. Enforced here so a future writer that bypasses the service
            # cannot record a failure nobody can act on.
            sa.CheckConstraint(
                "status <> 'failed' OR failure_code IS NOT NULL",
                name="ck_connector_access_test_failure_names_a_cause",
            ),
        )

    op.create_index(
        _CONNECTOR_INDEX, _TESTS_TABLE, ["connector_id", "status"], if_not_exists=True
    )
    op.create_index(
        _ORG_STATUS_INDEX, _TESTS_TABLE, ["organization_id", "status"], if_not_exists=True
    )
    op.create_index(_ORG_COLUMN_INDEX, _TESTS_TABLE, ["organization_id"], if_not_exists=True)

    for name, column_type in _LIFECYCLE_COLUMNS:
        if not _col_exists(conn, _CONNECTORS_TABLE, name):
            op.add_column(_CONNECTORS_TABLE, sa.Column(name, column_type, nullable=True))
    if not _col_exists(conn, _CONNECTORS_TABLE, "revoked_by_user_id"):
        op.add_column(
            _CONNECTORS_TABLE,
            sa.Column(
                "revoked_by_user_id",
                sa.Integer(),
                sa.ForeignKey("users.id", ondelete="SET NULL"),
                nullable=True,
            ),
        )


def downgrade() -> None:
    conn = op.get_bind()

    if _col_exists(conn, _CONNECTORS_TABLE, "revoked_by_user_id"):
        op.drop_column(_CONNECTORS_TABLE, "revoked_by_user_id")
    for name, _ in reversed(_LIFECYCLE_COLUMNS):
        if _col_exists(conn, _CONNECTORS_TABLE, name):
            op.drop_column(_CONNECTORS_TABLE, name)

    if not _table_exists(conn, _TESTS_TABLE):
        return
    for index in (_ORG_COLUMN_INDEX, _ORG_STATUS_INDEX, _CONNECTOR_INDEX):
        op.drop_index(index, table_name=_TESTS_TABLE, if_exists=True)
    op.drop_table(_TESTS_TABLE)

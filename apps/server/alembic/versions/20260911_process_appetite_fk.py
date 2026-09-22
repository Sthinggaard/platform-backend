"""register the Risk Appetite a business process runs under

Adds `value_streams.risk_appetite_policy_id`.

⚠️ **Why a column and not a query.** A process's appetite is either its own
policy or the organisation's, inherited. The first is discoverable — a policy
row scoped to the process — but the second never wrote anything: accepting the
inherited baseline deliberately creates no process override
(`accept_process_appetite_recommendation`, 2026-08-30), and the only trace was
an audit event whose metadata does not carry the process id. So nothing could
tell a process whose owner had decided to inherit from one that had never been
asked, and the workspace asked again on every load (Søren, 2026-09-11).

This records the decision itself: null until the owner makes one, then the
policy they are running under, whichever scope it belongs to.

Revision ID: 20260911_process_appetite_fk
Revises: 20260910_schema_baseline
Create Date: 2026-09-11 00:00:00.000000
"""

from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
# ⚠️ 32 characters is the hard limit — `alembic_version.version_num` is
# varchar(32), and a longer id fails only at the very end of the upgrade,
# after every DDL statement has run. 32 of the archived 131 revisions hit
# this (see docs/architecture/staging-deploy-2026-09-09.md).
revision = "20260911_process_appetite_fk"
down_revision = "20260910_schema_baseline"
branch_labels = None
depends_on = None


def _col_exists(conn, table: str, col: str) -> bool:
    return (
        conn.execute(
            sa.text(
                "SELECT 1 FROM information_schema.columns "
                "WHERE table_name=:t AND column_name=:c"
            ),
            {"t": table, "c": col},
        ).fetchone()
        is not None
    )


def _constraint_exists(conn, name: str) -> bool:
    return (
        conn.execute(
            sa.text("SELECT 1 FROM pg_constraint WHERE conname=:n"),
            {"n": name},
        ).fetchone()
        is not None
    )


def upgrade() -> None:
    conn = op.get_bind()

    if not _col_exists(conn, "value_streams", "risk_appetite_policy_id"):
        op.add_column(
            "value_streams",
            sa.Column("risk_appetite_policy_id", sa.String(length=36), nullable=True),
        )

    if not _constraint_exists(conn, "fk_value_streams_risk_appetite_policy"):
        op.create_foreign_key(
            "fk_value_streams_risk_appetite_policy",
            "value_streams",
            "risk_appetite_policies",
            ["risk_appetite_policy_id"],
            ["id"],
            # ⚠️ SET NULL, never CASCADE: a deleted policy must not take the
            # process with it. The process survives and is asked again, which is
            # the honest state — it no longer has an appetite it can name.
            ondelete="SET NULL",
        )

    # ⚠️ **Backfill, or the column regresses every process that already decided.**
    # A process with an active process-scoped policy has plainly made the
    # decision; leaving it null would have the workspace ask again for four of
    # the six processes in the dev organisation alone. The organisation-inherited
    # case cannot be recovered — that decision was only ever an audit event
    # without a process id — so those processes are asked once more, which is
    # the honest state rather than a guess.
    op.execute(
        sa.text(
            """
            UPDATE value_streams AS v
            SET risk_appetite_policy_id = p.id
            FROM risk_appetite_policies AS p
            WHERE p.process_id = v.id
              AND p.scope = 'business_process'
              AND p.status = 'active'
              AND p.organization_id = v.organization_id
              AND v.risk_appetite_policy_id IS NULL
            """
        )
    )


def downgrade() -> None:
    conn = op.get_bind()

    if _constraint_exists(conn, "fk_value_streams_risk_appetite_policy"):
        op.drop_constraint(
            "fk_value_streams_risk_appetite_policy", "value_streams", type_="foreignkey"
        )

    if _col_exists(conn, "value_streams", "risk_appetite_policy_id"):
        op.drop_column("value_streams", "risk_appetite_policy_id")

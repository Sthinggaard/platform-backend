"""Step 4.2 Part 2 (DISC-34) — EvidencePackage idempotency key

Unique constraint on provider_execution_id: a given attempt can only ever
legitimately produce one evidence package (a retry is a brand new
ProviderExecution row, DISC-27/28's own convention) — closes a genuine
concurrent duplicate result-report race that a plain application-level
status check alone cannot. Confirmed no existing duplicate
provider_execution_id rows in the real dev database before writing this
migration. See tasks/active/DISC-26-execution-engine-reconciliation.md.

Revision ID: e5f6a7b8c9d0
Revises: d4e5f6a7b8c9
Create Date: 2026-07-24 00:00:00.000000
"""

from alembic import op
import sqlalchemy as sa

revision = "e5f6a7b8c9d0"
down_revision = "d4e5f6a7b8c9"
branch_labels = None
depends_on = None

_CONSTRAINT_NAME = "uq_evidence_package_provider_execution"


def _constraint_exists(conn, table: str, name: str) -> bool:
    return conn.execute(
        sa.text(
            "SELECT 1 FROM information_schema.table_constraints "
            "WHERE table_name=:t AND constraint_name=:n"
        ),
        {"t": table, "n": name},
    ).fetchone() is not None


def upgrade() -> None:
    conn = op.get_bind()
    if not _constraint_exists(conn, "evidence_packages", _CONSTRAINT_NAME):
        op.create_unique_constraint(_CONSTRAINT_NAME, "evidence_packages", ["provider_execution_id"])


def downgrade() -> None:
    conn = op.get_bind()
    if _constraint_exists(conn, "evidence_packages", _CONSTRAINT_NAME):
        op.drop_constraint(_CONSTRAINT_NAME, "evidence_packages", type_="unique")

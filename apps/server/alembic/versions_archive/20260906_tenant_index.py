"""Index organization_id on the 14 tenant tables that lacked one.

Søren, 2026-09-06: *"You can have pooling but via org_id, and then only load
anything with the org_id, which makes the search in the DB quick or just normal.
But if I have to look through all data sources searching for the org_id every
time I need to retrieve data, it becomes slow."*

Exactly right, and 105 of the platform's 119 tenant tables already worked that
way — `organization_id` leads an index, so a tenant-scoped read goes straight to
its own rows. Fourteen did not, and they sequential-scanned every tenant's rows
to find one tenant's. Measured before this migration:

    EXPLAIN ANALYZE SELECT * FROM collector_readiness_reports WHERE organization_id = 7
      Seq Scan  ...  Rows Removed by Filter: 893

With two organisations that discards 893 rows per read. The proportion discarded
grows with every organisation added, and `collector_readiness_reports` and
`scanner_commands` grow with every Collector poll — so these were the two worst
possible tables to leave unindexed.

⚠️ This is a **performance** fix and nothing more. It does not improve tenant
isolation: separation is still a `WHERE` clause the application has to remember,
row-level security is enabled on no table, and every organisation's data still
shares one database. Those are the security and blast-radius questions, recorded
separately, and an index must not be mistaken for progress on them.

Revision ID: 20260906_tenant_index
Revises: 20260904_notices
"""

from __future__ import annotations

from alembic import op

revision = "20260906_tenant_index"
down_revision = "20260904_notices"
branch_labels = None
depends_on = None

# Ordered by how fast each grows, not alphabetically: the first two are written
# on every Collector poll.
TABLES = (
    "collector_readiness_reports",
    "scanner_commands",
    "scanner_instances",
    "evidence_receipts",
    "verification_inspection_commands",
    "scanner_network_targets",
    "scanner_domain_targets",
    "scanner_credentials",
    "evidence_source_scopes",
    "evidence_source_exceptions",
    "evidence_import_batches",
    "evidence_manual_entries",
    "service_appetite_reassessments",
    "process_scanner_links",
)


def _index(table: str) -> str:
    return f"ix_{table}_organization_id"


def upgrade() -> None:
    for table in TABLES:
        # IF NOT EXISTS because this repo's dev database was created with
        # `create_all` and its alembic_version lags, so a migration can meet a
        # table that already has what it is about to add.
        op.execute(
            f"CREATE INDEX IF NOT EXISTS {_index(table)} ON {table} (organization_id)"
        )


def downgrade() -> None:
    for table in TABLES:
        op.execute(f"DROP INDEX IF EXISTS {_index(table)}")

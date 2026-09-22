"""An observation records where it came from and what it saw (CA-06.2).

Two gaps the CA-06 checklist names, closed together because they are the same
statement about one row — what was seen, and who says so.

**Provenance.** ``asset_evidence_signals`` carried no reference to the evidence
package, the job, or the Collector that produced it; the only trace was an
``ingestionBatchId`` inside a JSON blob. So an inventory claim could not be
traced back to its evidence without re-parsing a raw scanner payload. The three
columns added here, plus ``evidence_package_id`` on the ingestion batch that
carries them through normalization, make the chain artefact → signal → evidence
package → discovery run → Collector answerable by following foreign keys.

All four are **nullable, and stay nullable**. A batch uploaded by hand genuinely
has no evidence package, and rows written before these columns existed genuinely
have no provenance. Nothing is backfilled: an absent reference reads as absent
rather than as a guess, which is the only honest option — the alternative would
be inventing a provenance chain for evidence that never had one.

``ondelete="SET NULL"`` throughout: cleaning up an old run must not delete the
observation that an artefact exists. The claim outlives the paperwork.

**Observed detail.** ``asset_observed_ports`` records the ports and protocols an
artefact has been seen serving, which previously survived only inside
``payload_json`` and as service-name strings in ``Asset.intent``. A row is never
deleted when the port stops answering — ``last_seen_at`` simply stops advancing,
which is what makes "closed since when" answerable. Bounded by construction
(one row per port/protocol per artefact), so unlike the signal stream in
BUG-DISC-18 it cannot grow without limit as scans repeat.

Idempotent per the repo's rules: guarded per table, per column and per index, so
a partial apply can be re-run.

Revision ID: e2c7a48f13bd
Revises: c9f4b12e70da
Create Date: 2026-08-15 00:00:00.000000
"""

from alembic import op
import sqlalchemy as sa

revision = "e2c7a48f13bd"
down_revision = "c9f4b12e70da"
branch_labels = None
depends_on = None

_SIGNALS = "asset_evidence_signals"
_BATCHES = "risk_intelligence_ingestion_batches"
_PORTS = "asset_observed_ports"

_PORTS_UNIQUE_INDEX = "uq_asset_observed_ports_asset_port_protocol"
_PORTS_ORG_ASSET_INDEX = "ix_asset_observed_ports_org_asset"
_PORTS_ORG_INDEX = "ix_asset_observed_ports_organization_id"
_PORTS_ASSET_INDEX = "ix_asset_observed_ports_asset_id"
_BATCH_PACKAGE_INDEX = "ix_risk_intelligence_ingestion_batches_evidence_package_id"

#: (table, column, type, referenced table) — every one additive and nullable.
_PROVENANCE_COLUMNS = (
    (_SIGNALS, "evidence_package_id", sa.String(36), "evidence_packages"),
    (_SIGNALS, "provider_execution_id", sa.String(36), "provider_executions"),
    (_SIGNALS, "scanner_instance_id", sa.String(36), "scanner_instances"),
    (_BATCHES, "evidence_package_id", sa.String(36), "evidence_packages"),
)


def _table_exists(conn, table: str) -> bool:
    return conn.execute(
        sa.text("SELECT 1 FROM information_schema.tables WHERE table_name = :t"),
        {"t": table},
    ).fetchone() is not None


def _col_exists(conn, table: str, column: str) -> bool:
    return conn.execute(
        sa.text(
            "SELECT 1 FROM information_schema.columns "
            "WHERE table_name = :t AND column_name = :c"
        ),
        {"t": table, "c": column},
    ).fetchone() is not None


def _constraint_exists(conn, name: str) -> bool:
    return conn.execute(
        sa.text("SELECT 1 FROM pg_constraint WHERE conname = :n"),
        {"n": name},
    ).fetchone() is not None


def upgrade() -> None:
    conn = op.get_bind()

    for table, column, column_type, referenced_table in _PROVENANCE_COLUMNS:
        if not _table_exists(conn, table) or _col_exists(conn, table, column):
            continue
        op.add_column(table, sa.Column(column, column_type, nullable=True))
        if _table_exists(conn, referenced_table):
            # Guarded: the discovery-execution tables are created by their own
            # migration, and a database that has not reached it yet should get
            # the column now and the constraint when the target exists, rather
            # than failing the whole migration.
            op.create_foreign_key(
                f"fk_{table}_{column}",
                table,
                referenced_table,
                [column],
                ["id"],
                ondelete="SET NULL",
            )

    if _table_exists(conn, _BATCHES):
        op.create_index(
            _BATCH_PACKAGE_INDEX, _BATCHES, ["evidence_package_id"], if_not_exists=True
        )

    if not _table_exists(conn, _PORTS):
        op.create_table(
            _PORTS,
            sa.Column("id", sa.Integer(), primary_key=True),
            sa.Column(
                "organization_id", sa.Integer(), sa.ForeignKey("organizations.id"), nullable=False
            ),
            sa.Column(
                "asset_id",
                sa.Integer(),
                sa.ForeignKey("assets.id", ondelete="CASCADE"),
                nullable=False,
            ),
            sa.Column("port", sa.Integer(), nullable=False),
            # Never NULL: in SQL NULL is not equal to NULL, so a nullable
            # protocol would defeat the uniqueness below and every rescan of the
            # same port would insert another row. "unknown" is stated instead.
            sa.Column("protocol", sa.String(10), nullable=False),
            sa.Column("service_name", sa.String(100), nullable=True),
            sa.Column("product", sa.String(255), nullable=True),
            sa.Column("product_version", sa.String(100), nullable=True),
            sa.Column("first_seen_at", sa.DateTime(), nullable=False),
            sa.Column("last_seen_at", sa.DateTime(), nullable=False),
        )

    op.create_index(
        _PORTS_UNIQUE_INDEX,
        _PORTS,
        ["asset_id", "port", "protocol"],
        unique=True,
        if_not_exists=True,
    )
    op.create_index(_PORTS_ORG_ASSET_INDEX, _PORTS, ["organization_id", "asset_id"], if_not_exists=True)
    op.create_index(_PORTS_ORG_INDEX, _PORTS, ["organization_id"], if_not_exists=True)
    op.create_index(_PORTS_ASSET_INDEX, _PORTS, ["asset_id"], if_not_exists=True)


def downgrade() -> None:
    conn = op.get_bind()

    if _table_exists(conn, _PORTS):
        for index in (
            _PORTS_ASSET_INDEX,
            _PORTS_ORG_INDEX,
            _PORTS_ORG_ASSET_INDEX,
            _PORTS_UNIQUE_INDEX,
        ):
            op.drop_index(index, table_name=_PORTS, if_exists=True)
        op.drop_table(_PORTS)

    if _table_exists(conn, _BATCHES):
        op.drop_index(_BATCH_PACKAGE_INDEX, table_name=_BATCHES, if_exists=True)

    for table, column, _column_type, _referenced_table in _PROVENANCE_COLUMNS:
        if not _table_exists(conn, table) or not _col_exists(conn, table, column):
            continue
        # The constraint is created only when its target table exists, so its
        # absence here is a legitimate state, not an error.
        if _constraint_exists(conn, f"fk_{table}_{column}"):
            op.drop_constraint(f"fk_{table}_{column}", table, type_="foreignkey")
        op.drop_column(table, column)

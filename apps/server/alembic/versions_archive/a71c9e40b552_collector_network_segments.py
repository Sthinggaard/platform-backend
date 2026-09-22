"""#321/#320 — a Collector records the network it is standing on.

The platform has never known where a Collector sits. ``describe_host()`` reports
architecture, kernel and OS; nothing reports the Collector's own addresses. So
the one question that decides whether a scan can work at all — *is this Collector
attached to the network it is being asked to scan?* — could not be asked.

Two live failures followed, both on 2026-08-27:

* An estate approved for ``192.168.1.0/24`` on a network renumbered to
  ``192.168.50.0/24``. Every artefact was an echo of a /24 that no longer
  existed, and nothing in the product was positioned to notice.
* ``raw_packet_access`` answers *may I send raw packets*, and Docker grants
  ``CAP_NET_RAW`` to root containers by default — so it answers **True almost
  everywhere**, including where the container sees only ``172.x`` bridges and
  can never ARP the estate. The platform was told it could see hardware
  addresses in exactly the case where it could not.

Additive and nullable: a Collector that has never reported leaves this null, and
null means *we do not know where it is* — deliberately not *it is nowhere*.
Reading an unknown as a negative is the same class of mistake this column exists
to end.

Revision ID: a71c9e40b552
Revises: 20260824_inspection_identity
Create Date: 2026-08-27 00:00:00.000000
"""

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision = "a71c9e40b552"
down_revision = "20260824_inspection_identity"
branch_labels = None
depends_on = None

_TABLE = "scanner_instances"
_COLUMN = "network_segments"


def _col_exists(conn) -> bool:
    row = conn.execute(
        sa.text(
            "SELECT 1 FROM information_schema.columns "
            "WHERE table_name = :table AND column_name = :column"
        ),
        {"table": _TABLE, "column": _COLUMN},
    ).first()
    return row is not None


def upgrade() -> None:
    conn = op.get_bind()
    if _col_exists(conn):
        return
    op.add_column(
        _TABLE,
        sa.Column(_COLUMN, postgresql.JSONB(astext_type=sa.Text()), nullable=True),
    )


def downgrade() -> None:
    conn = op.get_bind()
    if not _col_exists(conn):
        return
    op.drop_column(_TABLE, _COLUMN)

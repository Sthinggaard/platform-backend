"""#460 — a dependency's resilience answers live on its slot record

Adds seven nullable columns to `slot_instances`: `spof`, `fallback_status`, `recovery_dependent`,
`impact_type`, `business_impact_level`, `business_consequence` and `critical_for_business`. Then it
copies the answers already given onto them.

**Why.** An owner's dependency decision was stored in two places.
- The step slide-out wrote a slot record.
- The service setup page wrote a bundle node.
- The map read only the nodes (#452).

Søren, 2026-09-15: the slot record is the one live record, and bundle nodes become the published
snapshot. The resilience answers existed only on nodes, so they move here first.

**What is copied.** From the development database on 2026-09-15, only the 15 hand-added nodes in
organisation 7 held answers a slot record lacked: SPOF, impact and recovery on all 15, fallback on
none. Nodes written by the slot wizard carry no answers and duplicate slot records the wizard wrote
at the same time, so there is nothing to copy from them.

- **Matching.** A node matches the slot record of the same organisation, service and group whose
  `slot_id` equals the node's `template_key`, or ends with `.<template_key>`. Templates namespace
  some slot ids, e.g. `billing_subscription_management.application.api_service` for `api_service`.
  All 15 match in development.
- **No overwrite.** A slot record that already holds any answer is left alone.
- **Artefacts are not copied.** Every matched slot in development already holds the node's artefact.
  Moving an asset link is a mapping decision, not an answer, so it is not made here.
- **Answered nodes with no matching slot record** are counted and logged, never guessed.

**Values.** Frozen here as of 2026-09-15 and mirroring `core/constants/dependency_assessment_enums.py`.
A migration must not import application code that later changes. A value outside the list is
copied as null, never invented.

Idempotent: the columns are guarded, and the backfill only fills slot records with no answer yet, so
a second run changes nothing.

**On the inline `nosemgrep`.** `avoid-sqlalchemy-text` fires on the two statements because they are
f-strings. The only values interpolated are this module's constants `_NODES`, `_MATCH` and `_ANSWERED`,
so nothing a request can reach. Suppressed at the site with the rule id, as
`20260913_asset_link_spelling` does.

Revision ID: 20260915_slot_assessment
Revises: 20260914_merge_heads
Create Date: 2026-09-15 00:00:00.000000
"""

import logging

import sqlalchemy as sa

from alembic import op

# ⚠️ 32 characters is the hard limit for `alembic_version.version_num`; this is 24.
revision = "20260915_slot_assessment"
down_revision = "20260914_merge_heads"
branch_labels = None
depends_on = None

logger = logging.getLogger("alembic.runtime.migration")

#: (column, SQLAlchemy type). One list, so the upgrade and the downgrade cannot disagree.
ASSESSMENT_COLUMNS: tuple[tuple[str, sa.types.TypeEngine], ...] = (
    ("spof", sa.Boolean()),
    ("fallback_status", sa.String(length=10)),
    ("recovery_dependent", sa.Boolean()),
    ("impact_type", sa.String(length=20)),
    ("business_impact_level", sa.String(length=10)),
    ("business_consequence", sa.Text()),
    ("critical_for_business", sa.Boolean()),
)

# Every node of every bundle, skipping anything that is not an object or not an array.
_NODES = """
    FROM dependency_bundles AS b
    CROSS JOIN LATERAL jsonb_array_elements(
        CASE WHEN jsonb_typeof(b.groups) = 'array' THEN b.groups ELSE '[]'::jsonb END
    ) AS grp
    CROSS JOIN LATERAL jsonb_array_elements(
        CASE WHEN jsonb_typeof(grp->'nodes') = 'array' THEN grp->'nodes' ELSE '[]'::jsonb END
    ) AS node
"""

# The slot record a node belongs to.
_MATCH = """
    slot.organization_id = b.organization_id
    AND slot.service_id = b.service_id
    AND slot.group_key = grp->>'key'
    AND coalesce(node->>'template_key', '') <> ''
    AND (
        slot.slot_id = node->>'template_key'
        OR right(slot.slot_id, length(node->>'template_key') + 1) = '.' || (node->>'template_key')
    )
"""

# A node that carries at least one answer.
_ANSWERED = """
    jsonb_typeof(grp) = 'object'
    AND jsonb_typeof(node) = 'object'
    AND (
        jsonb_typeof(node->'spof') = 'boolean'
        OR coalesce(node->>'fallback_status', '') <> ''
        OR jsonb_typeof(node->'recovery_dependent') = 'boolean'
        OR coalesce(node->>'impact_type', '') <> ''
        OR coalesce(node->>'business_impact_level', '') <> ''
        OR coalesce(node->>'business_consequence', '') <> ''
        OR jsonb_typeof(node->'critical_for_business') = 'boolean'
    )
"""

BACKFILL_SLOT_ASSESSMENT = sa.text(  # nosemgrep: python.sqlalchemy.security.audit.avoid-sqlalchemy-text.avoid-sqlalchemy-text
    f"""
    UPDATE slot_instances AS s
    SET spof = src.spof,
        fallback_status = src.fallback_status,
        recovery_dependent = src.recovery_dependent,
        impact_type = src.impact_type,
        business_impact_level = src.business_impact_level,
        business_consequence = src.business_consequence,
        critical_for_business = src.critical_for_business
    FROM (
        SELECT DISTINCT ON (slot.id)
            slot.id AS slot_row_id,
            CASE WHEN jsonb_typeof(node->'spof') = 'boolean'
                 THEN (node->>'spof')::boolean END AS spof,
            CASE WHEN node->>'fallback_status' IN ('none', 'partial', 'full')
                 THEN node->>'fallback_status' END AS fallback_status,
            CASE WHEN jsonb_typeof(node->'recovery_dependent') = 'boolean'
                 THEN (node->>'recovery_dependent')::boolean END AS recovery_dependent,
            CASE WHEN node->>'impact_type' IN ('availability', 'confidentiality', 'integrity', 'combined')
                 THEN node->>'impact_type' END AS impact_type,
            CASE WHEN node->>'business_impact_level' IN ('high', 'medium', 'low')
                 THEN node->>'business_impact_level' END AS business_impact_level,
            NULLIF(node->>'business_consequence', '') AS business_consequence,
            CASE WHEN jsonb_typeof(node->'critical_for_business') = 'boolean'
                 THEN (node->>'critical_for_business')::boolean END AS critical_for_business
        {_NODES}
        JOIN slot_instances AS slot ON {_MATCH}
        WHERE {_ANSWERED}
        ORDER BY slot.id, node->>'id'
    ) AS src
    WHERE s.id = src.slot_row_id
      AND s.spof IS NULL
      AND s.fallback_status IS NULL
      AND s.recovery_dependent IS NULL
      AND s.impact_type IS NULL
      AND s.business_impact_level IS NULL
      AND s.business_consequence IS NULL
      AND s.critical_for_business IS NULL
    """
)

COUNT_UNMATCHED_ANSWERED_NODES = sa.text(  # nosemgrep: python.sqlalchemy.security.audit.avoid-sqlalchemy-text.avoid-sqlalchemy-text
    f"""
    SELECT count(*)
    {_NODES}
    WHERE {_ANSWERED}
      AND NOT EXISTS (SELECT 1 FROM slot_instances AS slot WHERE {_MATCH})
    """
)


def _table_exists(conn, table: str) -> bool:
    return (
        conn.execute(
            sa.text("SELECT 1 FROM information_schema.tables WHERE table_name=:t"),
            {"t": table},
        ).fetchone()
        is not None
    )


def _col_exists(conn, table: str, col: str) -> bool:
    return (
        conn.execute(
            sa.text(
                "SELECT 1 FROM information_schema.columns WHERE table_name=:t AND column_name=:c"
            ),
            {"t": table, "c": col},
        ).fetchone()
        is not None
    )


def upgrade() -> None:
    conn = op.get_bind()
    if not _table_exists(conn, "slot_instances"):
        return

    for name, column_type in ASSESSMENT_COLUMNS:
        if not _col_exists(conn, "slot_instances", name):
            op.add_column("slot_instances", sa.Column(name, column_type, nullable=True))

    if _table_exists(conn, "dependency_bundles"):
        copied = conn.execute(BACKFILL_SLOT_ASSESSMENT).rowcount
        unmatched = conn.execute(COUNT_UNMATCHED_ANSWERED_NODES).scalar() or 0
        logger.info(
            "20260915_slot_assessment: copied answers onto %s slot records; "
            "%s answered bundle nodes have no matching slot record and were left on the node",
            copied,
            unmatched,
        )


def downgrade() -> None:
    conn = op.get_bind()
    if not _table_exists(conn, "slot_instances"):
        return
    for name, _ in reversed(ASSESSMENT_COLUMNS):
        if _col_exists(conn, "slot_instances", name):
            op.drop_column("slot_instances", name)

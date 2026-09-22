"""#363 — one stored spelling for an asset link, in both places it is stored.

Asset links reached storage as ``"asset-92"``, as the bare integer ``92``, and as
the digit string ``"92"``. ``20260830_asset_refs`` rewrote the integers and left
every string untouched by design, so the digit strings survived it. They came
from the scanner's slot-mapping suggestions, which wrote ``str(asset.id)``, and
were carried into slot rows and bundle links when a suggestion was accepted. On the
development
database on 2026-09-13: 9 of 71 bundle links and 38 of 118 non-null
``slot_instances.asset_id`` values.

Readers already normalise, so nothing showed as unmapped. What the second spelling
broke was every raw comparison: ``unassign_asset`` could not remove a link stored
in the other spelling, ``assign_asset`` could store one asset twice, and
``asset_context_service._find_asset_dependencies`` matches ``SlotInstance.asset_id``
against ``"asset-N"`` and so never saw the 38 rows.

The writers are fixed at source in the same change; this converges what is
already stored. A node holding one asset in both spellings keeps it once, in the
position it first appeared.

``dependency_bundle_versions`` is left alone deliberately: a published version is
a record of what was stored at the time, and none held a digit string.

Idempotent: every statement touches only values still in a non-canonical spelling,
so a second run finds nothing. Guarded on each table existing.

**On the inline ``nosemgrep``**: ``avoid-sqlalchemy-text`` fires on
``NORMALISE_BUNDLE_LINKS`` because it is an f-string. The only values it interpolates
are the module constants ``_CANONICAL_REF`` and ``_NON_CANONICAL_REF``, so nothing a
request can reach. Suppressed at the site with the rule id, as
``20260824_verification_inspection_commands`` does.

Revision ID: 20260913_asset_link_spelling
Revises: 20260910_schema_baseline
Create Date: 2026-09-13 00:00:00.000000
"""

import sqlalchemy as sa

from alembic import op

# ⚠️ 32 characters is the hard limit for `alembic_version.version_num`; this is 28.
revision = "20260913_asset_link_spelling"
down_revision = "20260910_schema_baseline"
branch_labels = None
depends_on = None

# A node's link, in its stored spelling: numbers and digit strings gain the prefix,
# every other value passes through exactly as it was.
_CANONICAL_REF = """
    CASE
        WHEN jsonb_typeof(ref) = 'number'
            THEN to_jsonb('asset-' || (ref #>> '{}'))
        WHEN jsonb_typeof(ref) = 'string' AND (ref #>> '{}') ~ '^[0-9]+$'
            THEN to_jsonb('asset-' || (ref #>> '{}'))
        ELSE ref
    END
"""

# Whether a stored value is still in a spelling this migration rewrites.
_NON_CANONICAL_REF = """
    (jsonb_typeof(ref) = 'number'
     OR (jsonb_typeof(ref) = 'string' AND (ref #>> '{}') ~ '^[0-9]+$'))
"""

NORMALISE_BUNDLE_LINKS = sa.text(  # nosemgrep: python.sqlalchemy.security.audit.avoid-sqlalchemy-text.avoid-sqlalchemy-text
    f"""
    UPDATE dependency_bundles AS b
    SET groups = (
        SELECT jsonb_agg(
            CASE
                WHEN jsonb_typeof(grp) = 'object' AND jsonb_typeof(grp->'nodes') = 'array'
                THEN jsonb_set(
                    grp,
                    '{{nodes}}',
                    (
                        SELECT COALESCE(jsonb_agg(
                            CASE
                                WHEN jsonb_typeof(node) = 'object'
                                     AND jsonb_typeof(node->'linked_asset_ids') = 'array'
                                THEN jsonb_set(
                                    node,
                                    '{{linked_asset_ids}}',
                                    (
                                        SELECT COALESCE(jsonb_agg(canonical ORDER BY first_position), '[]'::jsonb)
                                        FROM (
                                            SELECT canonical, min(position) AS first_position
                                            FROM (
                                                SELECT {_CANONICAL_REF} AS canonical, position
                                                FROM jsonb_array_elements(node->'linked_asset_ids')
                                                     WITH ORDINALITY AS links(ref, position)
                                            ) AS spelled
                                            GROUP BY canonical
                                        ) AS once
                                    )
                                )
                                ELSE node
                            END
                            ORDER BY node_position
                        ), '[]'::jsonb)
                        FROM jsonb_array_elements(grp->'nodes') WITH ORDINALITY AS nodes(node, node_position)
                    )
                )
                ELSE grp
            END
            ORDER BY group_position
        )
        FROM jsonb_array_elements(b.groups) WITH ORDINALITY AS grps(grp, group_position)
    )
    WHERE jsonb_typeof(b.groups) = 'array'
      AND EXISTS (
          SELECT 1
          FROM jsonb_array_elements(b.groups) AS g,
               jsonb_array_elements(
                   CASE WHEN jsonb_typeof(g->'nodes') = 'array' THEN g->'nodes' ELSE '[]'::jsonb END
               ) AS n,
               jsonb_array_elements(
                   CASE WHEN jsonb_typeof(n->'linked_asset_ids') = 'array' THEN n->'linked_asset_ids' ELSE '[]'::jsonb END
               ) AS ref
          WHERE {_NON_CANONICAL_REF}
      )
    """
)

NORMALISE_SLOT_ASSETS = sa.text(
    """
    UPDATE slot_instances
    SET asset_id = 'asset-' || asset_id
    WHERE asset_id ~ '^[0-9]+$'
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


def upgrade() -> None:
    conn = op.get_bind()
    if _table_exists(conn, "dependency_bundles"):
        conn.execute(NORMALISE_BUNDLE_LINKS)
    if _table_exists(conn, "slot_instances"):
        conn.execute(NORMALISE_SLOT_ASSETS)


def downgrade() -> None:
    """Deliberately not reversed.

    Which rows were stored as ``"92"`` rather than ``"asset-92"`` is not recorded,
    and restoring a second spelling would reintroduce the defect rather than a
    prior state worth having. Nothing depends on the digit-string form.
    """
    return

"""#363 — one stored shape for a dependency's asset link.

``DependencyBundle.groups[].nodes[].linked_asset_ids`` held two shapes. The
Risklence internal tenant seed wrote the bare integer ``92``; every other writer
and every reader uses ``"asset-92"``. Readers accepting only the reference form
dropped the integers silently — the slot reported as *Unmapped* while a human
was looking at the asset linked to it, which inflated mapping-gap counts and hid
the SPOF and evidence signals on exactly those slots.

The seed is fixed at source. This normalises what is already stored so every
reader agrees, rather than each one compensating.

Idempotent: it only rewrites elements that are JSON numbers, so re-running finds
nothing to do. Guarded on the table existing.

Revision ID: 20260830_asset_refs
Revises: 20260830_service_tier_vocabulary
Create Date: 2026-08-30 18:20:00.000000
"""

import sqlalchemy as sa

from alembic import op

revision = "20260830_asset_refs"
down_revision = "20260830_service_tier_vocabulary"
branch_labels = None
depends_on = None

_TABLE = "dependency_bundles"

# Rewrites every numeric element of every node's linked_asset_ids to the
# canonical "asset-{id}" string, leaving strings and every other key untouched.
_NORMALISE = sa.text(
    """
    UPDATE dependency_bundles AS b
    SET groups = (
        SELECT jsonb_agg(
            CASE
                WHEN jsonb_typeof(grp) = 'object' AND grp ? 'nodes'
                THEN jsonb_set(
                    grp,
                    '{nodes}',
                    (
                        SELECT COALESCE(jsonb_agg(
                            CASE
                                WHEN jsonb_typeof(node) = 'object' AND node ? 'linked_asset_ids'
                                THEN jsonb_set(
                                    node,
                                    '{linked_asset_ids}',
                                    (
                                        SELECT COALESCE(jsonb_agg(
                                            CASE
                                                WHEN jsonb_typeof(ref) = 'number'
                                                THEN to_jsonb('asset-' || (ref #>> '{}'))
                                                ELSE ref
                                            END
                                        ), '[]'::jsonb)
                                        FROM jsonb_array_elements(node->'linked_asset_ids') AS ref
                                    )
                                )
                                ELSE node
                            END
                        ), '[]'::jsonb)
                        FROM jsonb_array_elements(grp->'nodes') AS node
                    )
                )
                ELSE grp
            END
        )
        FROM jsonb_array_elements(b.groups) AS grp
    )
    WHERE b.groups IS NOT NULL
      AND jsonb_typeof(b.groups) = 'array'
      AND EXISTS (
          SELECT 1
          FROM jsonb_array_elements(b.groups) AS g,
               jsonb_array_elements(COALESCE(g->'nodes', '[]'::jsonb)) AS n,
               jsonb_array_elements(COALESCE(n->'linked_asset_ids', '[]'::jsonb)) AS r
          WHERE jsonb_typeof(r) = 'number'
      )
    """
)


def _table_exists(conn, table: str) -> bool:
    return conn.execute(
        sa.text("SELECT 1 FROM information_schema.tables WHERE table_name=:t"),
        {"t": table},
    ).fetchone() is not None


def upgrade() -> None:
    conn = op.get_bind()
    if not _table_exists(conn, _TABLE):
        return
    conn.execute(_NORMALISE)


def downgrade() -> None:
    """Deliberately not reversed.

    The canonical form is what every reader and every other writer already uses,
    so turning references back into bare integers would reintroduce the defect
    rather than restore a prior state. Nothing depends on the old shape.
    """
    return

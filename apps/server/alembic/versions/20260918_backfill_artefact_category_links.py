"""Backfill unambiguous legacy dependency mappings into #493 library links."""

import sqlalchemy as sa
from alembic import op


revision = "20260918_backfill_artefact_category_links"
down_revision = "20260918_artefact_library_dependency_links"
branch_labels = None
depends_on = None


def upgrade() -> None:
    conn = op.get_bind()
    # A prior mapped slot is a human-approved service fact. It may seed a
    # library category only when all existing mappings for that Artefact agree;
    # cross-category evidence stays unlabelled for a library reviewer.
    conn.execute(sa.text("""
        WITH mapped AS (
          SELECT organization_id, service_id, regexp_replace(asset_id, '^asset-', '')::integer AS asset_id,
                 dependency_category
          FROM slot_instances
          WHERE status = 'mapped' AND dependency_category IS NOT NULL
            AND asset_id ~ '^(asset-)?[0-9]+$'
        ), agreed AS (
          SELECT organization_id, asset_id, min(dependency_category) AS dependency_category
          FROM mapped GROUP BY organization_id, asset_id
          HAVING count(DISTINCT dependency_category) = 1
        )
        UPDATE assets asset SET dependency_category = agreed.dependency_category
        FROM agreed WHERE asset.organization_id = agreed.organization_id AND asset.id = agreed.asset_id
          AND asset.dependency_category IS NULL
    """))
    conn.execute(sa.text("""
        WITH mapped AS (
          SELECT organization_id, service_id, regexp_replace(asset_id, '^asset-', '')::integer AS asset_id,
                 dependency_category
          FROM slot_instances
          WHERE status = 'mapped' AND dependency_category IS NOT NULL
            AND asset_id ~ '^(asset-)?[0-9]+$'
        ), agreed AS (
          SELECT organization_id, asset_id, min(dependency_category) AS dependency_category
          FROM mapped GROUP BY organization_id, asset_id
          HAVING count(DISTINCT dependency_category) = 1
        )
        INSERT INTO service_artefact_dependency_links
          (id, organization_id, service_id, asset_id, dependency_category, linked_at)
        SELECT md5(mapped.organization_id::text || ':' || mapped.service_id || ':' || mapped.asset_id::text),
          mapped.organization_id, mapped.service_id, mapped.asset_id, agreed.dependency_category, now()
        FROM mapped JOIN agreed USING (organization_id, asset_id)
        JOIN assets asset ON asset.organization_id = mapped.organization_id AND asset.id = mapped.asset_id
        ON CONFLICT ON CONSTRAINT uq_service_artefact_dependency_link DO NOTHING
    """))


def downgrade() -> None:
    # Legacy records were not deleted or overwritten; reversal must not erase
    # links a person could have added after this migration ran.
    pass

"""Remove #493's automatic legacy category inference.

Artefact categories are a library-level human decision. A prior slot mapping is
evidence, not permission to classify an Artefact or link it to another service.
"""

import sqlalchemy as sa
from alembic import op


revision = "20260918_remove_inferred_artefact_category_links"
down_revision = "20260918_backfill_artefact_category_links"
branch_labels = None
depends_on = None


def upgrade() -> None:
    conn = op.get_bind()
    # The predecessor migration was the only writer that created links without
    # an actor. Human-confirmed links always retain linked_by_user_id.
    conn.execute(
        sa.text(
            "DELETE FROM service_artefact_dependency_links WHERE linked_by_user_id IS NULL"
        )
    )
    # It also populated categories without the library review event that the
    # category endpoint writes. Do not leave inferred classifications behind.
    conn.execute(
        sa.text(
            """
            UPDATE assets asset
            SET dependency_category = NULL
            WHERE dependency_category IS NOT NULL
              AND NOT EXISTS (
                SELECT 1 FROM audit_events event
                WHERE event.organization_id = asset.organization_id
                  AND event.event_type = 'artefact.dependency_category_set'
                  AND event.metadata ->> 'assetId' = asset.id::text
              )
            """
        )
    )


def downgrade() -> None:
    # A removed inference must not be recreated on downgrade.
    pass

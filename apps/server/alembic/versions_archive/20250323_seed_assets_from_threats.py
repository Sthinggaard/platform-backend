"""Seed CMDB assets from threat data and wire into business services.

For every unique (asset, tier) pair in the threats table, creates a real
Asset CMDB record and groups them into BusinessService rows via l1[] arrays.
The service l1 IDs use the "asset-{id}" format that the frontend mapper
(useAssets.ts) produces, so the MAP and APPETITE config tabs show live data.
"""

from __future__ import annotations

import uuid as _uuid
from datetime import datetime
from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op
from sqlalchemy import text

revision: str = "20250323_seed_assets_from_threats"
down_revision: Union[str, None] = "20250322_add_threats_and_services"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def _seed_for_org(bind, org_id: int) -> None:
    """Seed CMDB assets and business services for a single organisation."""

    # ── Collect unique (asset, tier) pairs from threats ───────────────────────
    pairs = bind.execute(
        text("""
            SELECT DISTINCT asset, tier
            FROM   threats
            WHERE  organization_id = :org_id
              AND  asset IS NOT NULL
              AND  asset != ''
            ORDER  BY tier, asset
        """),
        {"org_id": org_id},
    ).fetchall()

    if not pairs:
        return

    now = datetime.utcnow()

    # ── Get already-existing assets for this org ──────────────────────────────
    existing_rows = bind.execute(
        text("SELECT display_name, id FROM assets WHERE organization_id = :org_id"),
        {"org_id": org_id},
    ).fetchall()
    existing: dict[str, int] = {r[0]: r[1] for r in existing_rows}

    # ── 4. Insert missing assets; collect name → (id, tier) mapping ──────────
    asset_records: dict[str, tuple[int, str]] = {}

    for asset_name, tier in pairs:
        if asset_name in existing:
            asset_records[asset_name] = (existing[asset_name], tier)
            continue

        criticality = "CRITICAL" if tier == "Mission Critical" else "HIGH"
        risk_score = 80.0 if criticality == "CRITICAL" else 65.0

        result = bind.execute(
            text("""
                INSERT INTO assets (
                    organization_id, type, display_name, layer,
                    environment, criticality, status, connectivity_status,
                    setup_confidence, scan_start_mode,
                    posture_stale, risk_score, findings_count, confidence,
                    created_at, updated_at
                ) VALUES (
                    :org_id, 'Application', :name, 'Application',
                    'PROD', :criticality, 'AT_RISK', 'DEGRADED',
                    'MEDIUM', 'AFTER_SME_CONFIRM',
                    false, :risk_score, 0, 0.8,
                    :now, :now
                ) RETURNING id
            """),
            {
                "org_id": org_id,
                "name": asset_name,
                "criticality": criticality,
                "risk_score": risk_score,
                "now": now,
            },
        )
        new_id: int = result.fetchone()[0]
        asset_records[asset_name] = (new_id, tier)

    # ── 5. Check if services already exist ───────────────────────────────────
    existing_svcs = bind.execute(
        text("SELECT id, tier FROM business_services WHERE organization_id = :org_id"),
        {"org_id": org_id},
    ).fetchall()

    # ── 6. Group assets by tier → service l1 arrays ───────────────────────────
    # The frontend useAssets.ts mapper wraps integer IDs as "asset-{id}",
    # and useDecisionData.ts matches service.l1[] against asset.id strings.
    mc_ids = [
        f"asset-{aid}"
        for name, (aid, tier) in asset_records.items()
        if tier == "Mission Critical"
    ]
    bc_ids = [
        f"asset-{aid}"
        for name, (aid, tier) in asset_records.items()
        if tier == "Business Critical"
    ]

    # ── 7. Upsert business services ───────────────────────────────────────────
    existing_mc = next((s[0] for s in existing_svcs if s[1] == "Mission Critical"), None)
    existing_bc = next((s[0] for s in existing_svcs if s[1] == "Business Critical"), None)

    if mc_ids:
        if existing_mc:
            bind.execute(
                text("UPDATE business_services SET l1 = :l1, l2 = :l2, l3 = :l3, trading_impact = :impact WHERE id = :id"),
                {"id": existing_mc, "l1": mc_ids, "l2": [], "l3": [],
                 "impact": "Core platform revenue generation — primary trading infrastructure"},
            )
        else:
            bind.execute(
                text("""
                    INSERT INTO business_services
                        (id, organization_id, name, tier, trading_impact, l1, l2, l3, created_at, updated_at)
                    VALUES
                        (:id, :org_id, 'Mission Critical Operations', 'Mission Critical',
                         'Core platform revenue generation — primary trading infrastructure',
                         :l1, :l2, :l3, :now, :now)
                """),
                {"id": str(_uuid.uuid4()), "org_id": org_id, "l1": mc_ids, "l2": [], "l3": [], "now": now},
            )

    if bc_ids:
        if existing_bc:
            bind.execute(
                text("UPDATE business_services SET l1 = :l1, l2 = :l2, l3 = :l3, trading_impact = :impact WHERE id = :id"),
                {"id": existing_bc, "l1": bc_ids, "l2": [], "l3": [],
                 "impact": "Supporting business functions — operational continuity"},
            )
        else:
            bind.execute(
                text("""
                    INSERT INTO business_services
                        (id, organization_id, name, tier, trading_impact, l1, l2, l3, created_at, updated_at)
                    VALUES
                        (:id, :org_id, 'Business Critical Operations', 'Business Critical',
                         'Supporting business functions — operational continuity',
                         :l1, :l2, :l3, :now, :now)
                """),
                {"id": str(_uuid.uuid4()), "org_id": org_id, "l1": bc_ids, "l2": [], "l3": [], "now": now},
            )


def upgrade() -> None:
    bind = op.get_bind()

    # Iterate every organisation that has threat data — org IDs vary per environment.
    org_rows = bind.execute(
        text("""
            SELECT DISTINCT organization_id
            FROM   threats
            WHERE  asset IS NOT NULL AND asset != ''
        """)
    ).fetchall()

    for (org_id,) in org_rows:
        _seed_for_org(bind, org_id)


def downgrade() -> None:
    # Data-only migration — no schema changes to reverse.
    # Removing seeded rows on downgrade is intentionally a no-op to protect
    # any edits the user may have made via the UI.
    pass

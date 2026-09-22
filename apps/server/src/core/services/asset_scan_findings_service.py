"""What the vulnerability scanner has found on an artefact.

One question, asked by two read surfaces — the standing artefact inventory and a
discovery run's results — so it lives in neither of them. A copy in each is how
one artefact starts reporting a different number of findings on two pages.

⚠️ ``asset_findings`` is a **shared** table. The asset-monitoring engine writes
its own rows into it under the ``network`` domain — 160 of them in organisation 7
on 2026-09-07, none of which any scanner produced. Every reader here filters on
``FINDING_DOMAIN_RISK_INTELLIGENCE`` for that reason: counting the table instead
would report a scan result on artefacts no scan has ever reached, which is an
assertion posing as an observation.
"""

from __future__ import annotations

from datetime import datetime

from sqlalchemy import func
from sqlalchemy.orm import Session

from src.core.constants.risk_intelligence_ingestion import FINDING_DOMAIN_RISK_INTELLIGENCE
from src.core.model_defs.assets_runtime import AssetFinding, AssetFindingStatus

def scan_findings_by_asset(
    db: Session, *, organization_id: int, asset_ids: list[int]
) -> dict[int, tuple[int, datetime | None]]:
    """What the last vulnerability scan found on each artefact, and when.

    Scoped to ``FINDING_DOMAIN_RISK_INTELLIGENCE`` — findings normalisation wrote from scanner
    evidence — deliberately, and **not** to every ``AssetFinding``. The
    asset-monitoring engine writes its own rows into the same table under the
    ``network`` domain (160 of them in organisation 7, none from a scanner), so
    counting the table would report a scan result on artefacts no scan has ever
    reached.

    Resolved findings are excluded: the question this answers on the row is
    "what did the last scan find", and a finding somebody has already dealt with
    is not that.
    """
    if not asset_ids:
        return {}
    rows = (
        db.query(
            AssetFinding.asset_id,
            func.count(AssetFinding.id),
            func.max(AssetFinding.last_seen_at),
        )
        .filter(AssetFinding.organization_id == organization_id)
        .filter(AssetFinding.asset_id.in_(asset_ids))
        .filter(AssetFinding.domain == FINDING_DOMAIN_RISK_INTELLIGENCE)
        .filter(AssetFinding.status != AssetFindingStatus.RESOLVED)
        .group_by(AssetFinding.asset_id)
        .all()
    )
    return {asset_id: (count, last_seen) for asset_id, count, last_seen in rows}


__all__ = ["scan_findings_by_asset"]

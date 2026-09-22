"""Cross-organisation Risk Appetite peer benchmark for the recommendation engine.

Deliberate, narrow exception to the per-tenant isolation rule: this module
reads other organisations' *active* Risk Appetite answers to compute an
aggregate, never a per-organisation lookup. It never returns which
organisation set what value, never returns raw per-org rows, and returns
nothing at all — not even a count — for a dimension until at least
``MIN_PEER_COUNT`` other organisations have a comparable, active answer.

Two comparability keys, one per scope, both intentionally narrow:
* Process Risk Appetite peers share the same process template
  (``ValueStream.library_item_id``); nothing looser (e.g. never industry).
* Organisation Risk Appetite peers share the same industry classification
  (``Organization.nace_code``) — there is no process-template equivalent at
  organisation scope, so industry is the honest, narrowest comparability
  signal available at that level.
"""

from __future__ import annotations

from dataclasses import dataclass
from statistics import median

from sqlalchemy.orm import Session

from src.core.model_defs.risk_appetite_policy import (
    APPETITE_POLICY_ACTIVE,
    APPETITE_SCOPE_BUSINESS_PROCESS,
    APPETITE_SCOPE_ORGANISATION,
    RiskAppetitePolicy,
)
from src.core.model_defs.tenant_org import Organization
from src.core.model_defs.value_streams import ValueStream

MIN_PEER_COUNT = 3


@dataclass(frozen=True)
class PeerAppetiteBenchmark:
    median_level: int
    peer_count: int


def _aggregate_by_dimension(policies: list[RiskAppetitePolicy]) -> dict[str, PeerAppetiteBenchmark]:
    levels_by_dimension: dict[str, list[int]] = {}
    for policy in policies:
        for dimension, level in (policy.answers or {}).items():
            if isinstance(level, int):
                levels_by_dimension.setdefault(dimension, []).append(level)

    return {
        dimension: PeerAppetiteBenchmark(median_level=round(median(levels)), peer_count=len(levels))
        for dimension, levels in levels_by_dimension.items()
        if len(levels) >= MIN_PEER_COUNT
    }


def peer_appetite_benchmark(
    db: Session, *, library_item_id: str | None, exclude_organization_id: int
) -> dict[str, PeerAppetiteBenchmark]:
    """Per-dimension peer median + count, only for dimensions with enough peers.

    Returns an empty dict (no signal at all) when there is no process
    template to compare against, or fewer than MIN_PEER_COUNT peers have an
    active appetite for it.
    """
    if not library_item_id:
        return {}

    peer_process_ids = [
        row.id
        for row in db.query(ValueStream.id)
        .filter(
            ValueStream.library_item_id == library_item_id,
            ValueStream.organization_id != exclude_organization_id,
        )
        .all()
    ]
    if not peer_process_ids:
        return {}

    peer_policies = (
        db.query(RiskAppetitePolicy)
        .filter(
            RiskAppetitePolicy.scope == APPETITE_SCOPE_BUSINESS_PROCESS,
            RiskAppetitePolicy.status == APPETITE_POLICY_ACTIVE,
            RiskAppetitePolicy.process_id.in_(peer_process_ids),
        )
        .all()
    )
    return _aggregate_by_dimension(peer_policies)


def org_peer_appetite_benchmark(
    db: Session, *, nace_code: str | None, exclude_organization_id: int
) -> dict[str, PeerAppetiteBenchmark]:
    """Per-dimension peer median + count across other organisations' active
    Organisation Risk Appetite, comparable only by industry classification
    (``nace_code``). Empty when the organisation has no NACE code recorded
    yet, or fewer than MIN_PEER_COUNT peers share it."""
    if not nace_code:
        return {}

    peer_org_ids = [
        row.id
        for row in db.query(Organization.id)
        .filter(Organization.nace_code == nace_code, Organization.id != exclude_organization_id)
        .all()
    ]
    if not peer_org_ids:
        return {}

    peer_policies = (
        db.query(RiskAppetitePolicy)
        .filter(
            RiskAppetitePolicy.scope == APPETITE_SCOPE_ORGANISATION,
            RiskAppetitePolicy.status == APPETITE_POLICY_ACTIVE,
            RiskAppetitePolicy.organization_id.in_(peer_org_ids),
        )
        .all()
    )
    return _aggregate_by_dimension(peer_policies)

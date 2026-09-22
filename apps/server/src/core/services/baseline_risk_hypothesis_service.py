"""Baseline Risk Hypothesis generation and validation (BSP-10).

Single source of truth for how the cold-start business model draft is
generated from company context, how it is superseded on regeneration, how
pre-hypothesis organisations are backfilled, and how a validated hypothesis
is projected onto ``organizations.org_value_stream_profile``.

Contract rules (risklence-domain-decision-model):
- The hypothesis is assumption-based — provenance, confidence, and an
  explainable reason on every item; never presented as verified fact.
- A human validates; nothing is created from a hypothesis silently.
- Regeneration supersedes, it never rewrites history.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

from sqlalchemy.orm import Session

from src.core.constants.service_key_archetypes import (
    get_archetype_for_service_key,
    get_service_key_name,
)
from src.core.constants.service_model import SERVICE_TIER_BUSINESS_CRITICAL
from src.core.constants.value_stream_library import (
    VALUE_STREAM_BY_KEY,
    infer_value_streams_from_nace,
)
from src.core.model_defs.baseline_risk_hypothesis import (
    ASSUMPTION_CONFIRMED,
    ASSUMPTION_DISMISSED,
    ASSUMPTION_PROPOSED,
    HYPOTHESIS_STATUS_GENERATED,
    HYPOTHESIS_STATUS_SUPERSEDED,
    HYPOTHESIS_STATUS_UNDER_REVIEW,
    HYPOTHESIS_STATUS_VALIDATED,
    BaselineRiskHypothesis,
)
from src.core.model_defs.common import utcnow
from src.core.model_defs.value_streams import BusinessService, ValueStream
from src.core.models import Organization
from src.core.services.template_library_service import get_active_service_template

PROVENANCE_INFERRED = "inferred"
PROVENANCE_TEMPLATE = "template"
PROVENANCE_PUBLIC_ONBOARDING = "public_onboarding"
PUBLIC_ONBOARDING_HANDOFF_KEY = "public_onboarding_handoff"

_HANDOFF_CONFIDENCE_BANDS = {
    "high": "high",
    "medium_high": "medium",
    "medium": "medium",
    "medium_low": "medium",
    "low": "low",
}


def _company_context_snapshot(org: Organization) -> dict:
    """Freeze the inputs the hypothesis was generated from."""
    return {
        "nace_code": org.nace_code or "",
        "industry": org.industry or "",
        "company_size": org.company_size or "",
        "country": org.country or "",
        "required_frameworks": list(org.required_frameworks or []),
    }


def _normalize_handoff_confidence(value: object) -> str:
    if isinstance(value, str):
        return _HANDOFF_CONFIDENCE_BANDS.get(value, "medium")
    return "medium"


def create_public_onboarding_handoff_hypothesis(
    db: Session,
    org: Organization,
    *,
    baseline_snapshot: dict[str, Any] | None,
    model_version: str | None,
    generated_at: datetime | None,
    process_candidates: list[dict[str, Any]],
    source_session_id: str,
    source_draft_id: str,
) -> BaselineRiskHypothesis:
    """Persist public onboarding output as an unapproved tenant hypothesis.

    Public onboarding may propose a process model, but it cannot create a
    Business Process or establish an approved governance record. The canonical
    hypothesis preserves the source snapshot and gives the authenticated review
    flow one tenant-side record to confirm or dismiss.
    """
    public_baseline = {
        key: value
        for key, value in (baseline_snapshot or {}).items()
        if key != "_legacy"
    }
    baseline_confidence = public_baseline.get("confidence")
    confidence_band = (
        baseline_confidence.get("band")
        if isinstance(baseline_confidence, dict)
        else None
    )
    assumptions: list[dict[str, Any]] = []
    seen_keys: set[str] = set()
    for candidate in process_candidates:
        key = candidate.get("key")
        name = candidate.get("name")
        if not isinstance(key, str) or not key.strip() or not isinstance(name, str) or not name.strip():
            continue
        if key in seen_keys:
            continue
        seen_keys.add(key)
        source_confidence = candidate.get("confidence") or confidence_band
        inference_reason = candidate.get("inference_reason")
        assumptions.append(
            {
                "kind": "business_process",
                "key": key,
                "name": name.strip(),
                "parent_key": None,
                "provenance": PROVENANCE_PUBLIC_ONBOARDING,
                "confidence": _normalize_handoff_confidence(source_confidence),
                "source_confidence": source_confidence,
                "reason": (
                    inference_reason
                    if isinstance(inference_reason, str) and inference_reason.strip()
                    else "Proposed from public onboarding company context and requires authenticated review."
                ),
                "suggested_priority": candidate.get("priority"),
                "validation": ASSUMPTION_PROPOSED,
                "decided_by": None,
                "decided_at": None,
                "public_confirmation_at": candidate.get("public_confirmation_at"),
            }
        )

    company_context = _company_context_snapshot(org)
    company_context[PUBLIC_ONBOARDING_HANDOFF_KEY] = {
        "source": PROVENANCE_PUBLIC_ONBOARDING,
        "session_id": source_session_id,
        "draft_id": source_draft_id,
        "model_version": model_version,
        "generated_at": generated_at.isoformat() if generated_at else None,
        "baseline_snapshot": public_baseline,
        "baseline_confidence": baseline_confidence,
    }
    hypothesis = BaselineRiskHypothesis(
        organization_id=org.id,
        status=HYPOTHESIS_STATUS_GENERATED,
        company_context=company_context,
        assumptions=assumptions,
    )
    db.add(hypothesis)
    db.flush()
    return hypothesis


def _process_assumption(inferred) -> dict:
    return {
        "kind": "business_process",
        "key": inferred.key,
        "name": inferred.name,
        "parent_key": None,
        "provenance": PROVENANCE_INFERRED,
        "confidence": inferred.confidence,
        "reason": inferred.inference_reason,
        "suggested_priority": inferred.suggested_priority,
        "validation": ASSUMPTION_PROPOSED,
        "decided_by": None,
        "decided_at": None,
    }


def _service_assumptions(inferred) -> list[dict]:
    library_item = VALUE_STREAM_BY_KEY.get(inferred.key)
    if library_item is None:
        return []
    return [
        {
            "kind": "business_service",
            "key": service_key,
            "name": get_service_key_name(service_key),
            "parent_key": inferred.key,
            "provenance": PROVENANCE_TEMPLATE,
            "confidence": inferred.confidence,
            "reason": (
                f"Organisations running '{inferred.name}' typically depend on this "
                "capability — proposed from the process pattern, not yet observed."
            ),
            "suggested_priority": inferred.suggested_priority,
            "validation": ASSUMPTION_PROPOSED,
            "decided_by": None,
            "decided_at": None,
        }
        for service_key in library_item.core_service_keys
    ]


def get_current_hypothesis(db: Session, organization_id: int) -> BaselineRiskHypothesis | None:
    """Latest non-superseded hypothesis for the organisation."""
    return (
        db.query(BaselineRiskHypothesis)
        .filter(
            BaselineRiskHypothesis.organization_id == organization_id,
            BaselineRiskHypothesis.status != HYPOTHESIS_STATUS_SUPERSEDED,
        )
        .order_by(BaselineRiskHypothesis.generated_at.desc())
        .first()
    )


def _existing_model_keys(db: Session, organization_id: int) -> tuple[set[str], set[str]]:
    """Library keys of processes and services the org already models."""
    stream_keys = {
        key
        for (key,) in db.query(ValueStream.library_item_id)
        .filter(ValueStream.organization_id == organization_id)
        .all()
        if key
    }
    service_keys: set[str] = set()
    for template_key, library_item_id in (
        db.query(BusinessService.template_key, BusinessService.library_item_id)
        .filter(BusinessService.organization_id == organization_id)
        .all()
    ):
        if template_key:
            service_keys.add(template_key)
        if library_item_id:
            service_keys.add(library_item_id)
    return stream_keys, service_keys


def generate_baseline_hypothesis(db: Session, org: Organization) -> BaselineRiskHypothesis:
    """Generate a fresh hypothesis draft; supersede any live predecessor.

    Items the organisation already models arrive pre-confirmed — they were
    accountable decisions when created, and re-proposing them (or letting a
    partial validation drop them from the projection) would rewrite customer
    truth. The caller owns the transaction (commit).
    """
    inferred_streams = infer_value_streams_from_nace(
        nace_code=org.nace_code or "",
        company_form=(org.settings or {}).get("company_form", ""),
        company_size=org.company_size or "",
    )
    existing_stream_keys, existing_service_keys = _existing_model_keys(db, org.id)

    assumptions: list[dict] = []
    for inferred in inferred_streams:
        assumptions.append(_process_assumption(inferred))
        assumptions.extend(_service_assumptions(inferred))

    for item in assumptions:
        already_modelled = (
            item["key"] in existing_stream_keys
            if item["kind"] == "business_process"
            else item["key"] in existing_service_keys
        )
        if already_modelled:
            item["validation"] = ASSUMPTION_CONFIRMED
            item["reason"] = f"{item['reason']} Already part of your business model."

    hypothesis = BaselineRiskHypothesis(
        organization_id=org.id,
        company_context=_company_context_snapshot(org),
        assumptions=assumptions,
    )
    db.add(hypothesis)
    db.flush()

    predecessors = (
        db.query(BaselineRiskHypothesis)
        .filter(
            BaselineRiskHypothesis.organization_id == org.id,
            BaselineRiskHypothesis.status != HYPOTHESIS_STATUS_SUPERSEDED,
            BaselineRiskHypothesis.id != hypothesis.id,
        )
        .all()
    )
    for predecessor in predecessors:
        predecessor.status = HYPOTHESIS_STATUS_SUPERSEDED
        predecessor.superseded_by_id = hypothesis.id
        db.add(predecessor)

    return hypothesis


def backfill_hypothesis_from_org_profile(
    db: Session, org: Organization
) -> BaselineRiskHypothesis | None:
    """Represent a pre-hypothesis org's confirmed profile as a validated hypothesis.

    Older organisations carry confirmed streams only in
    ``org_value_stream_profile``; this records the same facts as a validated
    hypothesis (items confirmed, provenance preserved) so the refinement
    history has a starting point. No-op when the org has no confirmed profile
    or already has a hypothesis.
    """
    if get_current_hypothesis(db, org.id) is not None:
        return None
    profile = org.org_value_stream_profile or {}
    streams = profile.get("streams") or []
    if not streams:
        return None

    hypothesis = BaselineRiskHypothesis(
        organization_id=org.id,
        status=HYPOTHESIS_STATUS_VALIDATED,
        company_context=_company_context_snapshot(org),
        assumptions=[
            {
                "kind": "business_process",
                "key": item.get("key", ""),
                "name": item.get("name", ""),
                "parent_key": None,
                "provenance": item.get("source", PROVENANCE_INFERRED),
                "confidence": "medium",
                "reason": "Confirmed before hypothesis records existed — backfilled from the organisation profile.",
                "suggested_priority": item.get("priority"),
                "validation": ASSUMPTION_CONFIRMED,
                "decided_by": None,
                "decided_at": profile.get("confirmedAt"),
            }
            for item in streams
        ],
        validated_at=utcnow(),
    )
    db.add(hypothesis)
    return hypothesis


@dataclass(frozen=True)
class AssumptionDecision:
    key: str
    kind: str  # business_process | business_service
    validation: str  # confirmed | dismissed


@dataclass
class HypothesisApplyResult:
    created_process_keys: list[str] = field(default_factory=list)
    created_service_keys: list[str] = field(default_factory=list)
    linked_service_keys: list[str] = field(default_factory=list)
    already_modelled_keys: list[str] = field(default_factory=list)


def record_assumption_decisions(
    db: Session,
    hypothesis: BaselineRiskHypothesis,
    decisions: list[AssumptionDecision],
    *,
    decided_by: str,
) -> list[str]:
    """Record accountable per-item decisions; returns keys that matched nothing.

    Only ``confirmed``/``dismissed`` are human decisions; items not named in
    ``decisions`` are untouched. Re-deciding is allowed — the new decision is
    recorded with its own timestamp (history lives in the audit trail, the
    item carries the current stance).
    """
    valid_targets = {ASSUMPTION_CONFIRMED, ASSUMPTION_DISMISSED}
    decisions_by_item = {
        (d.kind, d.key): d.validation for d in decisions if d.validation in valid_targets
    }
    now_iso = utcnow().isoformat()

    unmatched = dict(decisions_by_item)
    assumptions = [dict(item) for item in (hypothesis.assumptions or [])]
    for item in assumptions:
        target = decisions_by_item.get((item.get("kind"), item.get("key")))
        if target is None:
            continue
        item["validation"] = target
        item["decided_by"] = decided_by
        item["decided_at"] = now_iso
        unmatched.pop((item.get("kind"), item.get("key")), None)

    hypothesis.assumptions = assumptions  # reassign — JSONB columns don't track mutation
    if hypothesis.status not in (HYPOTHESIS_STATUS_VALIDATED, HYPOTHESIS_STATUS_SUPERSEDED):
        hypothesis.status = HYPOTHESIS_STATUS_UNDER_REVIEW
    db.add(hypothesis)
    return [f"{kind}:{key}" for kind, key in unmatched]


def apply_validated_hypothesis(
    db: Session,
    org: Organization,
    hypothesis: BaselineRiskHypothesis,
    *,
    validated_by: str,
) -> HypothesisApplyResult:
    """The accountable creation moment: confirmed items become real records.

    Confirmed processes become ValueStreams, confirmed services become
    BusinessServices attached to their confirmed parent process — idempotently
    (existing rows are linked, never duplicated). Dismissed and still-proposed
    items create nothing. The caller owns the transaction (commit).
    """
    result = HypothesisApplyResult()
    assumptions = hypothesis.assumptions or []

    confirmed_processes = [
        item
        for item in assumptions
        if item.get("kind") == "business_process" and item.get("validation") == ASSUMPTION_CONFIRMED
    ]
    confirmed_services = [
        item
        for item in assumptions
        if item.get("kind") == "business_service" and item.get("validation") == ASSUMPTION_CONFIRMED
    ]

    stream_by_key: dict[str, ValueStream] = {}
    for item in confirmed_processes:
        key = item.get("key") or ""
        stream = (
            db.query(ValueStream)
            .filter(
                ValueStream.organization_id == org.id,
                ValueStream.library_item_id == key,
            )
            .first()
        )
        if stream is None:
            stream = ValueStream(
                organization_id=org.id,
                library_item_id=key,
                name=item.get("name") or key,
                priority=item.get("suggested_priority") or "standard",
                source=item.get("provenance") or "inferred",
            )
            db.add(stream)
            result.created_process_keys.append(key)
        else:
            result.already_modelled_keys.append(key)
        stream_by_key[key] = stream
    db.flush()

    for item in confirmed_services:
        service_key = item.get("key") or ""
        parent_key = item.get("parent_key")
        parent_stream = stream_by_key.get(parent_key) if parent_key else None

        existing = (
            db.query(BusinessService)
            .filter(
                BusinessService.organization_id == org.id,
                BusinessService.library_item_id == service_key,
            )
            .first()
        )
        if existing is not None:
            if parent_stream is not None:
                current_ids = list(existing.value_stream_ids or [])
                if parent_stream.id not in current_ids:
                    existing.value_stream_ids = current_ids + [parent_stream.id]
                    db.add(existing)
                    result.linked_service_keys.append(service_key)
                    continue
            result.already_modelled_keys.append(service_key)
            continue

        svc_template = get_active_service_template(db, service_key)
        db.add(
            BusinessService(
                organization_id=org.id,
                name=item.get("name") or get_service_key_name(service_key),
                library_item_id=service_key,
                archetype=get_archetype_for_service_key(service_key),
                template_key=service_key,
                template_version=svc_template.version if svc_template else None,
                value_stream_ids=[parent_stream.id] if parent_stream else [],
                tier=SERVICE_TIER_BUSINESS_CRITICAL,
                trading_impact="",
            )
        )
        result.created_service_keys.append(service_key)

    mark_hypothesis_validated(db, hypothesis, org, validated_by=validated_by)
    return result


def mark_hypothesis_validated(
    db: Session,
    hypothesis: BaselineRiskHypothesis,
    org: Organization,
    *,
    validated_by: str,
) -> None:
    """Record human validation and project confirmed processes onto the org profile.

    ``org_value_stream_profile`` is a projection of the validated hypothesis —
    this is the only writer.
    """
    now = utcnow()
    hypothesis.status = HYPOTHESIS_STATUS_VALIDATED
    hypothesis.validated_by = validated_by
    hypothesis.validated_at = now
    db.add(hypothesis)

    confirmed_processes = [
        item
        for item in (hypothesis.assumptions or [])
        if item.get("kind") == "business_process" and item.get("validation") == ASSUMPTION_CONFIRMED
    ]
    org.org_value_stream_profile = {
        "streams": [
            {
                "key": item.get("key"),
                "name": item.get("name"),
                "source": item.get("provenance", PROVENANCE_INFERRED),
                "priority": item.get("suggested_priority") or "standard",
            }
            for item in confirmed_processes
        ],
        "confirmedAt": now.isoformat(),
    }
    db.add(org)

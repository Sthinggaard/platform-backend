"""Template learning engine for UC-TDM-02.

Analyses SlotInstance decisions across all orgs to identify meaningful
evolution signals for ServiceTemplate slot configuration. Produces
TemplateCandidate rows which enter a governance review workflow before
becoming live template versions.

Governance class rules
----------------------
A   High confidence, auto-staged for publish without human review.
    Criteria: sample >= MIN_SAMPLE_CLASS_A AND change is strictly conservative
    (required → optional when NA rate is very high, or asset_type list is being
    narrowed to observed consensus). No structural additions.

B   Medium confidence, surfaced for human review before publish.
    Criteria: sample >= MIN_SAMPLE_CLASS_B AND consensus passes thresholds.
    Includes any single-slot required→optional or optional→required flip.

C   Low confidence or structural change (new slot proposed, group added).
    Explicit approval required. Surfaced for review but never auto-staged.

Proposed change types
---------------------
- ``make_optional``   required slot whose NA rate exceeds THRESHOLD_NA_REQUIRED
- ``make_required``   optional slot whose mapped rate exceeds THRESHOLD_MAPPED_OPTIONAL
- ``update_asset_types``  expected_asset_types does not reflect what orgs actually map
"""

from __future__ import annotations

import uuid
from collections import Counter
from datetime import datetime, timezone
from typing import Any

from sqlalchemy.orm import Session

from src.core.constants.value_stream_events import ValueStreamEvent
from src.core.models import (
    BusinessService,
    ServiceTemplate,
    SlotInstance,
    SlotTemplate,
    TemplateCandidate,
    TemplateLearningRun,
    ValueStreamSignal,
)
from src.core.services.slot_provisioning_service import is_answered_slot

# ── Thresholds ─────────────────────────────────────────────────────────────────

# Minimum number of distinct orgs with a decision for this slot before we act.
MIN_SAMPLE_CLASS_A = 20
MIN_SAMPLE_CLASS_B = 10

# If >= this fraction of decisions on a *required* slot are "not_applicable",
# propose making the slot optional.
THRESHOLD_NA_REQUIRED: float = 0.60

# If >= this fraction of decisions on an *optional* slot are "mapped",
# propose making the slot required.
THRESHOLD_MAPPED_OPTIONAL: float = 0.70

# Minimum fraction of mapped decisions that share the same asset_label prefix
# before we propose narrowing expected_asset_types.
THRESHOLD_ASSET_TYPE_CONSENSUS: float = 0.65

# Slots in these statuses *may* be an active decision — the query's coarse filter.
# `is_answered_slot` decides: an untouched slot also reads "unknown", and until
# 2026-09-13 every one of them was counted here as an org choosing "I don't know".
ACTIVE_DECISION_STATUSES = frozenset({"mapped", "not_applicable", "unknown"})
MAPPED_STATUSES = frozenset({"mapped"})
NA_STATUSES = frozenset({"not_applicable"})


# ── Internal data structures ───────────────────────────────────────────────────


class _SlotStats:
    """Aggregated stats for one (service_key, slot_id) pair."""

    def __init__(self, slot_id: str, required: bool, current_asset_types: list[str]) -> None:
        self.slot_id = slot_id
        self.required = required
        self.current_asset_types = current_asset_types
        self.total_decisions: int = 0
        self.mapped: int = 0
        self.not_applicable: int = 0
        self.unknown: int = 0
        self.asset_label_counts: Counter[str] = Counter()

    @property
    def na_rate(self) -> float:
        if self.total_decisions == 0:
            return 0.0
        return self.not_applicable / self.total_decisions

    @property
    def mapped_rate(self) -> float:
        if self.total_decisions == 0:
            return 0.0
        return self.mapped / self.total_decisions

    @property
    def unknown_rate(self) -> float:
        if self.total_decisions == 0:
            return 0.0
        return self.unknown / self.total_decisions

    def to_dict(self) -> dict[str, Any]:
        return {
            "slot_id": self.slot_id,
            "required": self.required,
            "total_decisions": self.total_decisions,
            "mapped": self.mapped,
            "not_applicable": self.not_applicable,
            "unknown": self.unknown,
            "na_rate": round(self.na_rate, 4),
            "mapped_rate": round(self.mapped_rate, 4),
            "unknown_rate": round(self.unknown_rate, 4),
            "top_asset_labels": dict(self.asset_label_counts.most_common(5)),
            "current_asset_types": self.current_asset_types,
        }


# ── Collection ─────────────────────────────────────────────────────────────────


def _collect_slot_stats(
    db: Session,
    service_key: str,
    active_template: ServiceTemplate,
    slot_templates: list[SlotTemplate],
) -> dict[str, _SlotStats]:
    """Pull all SlotInstance rows for orgs using this service_key and aggregate."""

    asset_types_by_slot = {st.slot_id: list(st.expected_asset_types or []) for st in slot_templates}
    stats: dict[str, _SlotStats] = {
        st.slot_id: _SlotStats(st.slot_id, st.required, asset_types_by_slot[st.slot_id])
        for st in slot_templates
    }

    # Join SlotInstance → BusinessService to filter by template_key.
    # Only include decisions made against the current active template version
    # (or null template_version for legacy rows without a version stamp).
    rows = (
        db.query(SlotInstance)
        .join(BusinessService, BusinessService.id == SlotInstance.service_id)
        .filter(
            BusinessService.template_key == service_key,
            SlotInstance.status.in_(ACTIVE_DECISION_STATUSES),
        )
        .all()
    )
    rows = [
        row
        for row in rows
        if is_answered_slot(
            status=row.status,
            mapping_status=row.mapping_status,
            evidence_source=row.evidence_source,
            decided_by=row.decided_by,
        )
    ]

    # Count per org so each org contributes exactly one decision per slot.
    # Keyed as (org_id, slot_id) → last status (ordered by updated_at descending
    # in the query above; SQLAlchemy returns rows unordered so we deduplicate
    # by keeping the latest updated_at per org-slot pair).
    latest: dict[tuple[int, str], SlotInstance] = {}
    for row in rows:
        key = (row.organization_id, row.slot_id)
        if key not in latest or row.updated_at > latest[key].updated_at:
            latest[key] = row

    for row in latest.values():
        slot_id = row.slot_id
        if slot_id not in stats:
            # Slot not in current template (orphan) — skip.
            continue
        s = stats[slot_id]
        s.total_decisions += 1
        if row.status in MAPPED_STATUSES:
            s.mapped += 1
            if row.asset_label:
                s.asset_label_counts[row.asset_label] += 1
        elif row.status in NA_STATUSES:
            s.not_applicable += 1
        else:
            s.unknown += 1

    return stats


# ── Candidate generation ───────────────────────────────────────────────────────


def _classify(changes: list[dict], sample_size: int) -> str:
    """Return governance class A, B, or C for a proposed change set."""
    if sample_size < MIN_SAMPLE_CLASS_B:
        return "C"

    # Any structural change (new slot, group) → C.
    if any(c["type"] in ("add_slot", "add_group") for c in changes):
        return "C"

    # Only conservative loosening (required→optional) with large sample → A.
    if sample_size >= MIN_SAMPLE_CLASS_A:
        if all(c["type"] == "make_optional" for c in changes):
            return "A"

    return "B"


def _propose_changes(
    stats: dict[str, _SlotStats],
) -> list[dict[str, Any]]:
    """Derive proposed slot-level changes from aggregated stats."""
    changes: list[dict[str, Any]] = []

    for slot_id, s in stats.items():
        if s.total_decisions == 0:
            continue

        # Required slot with very high N/A rate → propose optional.
        if s.required and s.na_rate >= THRESHOLD_NA_REQUIRED:
            changes.append(
                {
                    "type": "make_optional",
                    "slot_id": slot_id,
                    "rationale": (
                        f"{s.not_applicable}/{s.total_decisions} orgs ({s.na_rate:.0%}) "
                        "marked this required slot as not applicable."
                    ),
                    "evidence": {
                        "na_rate": s.na_rate,
                        "total_decisions": s.total_decisions,
                    },
                }
            )

        # Optional slot with very high mapped rate → propose required.
        elif not s.required and s.mapped_rate >= THRESHOLD_MAPPED_OPTIONAL:
            changes.append(
                {
                    "type": "make_required",
                    "slot_id": slot_id,
                    "rationale": (
                        f"{s.mapped}/{s.total_decisions} orgs ({s.mapped_rate:.0%}) "
                        "consistently map this optional slot."
                    ),
                    "evidence": {
                        "mapped_rate": s.mapped_rate,
                        "total_decisions": s.total_decisions,
                    },
                }
            )

        # Consensus on asset types diverges from template definition.
        if s.mapped >= MIN_SAMPLE_CLASS_B and s.asset_label_counts:
            total_mapped = s.mapped
            top_label, top_count = s.asset_label_counts.most_common(1)[0]
            consensus = top_count / total_mapped
            if (
                consensus >= THRESHOLD_ASSET_TYPE_CONSENSUS
                and top_label not in s.current_asset_types
            ):
                changes.append(
                    {
                        "type": "update_asset_types",
                        "slot_id": slot_id,
                        "rationale": (
                            f"{top_count}/{total_mapped} mapped decisions ({consensus:.0%}) "
                            f"use '{top_label}', which is not in the current expected_asset_types."
                        ),
                        "evidence": {
                            "top_label": top_label,
                            "consensus_rate": consensus,
                            "current_asset_types": s.current_asset_types,
                        },
                        "proposed_asset_types": s.current_asset_types + [top_label],
                    }
                )

    return changes


def _apply_changes_to_new_template(
    db: Session,
    active_template: ServiceTemplate,
    slot_templates: list[SlotTemplate],
    changes: list[dict],
    new_version: int,
) -> ServiceTemplate:
    """Create a new ServiceTemplate version with the proposed changes applied."""
    new_template = ServiceTemplate(
        id=str(uuid.uuid4()),
        service_key=active_template.service_key,
        service_name=active_template.service_name,
        archetype=active_template.archetype,
        version=new_version,
        status="published",
        is_active=False,  # Not live until governance approves.
        capability_groups=active_template.capability_groups,
        seeded_from=active_template.seeded_from,
    )
    db.add(new_template)
    db.flush()

    changes_by_slot = {c["slot_id"]: c for c in changes if "slot_id" in c}

    for st in slot_templates:
        change = changes_by_slot.get(st.slot_id)
        new_required = st.required
        new_asset_types = list(st.expected_asset_types or [])

        if change:
            if change["type"] == "make_optional":
                new_required = False
            elif change["type"] == "make_required":
                new_required = True
            elif change["type"] == "update_asset_types":
                new_asset_types = change.get("proposed_asset_types", new_asset_types)

        from src.core.models import SlotTemplate as SlotTemplateModel

        db.add(
            SlotTemplateModel(
                id=str(uuid.uuid4()),
                service_template_id=new_template.id,
                slot_id=st.slot_id,
                label=st.label,
                purpose=st.purpose,
                expected_asset_types=new_asset_types,
                required=new_required,
                capability_group_key=st.capability_group_key,
                display_order=st.display_order,
            )
        )

    return new_template


# ── Run orchestration ──────────────────────────────────────────────────────────


def run_learning_analysis(
    db: Session,
    service_keys: list[str] | None = None,
    triggered_by: str = "manual",
) -> TemplateLearningRun:
    """Analyse slot mapping patterns and produce TemplateCandidate rows.

    Args:
        db:             Database session.
        service_keys:   Restrict analysis to these service keys. None = all keys
                        that have at least one SlotInstance row.
        triggered_by:   'manual' or 'scheduled'.

    Returns:
        The completed TemplateLearningRun record.
    """
    run = TemplateLearningRun(
        id=str(uuid.uuid4()),
        status="running",
        triggered_by=triggered_by,
        started_at=datetime.now(timezone.utc),
    )
    db.add(run)
    db.commit()

    try:
        if service_keys is None:
            service_keys = _discover_service_keys(db)

        candidates_generated = 0
        candidates_auto_staged = 0
        run_summary: dict[str, Any] = {"per_service": {}}

        for service_key in service_keys:
            result = _analyse_service_key(db, run.id, service_key)
            run_summary["per_service"][service_key] = result

            if result.get("candidate_created"):
                candidates_generated += 1
                if result.get("governance_class") == "A":
                    candidates_auto_staged += 1

        run.status = "completed"
        run.service_keys_analysed = service_keys
        run.candidates_generated = candidates_generated
        run.candidates_auto_staged = candidates_auto_staged
        run.summary = run_summary
        run.finished_at = datetime.now(timezone.utc)
        db.commit()

    except Exception as exc:
        run.status = "failed"
        run.error = str(exc)
        run.finished_at = datetime.now(timezone.utc)
        db.commit()
        raise

    return run


def _discover_service_keys(db: Session) -> list[str]:
    """Return service keys that have at least one SlotInstance row."""
    rows = (
        db.query(BusinessService.template_key)
        .join(SlotInstance, SlotInstance.service_id == BusinessService.id)
        .filter(BusinessService.template_key.isnot(None))
        .distinct()
        .all()
    )
    return [r[0] for r in rows if r[0]]


def _analyse_service_key(
    db: Session,
    run_id: str,
    service_key: str,
) -> dict[str, Any]:
    """Analyse one service key and create a TemplateCandidate if warranted."""
    from src.core.services.template_library_service import (
        get_active_service_template,
        list_slot_templates_for_service,
    )

    active_template = get_active_service_template(db, service_key)
    if active_template is None:
        return {"skipped": True, "reason": "no_active_template"}

    slot_templates = list_slot_templates_for_service(db, active_template.id)
    if not slot_templates:
        return {"skipped": True, "reason": "no_slot_templates"}

    stats = _collect_slot_stats(db, service_key, active_template, slot_templates)
    total_sample = max((s.total_decisions for s in stats.values()), default=0)

    if total_sample < MIN_SAMPLE_CLASS_B:
        return {
            "skipped": True,
            "reason": "insufficient_sample",
            "total_decisions": total_sample,
        }

    changes = _propose_changes(stats)
    if not changes:
        return {
            "candidate_created": False,
            "total_decisions": total_sample,
            "reason": "no_changes_warranted",
        }

    governance_class = _classify(changes, total_sample)
    new_version = active_template.version + 1

    # Check for an existing pending candidate for this service key at this version.
    existing = (
        db.query(TemplateCandidate)
        .filter(
            TemplateCandidate.service_key == service_key,
            TemplateCandidate.candidate_version == new_version,
            TemplateCandidate.status.in_(["pending", "auto_staged"]),
        )
        .first()
    )
    if existing:
        return {
            "candidate_created": False,
            "reason": "pending_candidate_already_exists",
            "candidate_id": existing.id,
        }

    candidate_status = "auto_staged" if governance_class == "A" else "pending"
    new_template = _apply_changes_to_new_template(
        db, active_template, slot_templates, changes, new_version
    )

    candidate = TemplateCandidate(
        id=str(uuid.uuid4()),
        run_id=run_id,
        service_key=service_key,
        current_version=active_template.version,
        candidate_version=new_version,
        governance_class=governance_class,
        status=candidate_status,
        analysis={
            "total_sample": total_sample,
            "slot_stats": {sid: s.to_dict() for sid, s in stats.items()},
        },
        proposed_changes=changes,
        published_template_id=new_template.id,
        created_at=datetime.now(timezone.utc),
        updated_at=datetime.now(timezone.utc),
    )
    db.add(candidate)
    db.commit()

    # Emit training signal (no org_id / user_id for platform-level events).
    db.add(
        ValueStreamSignal(
            organization_id=0,
            user_id=0,
            event=ValueStreamEvent.TEMPLATE_CANDIDATE_GENERATED,
            stream_key=service_key,
            payload={
                "candidate_id": candidate.id,
                "governance_class": governance_class,
                "changes": len(changes),
                "new_version": new_version,
            },
        )
    )
    db.commit()

    return {
        "candidate_created": True,
        "candidate_id": candidate.id,
        "governance_class": governance_class,
        "candidate_version": new_version,
        "changes": len(changes),
        "total_decisions": total_sample,
    }


# ── Publish ────────────────────────────────────────────────────────────────────


def publish_candidate(
    db: Session,
    candidate: TemplateCandidate,
    reviewed_by: str,
    review_note: str | None = None,
) -> ServiceTemplate:
    """Approve and publish a TemplateCandidate as the new active ServiceTemplate version.

    Marks the previous active template as inactive, activates the candidate's
    draft template, updates the candidate status to 'published', and emits a
    TEMPLATE_VERSION_PUBLISHED signal.
    """
    # Deactivate the current active template for this service key.
    db.query(ServiceTemplate).filter(
        ServiceTemplate.service_key == candidate.service_key,
        ServiceTemplate.is_active.is_(True),
    ).update({"is_active": False, "updated_at": datetime.now(timezone.utc)})

    # Activate the new version.
    new_template = (
        db.query(ServiceTemplate)
        .filter(ServiceTemplate.id == candidate.published_template_id)
        .one()
    )
    new_template.is_active = True
    new_template.updated_at = datetime.now(timezone.utc)

    # Update candidate.
    candidate.status = "published"
    candidate.reviewed_by = reviewed_by
    candidate.review_note = review_note
    candidate.updated_at = datetime.now(timezone.utc)

    # Flag orgs on the old version as having an upgrade available.
    db.query(BusinessService).filter(
        BusinessService.template_key == candidate.service_key,
        BusinessService.template_version == candidate.current_version,
    ).update({"updated_at": datetime.now(timezone.utc)})

    db.add(
        ValueStreamSignal(
            organization_id=0,
            user_id=0,
            event=ValueStreamEvent.TEMPLATE_VERSION_PUBLISHED,
            stream_key=candidate.service_key,
            payload={
                "candidate_id": candidate.id,
                "new_version": candidate.candidate_version,
                "previous_version": candidate.current_version,
                "reviewed_by": reviewed_by,
            },
        )
    )
    db.commit()

    return new_template


def reject_candidate(
    db: Session,
    candidate: TemplateCandidate,
    reviewed_by: str,
    review_note: str | None = None,
) -> None:
    """Reject a TemplateCandidate. The draft ServiceTemplate is marked inactive."""
    if candidate.published_template_id:
        db.query(ServiceTemplate).filter(
            ServiceTemplate.id == candidate.published_template_id
        ).update(
            {"is_active": False, "status": "rejected", "updated_at": datetime.now(timezone.utc)}
        )

    candidate.status = "rejected"
    candidate.reviewed_by = reviewed_by
    candidate.review_note = review_note
    candidate.updated_at = datetime.now(timezone.utc)
    db.commit()


def get_upgrades_for_org(db: Session, organization_id: int) -> list[dict[str, Any]]:
    """Return services in this org that have a newer active template version available.

    Called from the per-org API to power the "Upgrade available" prompt on the
    process detail view.
    """
    services = (
        db.query(BusinessService)
        .filter(
            BusinessService.organization_id == organization_id,
            BusinessService.template_key.isnot(None),
            BusinessService.template_version.isnot(None),
        )
        .all()
    )

    upgrades: list[dict[str, Any]] = []
    # Cache latest active version per service_key within this call.
    latest_cache: dict[str, int] = {}

    for svc in services:
        key = svc.template_key
        current_version = svc.template_version
        # The query already excludes both nulls; this says so to the type
        # checker instead of asserting it, and skips rather than crashes if the
        # filter above is ever loosened.
        if key is None or current_version is None:
            continue
        if key not in latest_cache:
            latest = (
                db.query(ServiceTemplate.version)
                .filter(
                    ServiceTemplate.service_key == key,
                    ServiceTemplate.is_active.is_(True),
                )
                .order_by(ServiceTemplate.version.desc())
                .scalar()
            )
            latest_cache[key] = latest or 1

        if current_version < latest_cache[key]:
            upgrades.append(
                {
                    "service_id": svc.id,
                    "service_name": svc.name,
                    "service_key": key,
                    "current_version": current_version,
                    "latest_version": latest_cache[key],
                }
            )

    return upgrades

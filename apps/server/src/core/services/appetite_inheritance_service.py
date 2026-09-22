"""Process -> Service Risk Appetite inheritance (ONB-GOV-11).

Per the 2026-07-14 governance pivot: a Business Service inherits its parent
Business Process's approved Risk Appetite by default and only diverges where
a Service Owner's reassessment has been approved by the Process Owner — never
a blank re-ask of the same six-category questionnaire.

    Process Risk Appetite (approved)
    -> Business Service inherits it, category by category
    -> Service Owner requests a reassessment only where it materially differs
    -> Process Owner approves or rejects the reassessment
    -> approved reassessments are never silently overwritten

This module is the single source of truth for that merge rule, mirroring
`bia_inheritance_service.py`'s exact pattern so the two inheritance chains
(BIA and appetite) can never disagree about what "the categories in force"
means for a given service.
"""

from __future__ import annotations

APPETITE_DIMENSION_KEYS: frozenset[str] = frozenset(
    {"dataLoss", "downtime", "regulatory", "financial", "reputational", "security"}
)


def effective_service_appetite(
    reassessed_answers: dict | None, process_answers: dict | None
) -> dict | None:
    """The appetite actually in force for a service.

    Approved reassessments (if any) override the Process Risk Appetite
    category by category. Never fabricates a value that neither level
    actually set.
    """
    if not reassessed_answers:
        return dict(process_answers) if process_answers else None
    if not process_answers:
        return dict(reassessed_answers)
    merged = dict(process_answers)
    merged.update(reassessed_answers)
    return merged


def appetite_category_provenance(reassessed_answers: dict | None) -> dict[str, str]:
    """Per-category provenance: 'reassessed' where the service has an approved
    override, 'inherited' where it still relies on the Process Risk Appetite."""
    reassessed_keys = set((reassessed_answers or {}).keys())
    return {
        category: "reassessed" if category in reassessed_keys else "inherited"
        for category in APPETITE_DIMENSION_KEYS
    }


def service_appetite_status(reassessed_answers: dict | None, has_pending_reassessment: bool) -> str:
    """One of 'inherited' | 'reassessed' | 'pending_reassessment' (ONB-GOV-11)."""
    if has_pending_reassessment:
        return "pending_reassessment"
    if reassessed_answers:
        return "reassessed"
    return "inherited"

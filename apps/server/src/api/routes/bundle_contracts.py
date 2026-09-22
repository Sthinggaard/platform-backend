from __future__ import annotations

from typing import Annotated, Any, Literal

from pydantic import BaseModel, BeforeValidator, Field, model_validator

from src.api.schemas.timestamps import UtcTimestamp
from src.core.services.asset_context_service import normalise_asset_reference
from src.core.services.slot_provisioning_service import is_answered_slot

#: An asset link as a request carries it, turned into the one stored spelling
#: before any route sees it (#363). The tenant sends ``"asset-92"``, but an
#: accepted scanner suggestion carried an asset's own id (``"92"``) until the
#: suggestion service was fixed, and any client can still send either;
#: normalising at the contract means no route can store the second by forgetting
#: to. An empty or unusable value becomes ``None`` — refused where the field is
#: required.
AssetReferenceIn = Annotated[str, BeforeValidator(normalise_asset_reference)]
OptionalAssetReferenceIn = Annotated[str | None, BeforeValidator(normalise_asset_reference)]


class TemplatePatternOptionOut(BaseModel):
    template_key: str
    label: str
    pattern_key: str | None = None


class DependencyNodeOut(BaseModel):
    id: str
    label: str
    linked_asset_ids: list[str]
    source: str
    validation_status: str
    fallback_status: str | None
    spof: bool | None
    confidence: float | None
    template_key: str | None
    pattern_key: str | None = None
    critical_for_business: bool | None
    business_consequence: str | None
    impact_type: str | None
    business_impact_level: str | None
    recovery_dependent: bool | None
    deferred_asset_mapping: bool
    #: #460 — the slot record this node is composed from. `None` on a published
    #: snapshot node written before #460.
    slot_id: str | None = None
    #: #460 (Søren, 2026-09-15) — the decision's slot has left the service's active
    #: template. Kept live, flagged "no longer in the template — review" (#472).
    template_orphaned: bool = False


class DependencyGroupOut(BaseModel):
    key: str
    label: str
    question: str
    description: str
    required: bool
    template_nodes: list[TemplatePatternOptionOut]
    nodes: list[DependencyNodeOut]
    rejected: bool | None = None


class DependencyBundleResponse(BaseModel):
    id: str
    service_id: str
    status: str
    mode: str
    lifecycle_state: str
    groups: list[DependencyGroupOut]
    validation_snapshot: dict[str, Any] | None = None
    acknowledged_warning_ids: list[str] = Field(default_factory=list)
    created_at: UtcTimestamp
    updated_at: UtcTimestamp
    latest_version_id: str | None = None
    latest_version_number: int | None = None


class BundleVersionResponse(BaseModel):
    id: str
    bundle_id: str
    service_id: str
    version_number: int
    status: str
    lifecycle_state: str
    groups_snapshot: list[DependencyGroupOut]
    validation_snapshot: dict[str, Any] | None = None
    acknowledged_warning_ids: list[str] = Field(default_factory=list)
    published_at: UtcTimestamp
    created_at: UtcTimestamp


class LoadTemplateResponse(BaseModel):
    bundle: DependencyBundleResponse
    message: str


class BundleActionRequest(BaseModel):
    action: Literal[
        "add_pattern_node",
        "remove_node",
        "assign_asset",
        "unassign_asset",
        "classify_impact",
        "mark_spof",
        "mark_fallback",
        "mark_recovery_dependency",
        "defer_asset_mapping",
        "set_uncertain",
        "reject_group",
    ]
    group_key: str = Field(..., description="Which dependency group this targets")
    node_id: str | None = Field(default=None, description="Target node (required for most actions)")
    payload: dict[str, Any] = Field(default_factory=dict, description="Action-specific data")
    reason: str | None = Field(default=None, description="Optional reason (shown in audit log)")


class ValidationFindingOut(BaseModel):
    id: str
    severity: Literal["BLOCKER", "WARNING", "INFO"]
    dependency_id: str | None = None
    dependency_label: str | None = None
    group_key: str | None = None
    group_label: str | None = None
    message: str
    recommendation: str
    requires_acknowledgement: bool


class ValidateBundleResponse(BaseModel):
    valid: bool
    lifecycle_state: str
    errors: list[str]
    warnings: list[str]
    findings: list[ValidationFindingOut] = Field(default_factory=list)
    warning_ids: list[str] = Field(default_factory=list)
    acknowledged_warning_ids: list[str] = Field(default_factory=list)
    requires_warning_acceptance: bool


class ValidateBundleRequest(BaseModel):
    accept_warnings: bool = Field(default=False, alias="acceptWarnings")

    model_config = {"populate_by_name": True}


class ArchetypeSuggestResponse(BaseModel):
    suggested_archetype: str
    confidence: str


class SetArchetypeRequest(BaseModel):
    archetype: str = Field(..., description="Archetype key to assign to this service")
    reason: str | None = Field(default=None, description="Why the archetype was changed")


class SlotMappingDecision(BaseModel):
    group_key: str
    decision: Literal["mapped", "not_applicable", "unknown"]
    asset_id: OptionalAssetReferenceIn = None
    asset_label: str | None = None


class PublishSlotMappingsRequest(BaseModel):
    mappings: list[SlotMappingDecision]


class SlotPublishFinding(BaseModel):
    group_key: str
    severity: Literal["blocker", "warning"]
    message: str


class PublishSlotMappingsResponse(BaseModel):
    bundle_id: str
    lifecycle_state: str
    mapped_count: int
    not_applicable_count: int
    unknown_count: int
    coverage_score: int
    findings: list[SlotPublishFinding]


class SlotInstanceOut(BaseModel):
    slot_id: str
    group_key: str
    dependency_category: str | None = None
    status: Literal["mapped", "not_applicable", "unknown", "needs_review"]
    asset_id: str | None = None
    asset_label: str | None = None
    template_version: int | None = None
    mapping_status: Literal["suggested", "approved", "rejected", "needs_review"] = "approved"
    mapping_confidence: float | None = None
    evidence_source: str | None = None
    mapping_reason: str | None = None
    mapping_reason_code: str | None = None
    provenance: str | None = None
    decided_by: str | None = None
    #: #460 (Søren, 2026-09-15) — this decision's slot has left the service's active
    #: template. Only ever set on `ServiceSlotsResponse.orphaned_slots`.
    template_orphaned: bool = False
    #: Whether a person has answered this slot. Always derived below, never taken
    #: from input: ``status`` alone cannot say, because an untouched slot and a
    #: person's "I don't know" both read ``"unknown"``.
    answered: bool = False

    @model_validator(mode="after")
    def _derive_answered(self) -> SlotInstanceOut:
        self.answered = is_answered_slot(
            status=self.status,
            mapping_status=self.mapping_status,
            evidence_source=self.evidence_source,
            decided_by=self.decided_by,
        )
        return self


class DecideSlotMappingRequest(BaseModel):
    """One owner decision about one slot.

    Deliberately **not** `PublishSlotMappingsRequest` with a single element.
    Publishing marks the whole bundle `bundle_published` and records a coverage
    score computed over *the request body*, so a batch of one would report the
    service fully published and 100% covered after the reader's first answer.
    Deciding one slot is a different act from publishing a service, and the two
    now have different routes.
    """

    decision: Literal["mapped", "not_applicable", "unknown"]
    asset_id: OptionalAssetReferenceIn = None
    asset_label: str | None = None


class DecideSlotMappingResponse(BaseModel):
    slot: SlotInstanceOut
    #: Non-blocking observations about the decision just recorded — today only
    #: the shared-dependency warning. A list so a second kind can be added
    #: without changing the shape callers already read.
    findings: list[SlotPublishFinding] = []


class RejectSlotMappingRequest(BaseModel):
    reason_code: str
    reason: str | None = None


class SupersedeSlotMappingRequest(BaseModel):
    asset_id: AssetReferenceIn
    asset_label: str | None = None
    reason_code: str
    reason: str | None = None


class RejectionReasonOut(BaseModel):
    """One reason a reviewer may give for refusing a suggestion.

    Served rather than restated client-side. The tenant already carries
    hand-maintained copies of two server vocabularies, and each one is a place
    the two can drift; adding a third would repeat that on purpose. Offering a
    new reason should need no tenant change.
    """

    code: str
    label: str
    explanation: str


class ServiceSlotsResponse(BaseModel):
    service_id: str
    slots: list[SlotInstanceOut]
    #: What refusing a suggestion may be attributed to, in the order to offer
    #: them. CA-09A.5 — every rejection used to be recorded as the same code
    #: with the same sentence, so nothing downstream could tell them apart.
    rejection_reasons: list[RejectionReasonOut] = []
    #: #460 (Søren, 2026-09-15) — answered decisions whose slot has left the service's
    #: active template, each flagged `template_orphaned`. **Read-only and kept apart
    #: from `slots` on purpose:** the slide-out sends one answer to every row in
    #: `slots` for a group, so an orphan listed there would have a person's decision
    #: overwritten by an answer given for something else. Folding them in is #472.
    orphaned_slots: list[SlotInstanceOut] = []


# ─── BSP-05 — intelligence-engine slot-mapping suggestions ───────────────────


class SlotSuggestionOut(BaseModel):
    slot_id: str
    group_key: str
    slot_label: str
    asset_id: str
    asset_label: str
    confidence: float
    reason: str


class ParkedSlotOut(BaseModel):
    """A slot the engine declined to suggest for, because a person already ruled
    out the artefact it would have offered."""

    slot_id: str
    group_key: str


class ServiceSlotSuggestionsResponse(BaseModel):
    service_id: str
    template_version: int | None = None
    suggestions: list[SlotSuggestionOut]
    skipped_human_decided: list[str]
    unmatched_slot_ids: list[str]
    #: CA-09A.6 — slots parked because a person already ruled out the artefact
    #: the engine would have proposed. Never part of the active, approved set:
    #: a parked slot carries no asset and is not mapped. Sent so the surface can
    #: show it under its own chip rather than leave a reader wondering why a
    #: slot went quiet.
    parked_by_refutation: list[ParkedSlotOut] = []


# ─── EUC-03 — service bundle runtime view ────────────────────────────────────


class BundleSlotRuntime(BaseModel):
    slot_id: str
    dependency_category: str | None = None
    label: str
    status: Literal["mapped", "not_applicable", "unknown", "needs_review"]
    asset_id: str | None = None
    asset_label: str | None = None
    spof: bool | None = None
    fallback_status: str | None = None
    #: #460 (Søren, 2026-09-15) — a live decision whose slot has left the service's active
    #: template. Listed and counted, flagged for review (#472).
    template_orphaned: bool = False


class BundleGroupRuntime(BaseModel):
    key: str
    label: str
    description: str
    required: bool
    status: Literal["healthy", "attention_needed", "at_risk", "unverified"]
    slots: list[BundleSlotRuntime]
    mapped_count: int
    total_slots: int


class ServiceBundleRuntimeResponse(BaseModel):
    service_id: str
    service_name: str
    tier: str
    archetype: str | None
    resilience_score: int | None
    financial_exposure: str | None
    value_stream_ids: list[str]
    bundle_id: str | None
    lifecycle_state: str
    coverage_score: int | None
    groups: list[BundleGroupRuntime]


# ─── EUC-04 — dependency group asset drill ────────────────────────────────────


class DependencyAssetDetail(BaseModel):
    #: The slot this row IS — one entry per slot, not per asset.
    #:
    #: ⚠️ Added 2026-09-04. Without it a row had no identity of its own: two
    #: slots in one group can hold the same asset (a shared dependency, or a
    #: SPOF reached two ways) and every unmapped slot carries ``asset_id=""``,
    #: so a client keying rows on the asset saw React drop or duplicate them.
    #: The endpoint had this value all along and dropped it.
    slot_id: str
    dependency_category: str | None = None
    asset_id: str
    asset_label: str
    status: Literal["mapped", "not_applicable", "unknown", "needs_review"]
    display_name: str | None
    asset_type: str | None
    level: int | None
    is_spof: bool
    risk_score: float
    findings_count: int
    shared_service_count: int
    crown_jewel_candidate: bool
    #: #460 (Søren, 2026-09-15) — a live decision whose slot has left the service's active
    #: template. Listed and counted, flagged for review (#472).
    template_orphaned: bool = False


class DependencyGroupDrillResponse(BaseModel):
    service_id: str
    group_key: str
    label: str
    description: str
    required: bool
    status: Literal["healthy", "attention_needed", "at_risk", "unverified"]
    assets: list[DependencyAssetDetail]
    mapped_count: int
    total_slots: int

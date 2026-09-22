"""API contract for the prepared Business Process workspace projection."""

from pydantic import BaseModel, Field

from src.core.constants.process_workspace_enums import (
    ProcessWorkspaceDependencySlotStatus,
    ProcessWorkspaceReadinessAction,
    ProcessWorkspaceReadinessReason,
    ProcessWorkspaceReadinessState,
)


class ProcessWorkspaceDependencySlotResponse(BaseModel):
    slot_id: str
    label: str | None = None
    group_key: str | None = None
    status: ProcessWorkspaceDependencySlotStatus
    linked_asset_ids: list[str] = Field(default_factory=list)
    deferred_asset_mapping: bool = False
    evidence_gap: bool = False
    # Tri-state: `null` means nobody has answered whether this dependency is a
    # single point of failure. An unanswered question is not a "no".
    single_point_of_failure: bool | None = None
    # The grounds for the claim — linked assets independently flagged as single
    # points of failure. Stated as an observation, never as a score.
    spof_asset_ids: list[str] = Field(default_factory=list)
    # Other Business Processes that depend on the same assets: what else goes
    # down with this one.
    shared_with_process_ids: list[str] = Field(default_factory=list)
    # #460 (Søren, 2026-09-15) — this decision's slot has left the service's active
    # template. Kept live, flagged "no longer in the template — review" (#472).
    template_orphaned: bool = False


class ProcessWorkspaceDependencyResponse(BaseModel):
    bundle_id: str | None = None
    lifecycle_state: str | None = None
    #: Whether anyone has begun mapping this service's dependencies. Readers
    #: used to infer it from ``bundle_id is None``, which stopped meaning that
    #: once deciding one slot began creating the bundle row (#433).
    dependency_mapping_started: bool = False
    slots: list[ProcessWorkspaceDependencySlotResponse] = Field(default_factory=list)
    mapping_gap_count: int = 0
    evidence_gap_count: int = 0
    spof_slot_count: int = 0


class ProcessWorkspaceServiceResponse(BaseModel):
    service_id: str
    service_name: str
    tier: str
    library_item_id: str | None = None
    owner_user_id: int | None = None
    bia_complete: bool
    appetite_complete: bool
    linked_asset_ids: list[str] = Field(default_factory=list)
    dependency: ProcessWorkspaceDependencyResponse


class ProcessWorkspaceReadinessResponse(BaseModel):
    process_id: str
    state: ProcessWorkspaceReadinessState
    release_allowed: bool
    reasons: list[ProcessWorkspaceReadinessReason]
    next_actions: list[ProcessWorkspaceReadinessAction]
    service_count: int
    dependency_mapping_gap_count: int
    evidence_gap_count: int
    process_name: str
    outcome_statement: str | None = None
    process_source: str
    services: list[ProcessWorkspaceServiceResponse] = Field(default_factory=list)

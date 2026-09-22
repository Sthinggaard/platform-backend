"""Process access resolution (dashboard epic, slice 5).

Turns the org admin's configuration (canonical mandate role assignments +
visibility policy) into per-process access answers for one viewer:

- **visible** — may this person see the process row at all?
- **detail** — overview (stakeholder rollup) or full (owner-level setup)?
- **eligibility** — may they act, or view only?
- **mandate holder** — who is accountable for decisions on this process?

Contract (risklence-org-access-model):
- Mandate follows canonical role, never a job title or a generic global role.
- Process mandate resolves from a scoped Business Process Owner binding. The
  legacy ``BusinessService.owner_user_id`` field is used only as a documented
  compatibility fallback until each process has an explicit binding.
- Setup visibility defaults to owner + manager. Reporting lines must resolve
  from the identity provider at runtime — no runtime source is wired yet, so
  the manager seam returns nothing and says so, rather than inventing a chart.
- Org-wide visibility and full detail are two independent policy settings.
- **Unconfigured organisations**: when the admin has configured neither
  assignments nor a policy, enforcement would brick every screen. Access
  falls back to organisation-wide overview visibility with eligibility
  ``not_evaluated``, and the response says the model is unconfigured — a
  transparent interim, not a silent default.
"""

from __future__ import annotations

from dataclasses import dataclass

from sqlalchemy.orm import Session

from src.core.constants.org_access_enums import CanonicalMandateRole, MandateAssignmentSubjectType
from src.core.model_defs.org_access import (
    OrgMandateRoleAssignment,
    OrgMandateScopeBinding,
    OrgVisibilityPolicy,
)
from src.core.services.service_accountability_service import resolve_scoped_mandate_holders

ACCESS_DETAIL_OVERVIEW = "overview"
ACCESS_DETAIL_FULL = "full"

ELIGIBILITY_CAN_ACT = "can_act"
ELIGIBILITY_VIEW_ONLY = "view_only"
ELIGIBILITY_NOT_EVALUATED = "not_evaluated"


@dataclass(frozen=True)
class MandateHolder:
    user_id: int
    name: str
    canonical_role: str


@dataclass(frozen=True)
class ProcessAccess:
    visible: bool
    detail: str  # overview | full
    eligibility: str  # can_act | view_only | not_evaluated
    mandate_holder: MandateHolder | None


@dataclass(frozen=True)
class OrgAccessResolution:
    configured: bool
    access_by_process_id: dict[str, ProcessAccess]


def resolve_reporting_line_manager_of(_user_id: int) -> list[int]:
    """Reports of a user, resolved from the identity provider at runtime.

    No AAD/Google runtime lookup is wired yet; until it is, nobody gains
    manager visibility — an honest gap, never an invented org chart.
    """
    return []


def _display_name(user) -> str:
    first = (getattr(user, "first_name", None) or "").strip()
    last = (getattr(user, "last_name", None) or "").strip()
    if first or last:
        return f"{first} {last}".strip()
    return getattr(user, "email", None) or f"user-{user.id}"


def resolve_org_access(
    db: Session,
    *,
    organization_id: int,
    viewer_user_id: int | None,
    processes: list[object],
    services: list[object],
) -> OrgAccessResolution:
    """Resolve visibility, detail, eligibility, and mandate per process."""
    from src.core.models import User  # local import to avoid module cycles

    assignments: list[OrgMandateRoleAssignment] = (
        db.query(OrgMandateRoleAssignment)
        .filter(OrgMandateRoleAssignment.organization_id == organization_id)
        .all()
    )
    policy: OrgVisibilityPolicy | None = (
        db.query(OrgVisibilityPolicy)
        .filter(OrgVisibilityPolicy.organization_id == organization_id)
        .first()
    )
    scope_bindings: list[OrgMandateScopeBinding] = (
        db.query(OrgMandateScopeBinding)
        .filter(OrgMandateScopeBinding.organization_id == organization_id)
        .all()
    )
    configured = bool(assignments) or bool(scope_bindings) or policy is not None

    users_by_id = {
        user.id: user
        for user in db.query(User).filter(User.organization_id == organization_id).all()
    }

    # Canonical roles per user (group assignments need the identity-provider
    # runtime, same seam as reporting lines — not resolved here).
    roles_by_user: dict[int, set[str]] = {}
    for assignment in assignments:
        if assignment.subject_type == MandateAssignmentSubjectType.USER.value and assignment.user_id:
            roles_by_user.setdefault(assignment.user_id, set()).add(assignment.canonical_role)

    # "Who holds this scoped mandate" is one piece of knowledge, and it is now
    # answered in one place — this function and service accountability were
    # deriving it separately from the same two tables (AGENTS.md, DRY).
    holders = resolve_scoped_mandate_holders(db, organization_id=organization_id)
    process_owners_by_process = holders.process_owners
    service_owners_by_id = holders.service_owners

    scoped_service_owners_by_process: dict[str, set[int]] = {}
    legacy_service_owners_by_process: dict[str, set[int]] = {}
    for service in services:
        if getattr(service, "archived_at", None) is not None:
            continue
        # A set: the schema allows one scoped service owner, and the shared
        # lookup refuses to collapse more than one into a guess rather than
        # keeping whichever row it read last.
        scoped_owner_ids = service_owners_by_id.get(service.id, set())
        legacy_owner_id = getattr(service, "owner_user_id", None)
        for process_id in service.value_stream_ids or []:
            if scoped_owner_ids:
                scoped_service_owners_by_process.setdefault(process_id, set()).update(scoped_owner_ids)
            if legacy_owner_id is not None:
                legacy_service_owners_by_process.setdefault(process_id, set()).add(legacy_owner_id)

    overview_roles = set(policy.overview_role_keys or []) if policy else set()
    full_detail_roles = set(policy.full_detail_role_keys or []) if policy else set()
    viewer_roles = roles_by_user.get(viewer_user_id, set()) if viewer_user_id else set()
    viewer_reports = set(resolve_reporting_line_manager_of(viewer_user_id)) if viewer_user_id else set()

    access: dict[str, ProcessAccess] = {}
    for process in processes:
        process_owner_ids = process_owners_by_process.get(process.id, set())
        scoped_service_owner_ids = scoped_service_owners_by_process.get(process.id, set())
        has_scoped_owner = bool(process_owner_ids or scoped_service_owner_ids)
        legacy_owner_ids = legacy_service_owners_by_process.get(process.id, set())
        owner_scope_ids = (
            process_owner_ids | scoped_service_owner_ids
            if has_scoped_owner
            else legacy_owner_ids
        )

        # Explicit process bindings are authoritative. Legacy service owners
        # remain a temporary fallback only where this process has no scoped
        # owner binding at all, preserving existing access during migration.
        mandate_holder: MandateHolder | None = None
        mandate_candidate_ids = (
            process_owner_ids
            if process_owner_ids
            else legacy_owner_ids
            if not has_scoped_owner
            else set()
        )
        for owner_id in sorted(mandate_candidate_ids):
            if (
                CanonicalMandateRole.BUSINESS_PROCESS_OWNER.value
                not in roles_by_user.get(owner_id, set())
            ):
                continue
            owner = users_by_id.get(owner_id)
            if owner is not None:
                mandate_holder = MandateHolder(
                    user_id=owner_id,
                    name=_display_name(owner),
                    canonical_role=CanonicalMandateRole.BUSINESS_PROCESS_OWNER.value,
                )
                break

        if not configured:
            access[process.id] = ProcessAccess(
                visible=True,
                detail=ACCESS_DETAIL_OVERVIEW,
                eligibility=ELIGIBILITY_NOT_EVALUATED,
                mandate_holder=mandate_holder,
            )
            continue

        is_owner_scoped = viewer_user_id in owner_scope_ids if viewer_user_id else False
        is_manager_of_owner = bool(owner_scope_ids & viewer_reports)
        has_overview_role = bool(viewer_roles & overview_roles)
        has_full_detail_role = bool(viewer_roles & full_detail_roles)

        visible = is_owner_scoped or is_manager_of_owner or has_overview_role or has_full_detail_role
        detail = (
            ACCESS_DETAIL_FULL
            if is_owner_scoped or is_manager_of_owner or has_full_detail_role
            else ACCESS_DETAIL_OVERVIEW
        )
        can_act = (
            mandate_holder is not None
            and viewer_user_id == mandate_holder.user_id
        ) or (
            # Compatibility fallback while legacy owner fields remain.
            is_owner_scoped
            and not has_scoped_owner
            and CanonicalMandateRole.BUSINESS_PROCESS_OWNER.value in viewer_roles
        )

        access[process.id] = ProcessAccess(
            visible=visible,
            detail=detail,
            # A manager's visibility is oversight, never mandate.
            eligibility=ELIGIBILITY_CAN_ACT if can_act else ELIGIBILITY_VIEW_ONLY,
            mandate_holder=mandate_holder,
        )

    return OrgAccessResolution(configured=configured, access_by_process_id=access)

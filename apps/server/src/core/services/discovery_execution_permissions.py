"""Step 4.2 Part 3 (DISC-37) — shared permission projection for the
customer-facing Discovery Execution Pipeline surfaces.

Distinct from ``DiscoveryRunActionState`` (``discovery_run.py``):
``action_state`` is a pure run-state eligibility signal computed with no
knowledge of the viewing user's role at all — a MEMBER sees the same
``can_cancel``/``can_retry`` as an org_admin, even though only
``ADMIN_ROLES`` can actually call those mutating routes (enforced
separately, per-route, by each file's own ``_require_org_admin``). This
service combines the role gate with the same underlying state checks
``action_state`` already uses, so a Part 3 response can expose a true
"can this specific viewer actually do this" signal — the spec's own
``canStart``/``canCancel``/``canRetry``/``canViewDiagnostics`` projection
(§15), reusing ``ADMIN_ROLES`` for "Organisation Administrator".

"Technical Setup Owner" is not yet a real, enum-backed role anywhere in
this codebase (confirmed by DISC-36's repository inspection) — every
admin-only permission here resolves purely from ``ADMIN_ROLES``.

"Risklence Consultant" (DISC-44) started as narrow read-only access, then
was extended per the literal Part 3 spec §15/§46: "may start execution
only when: consultant access is active; the customer-authorised
implementation path permits it; the action is taken on behalf of the
setup programme; the audit event records consultant identity; consultant
action does not replace customer approval." Read literally: only
``canStart``/``canRetry`` are ever granted to a consultant, never
``canCancel`` — cancellation is a customer-scope decision (closer to
"approval" than to running/retrying what's already approved), and the
spec never lists it as a consultant capability. "The customer-authorised
implementation path" is this repo's existing minimal grant model itself —
being invited *as a consultant into this specific org* (an explicit,
admin-issued, time-boxed grant) already *is* the customer authorisation;
no separate scoped-grant concept exists or is introduced here. "The audit
event records consultant identity" is satisfied by the existing
``actor_user_id`` attribution (already the consultant's own id) plus a new
``actor_role`` metadata tag the route layer adds when the actor is a
consultant — see ``discovery_run.py``'s ``_write_audit`` call sites.
"""

from __future__ import annotations

from pydantic import BaseModel

from src.core.constants.discovery_run_enums import TERMINAL_DISCOVERY_RUN_STATUSES, DiscoveryRunStatus
from src.core.model_defs.discovery_run import DiscoveryRun
from src.core.models import User
from src.core.roles import ADMIN_ROLES, UserRole
from src.core.services.auth_service import is_access_expired
from src.core.services.discovery_run_lifecycle_service import evaluate_retry_eligibility


class DiscoveryExecutionPermissions(BaseModel):
    can_start: bool
    can_cancel: bool
    can_retry: bool
    can_view_diagnostics: bool


def _can_start_or_retry_role(user: User | None) -> bool:
    """The role gate alone, same rule resolve_discovery_execution_permissions
    ANDs against run state below for can_start/can_retry — pulled out so
    DISC-52's pre-run readiness check (no DiscoveryRun exists yet to
    resolve the full projection against) can reuse the exact same rule
    rather than a second, potentially-diverging copy of it."""
    is_currently_valid = user is not None and user.is_active and not is_access_expired(user)
    is_admin = is_currently_valid and user.role in ADMIN_ROLES
    is_consultant = is_currently_valid and user.role == UserRole.CONSULTANT.value
    return is_admin or is_consultant


def resolve_can_start_discovery(user: User | None) -> bool:
    """DISC-52 (spec §14) — the pre-execution confirmation screen's own
    "do you have permission to do this" check, evaluated against the
    readiness preview (no run exists yet, so the full
    DiscoveryExecutionPermissions projection below can't be resolved —
    there's nothing state-dependent to gate on before a run exists, only
    the role itself)."""
    return _can_start_or_retry_role(user)


def resolve_discovery_execution_permissions(user: User | None, run: DiscoveryRun) -> DiscoveryExecutionPermissions:
    """``user`` is ``None`` for a request whose user row could not be
    resolved (e.g. deactivated/deleted mid-session) — every permission is
    conservatively ``False`` in that case, never inferred from role alone.
    A user whose DISC-44 access_expires_at has passed is treated exactly
    like an inactive one here, re-checked fresh on every call (so an
    already-issued access token can't outlive the grant between logins).
    """
    is_currently_valid = user is not None and user.is_active and not is_access_expired(user)
    is_admin = is_currently_valid and user.role in ADMIN_ROLES
    can_start_or_retry_role = _can_start_or_retry_role(user)
    is_active_member = is_currently_valid
    is_terminal = run.status in TERMINAL_DISCOVERY_RUN_STATUSES

    return DiscoveryExecutionPermissions(
        # "Start" on a per-run permission block reads as "could this viewer
        # start a fresh discovery from here" — only meaningful once this
        # run has reached a terminal outcome; a run still in flight has
        # nothing new to start.
        can_start=can_start_or_retry_role and is_terminal,
        # Cancellation stays admin-only — see module docstring.
        can_cancel=is_admin and not is_terminal and run.status != DiscoveryRunStatus.BLOCKED.value,
        can_retry=can_start_or_retry_role
        and run.status == DiscoveryRunStatus.FAILED.value
        and evaluate_retry_eligibility(run).allowed,
        # Diagnostics (the DISC-41 audit timeline) are read-only — every
        # active org member may view them, not just admins.
        can_view_diagnostics=is_active_member,
    )

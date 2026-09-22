"""Epic A3 — shared read-access gate for the audit/provenance surface.

Extracted from ``discovery_execution_permissions.py``'s ``can_view_diagnostics``
rule (``is_active_member``), which was already domain-agnostic in practice: any
currently-active, non-expired org member may read audit history, re-checked
fresh on every call rather than trusted from a cached JWT claim. Audit routes
across every object type in this slice share this one check instead of each
re-deriving it.
"""

from __future__ import annotations

from src.core.models import User
from src.core.services.auth_service import is_access_expired


def is_active_org_member(user: User | None) -> bool:
    """``user`` is ``None`` when the request's user row could not be resolved
    (e.g. deactivated/deleted mid-session) — conservatively denied, never
    inferred from role alone. A user whose access has expired is treated
    exactly like an inactive one, re-checked fresh on every call."""
    return user is not None and user.is_active and not is_access_expired(user)

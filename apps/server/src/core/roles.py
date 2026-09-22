"""
Canonical role definitions for the Risklence platform.

Keep this file in sync with apps/tenant/features/auth/roles.ts.
"""

from enum import Enum


class UserRole(str, Enum):
    ORG_ADMIN = "org_admin"  # Org owner — full access including billing and user management
    ADMIN = "admin"          # Full access within the org
    MANAGER = "manager"      # Strategic views + can manage assets; cannot manage users or org settings
    MEMBER = "member"        # Operational views only (dashboard, monitoring, audit, assets read)
    # DISC-44 — external, time-boxed, read-only access (e.g. an implementation
    # consultant helping diagnose a discovery run). Deliberately excluded from
    # ROLE_HIERARCHY below: this role must only ever be granted through the
    # explicit invite flow (which requires an access_expires_at), never
    # auto-provisioned via an SSO group→role mapping, which sets no expiry.
    CONSULTANT = "consultant"


# Convenience sets for route/permission checks
ADMIN_ROLES: frozenset[str] = frozenset({UserRole.ORG_ADMIN, UserRole.ADMIN})
MANAGER_ROLES: frozenset[str] = frozenset({UserRole.ORG_ADMIN, UserRole.ADMIN, UserRole.MANAGER})
ALL_ROLES: frozenset[str] = frozenset(
    {UserRole.ORG_ADMIN, UserRole.ADMIN, UserRole.MANAGER, UserRole.MEMBER, UserRole.CONSULTANT}
)

# Ordered lowest → highest privilege (used for SSO role resolution). CONSULTANT
# is deliberately absent — see its own comment above.
ROLE_HIERARCHY: list[UserRole] = [
    UserRole.MEMBER,
    UserRole.MANAGER,
    UserRole.ADMIN,
    UserRole.ORG_ADMIN,
]

# DISC-44 — a consultant grant must always expire, and never for longer than
# this ceiling, regardless of what an inviting admin requests.
CONSULTANT_MAX_ACCESS_DAYS: int = 90

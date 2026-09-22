"""Shared active organisation-administrator authorization guard."""

from sqlalchemy.orm import Session

from src.core.exceptions import AuthorizationError
from src.core.model_defs.tenant_identity import User
from src.core.repository import TenantRepository
from src.core.roles import ADMIN_ROLES


def require_active_org_admin(
    db: Session,
    *,
    organization_id: int,
    user_id: int,
    error_message: str,
) -> User:
    user = TenantRepository(db, User, organization_id).get_by_id(user_id)
    if user is None or not user.is_active or user.role not in ADMIN_ROLES:
        raise AuthorizationError(error_message)
    return user

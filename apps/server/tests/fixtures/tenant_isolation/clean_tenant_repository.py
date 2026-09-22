"""Fixture: TenantRepository usage produces no raw .query()/select() call at
the caller site, so there is nothing for the checker to flag."""

from sqlalchemy.orm import Session

from src.core.models import User
from src.core.repository import TenantRepository


def list_users(db: Session, ctx) -> list[User]:
    return TenantRepository(db, User, ctx.organization_id).get_all()

"""Fixture: a self-lookup by ctx.user_id (server-derived, JWT-verified,
cannot be spoofed by the caller) — matches auth.py's own /auth/me shape."""

from sqlalchemy.orm import Session

from src.api.middleware.tenant_context import get_tenant_context
from src.core.models import User


def me(request, db: Session) -> User | None:
    ctx = get_tenant_context(request)
    return db.query(User).filter(User.id == ctx.user_id).first()

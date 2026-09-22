"""Fixture: an org filter applied in a Python comprehension after an
unfiltered fetch, rather than in SQL — matches services.py's own
get_service_journey_learning_aggregates shape. Inefficient, but a real,
correctly-applied tenant boundary, not a gap."""

from sqlalchemy.orm import Session

from src.api.middleware.tenant_context import TenantContext
from src.core.models import User


def list_users(db: Session, ctx: TenantContext) -> list[User]:
    return [row for row in db.query(User).all() if row.organization_id == ctx.organization_id]

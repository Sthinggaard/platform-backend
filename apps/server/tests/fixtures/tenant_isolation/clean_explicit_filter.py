"""Fixture: a raw query with an explicit Model.organization_id filter."""

from sqlalchemy.orm import Session

from src.core.models import User


def list_users(db: Session, ctx) -> list[User]:
    return db.query(User).filter(User.organization_id == ctx.organization_id).all()

"""Fixture: a raw db.query(Model) with no organization_id filter anywhere
in the function, and no ctx-derived self-lookup — a real violation."""

from sqlalchemy.orm import Session

from src.core.models import User


def list_all_users_by_status(db: Session, status: str) -> list[User]:
    return db.query(User).filter(User.status == status).all()

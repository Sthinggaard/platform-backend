"""Fixture: the select()/db.execute() query style, still no organization_id
filter anywhere in the function — a real violation, covering the second
query shape this codebase's routes actually use alongside db.query()."""

from sqlalchemy import select
from sqlalchemy.orm import Session

from src.core.models import User


def list_users_by_email_domain(db: Session, domain: str) -> list[User]:
    stmt = select(User).where(User.email.like(f"%@{domain}"))
    return db.execute(stmt).scalars().all()

"""Settings endpoints — user management and organisation profile."""

from __future__ import annotations

from datetime import datetime
from typing import Optional

from fastapi import APIRouter, Request
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.orm import Session
from fastapi import Depends

from src.api.middleware.tenant_context import get_tenant_context
from src.core.database import get_db
from src.core.models import User, Organization
from src.core.exceptions import AuthorizationError, ResourceNotFoundError

router = APIRouter(prefix="/api/v1/settings", tags=["Settings"])


def _require_admin(request: Request, db: Session) -> User:
    ctx = get_tenant_context(request)
    user = db.get(User, ctx.user_id)
    if not user or user.role not in ("admin", "org_admin"):
        raise AuthorizationError("Admin access required")
    return user


class UserOut(BaseModel):
    id: int
    email: str
    first_name: Optional[str]
    last_name: Optional[str]
    title: Optional[str]
    role: str
    status: str
    is_active: bool
    last_login_at: Optional[str]
    created_at: str

    @classmethod
    def from_orm(cls, u: User) -> "UserOut":
        return cls(
            id=u.id,
            email=u.email,
            first_name=u.first_name,
            last_name=u.last_name,
            title=u.title,
            role=u.role,
            status=u.status.value if hasattr(u.status, "value") else str(u.status),
            is_active=u.is_active,
            last_login_at=u.last_login_at.isoformat() if u.last_login_at else None,
            created_at=u.created_at.isoformat() if hasattr(u, "created_at") and u.created_at else "",
        )


class PatchUserRequest(BaseModel):
    first_name: Optional[str] = None
    last_name: Optional[str] = None
    title: Optional[str] = None
    role: Optional[str] = None
    is_active: Optional[bool] = None


class UserDirectoryEntryOut(BaseModel):
    id: int
    title: str
    full_name: str
    email: str

    @classmethod
    def from_orm(cls, user: User) -> "UserDirectoryEntryOut":
        full_name = " ".join(part for part in [user.first_name, user.last_name] if part).strip() or user.email
        return cls(
            id=user.id,
            title=(user.title or "").strip(),
            full_name=full_name,
            email=user.email,
        )


class OrgOut(BaseModel):
    id: int
    name: str
    slug: str
    industry: Optional[str]
    company_size: Optional[str]
    country: Optional[str]
    plan_tier: str
    subscription_status: str
    required_frameworks: Optional[list[str]]


class PatchOrgRequest(BaseModel):
    name: Optional[str] = None
    industry: Optional[str] = None
    company_size: Optional[str] = None
    country: Optional[str] = None


class PatchProfileRequest(BaseModel):
    first_name: Optional[str] = None
    last_name: Optional[str] = None
    title: Optional[str] = None


@router.get("/users")
def list_users(request: Request, db: Session = Depends(get_db)):
    ctx = get_tenant_context(request)
    admin = db.get(User, ctx.user_id)
    if not admin or admin.role not in ("admin", "org_admin"):
        raise AuthorizationError("Admin access required")
    users = db.execute(
        select(User)
        .where(User.organization_id == ctx.organization_id)
        .order_by(User.created_at.asc())
    ).scalars().all()
    return [UserOut.from_orm(u) for u in users]


@router.get("/user-directory")
def list_user_directory(request: Request, db: Session = Depends(get_db)):
    ctx = get_tenant_context(request)
    users = db.execute(
        select(User)
        .where(
            User.organization_id == ctx.organization_id,
            User.is_active.is_(True),
            User.title.is_not(None),
        )
        .order_by(User.title.asc(), User.created_at.asc())
    ).scalars().all()
    directory = [UserDirectoryEntryOut.from_orm(user) for user in users if (user.title or "").strip()]
    return directory


@router.get("/profile")
def get_profile(request: Request, db: Session = Depends(get_db)):
    ctx = get_tenant_context(request)
    user = db.execute(
        select(User).where(User.id == ctx.user_id, User.organization_id == ctx.organization_id)
    ).scalar_one_or_none()
    if not user:
        raise ResourceNotFoundError("User not found")
    return UserOut.from_orm(user)


@router.patch("/profile")
def patch_profile(payload: PatchProfileRequest, request: Request, db: Session = Depends(get_db)):
    ctx = get_tenant_context(request)
    user = db.execute(
        select(User).where(User.id == ctx.user_id, User.organization_id == ctx.organization_id)
    ).scalar_one_or_none()
    if not user:
        raise ResourceNotFoundError("User not found")
    if payload.first_name is not None:
        user.first_name = payload.first_name.strip() or None
    if payload.last_name is not None:
        user.last_name = payload.last_name.strip() or None
    if payload.title is not None:
        user.title = payload.title.strip() or None
    db.commit()
    return UserOut.from_orm(user)


@router.patch("/users/{user_id}")
def patch_user(user_id: int, payload: PatchUserRequest, request: Request, db: Session = Depends(get_db)):
    ctx = get_tenant_context(request)
    admin = db.get(User, ctx.user_id)
    if not admin or admin.role not in ("admin", "org_admin"):
        raise AuthorizationError("Admin access required")
    user = db.execute(
        select(User).where(User.id == user_id, User.organization_id == ctx.organization_id)
    ).scalar_one_or_none()
    if not user:
        raise ResourceNotFoundError("User not found")
    if payload.first_name is not None:
        user.first_name = payload.first_name.strip() or None
    if payload.last_name is not None:
        user.last_name = payload.last_name.strip() or None
    if payload.title is not None:
        user.title = payload.title.strip() or None
    if payload.role is not None:
        user.role = payload.role
    if payload.is_active is not None:
        user.is_active = payload.is_active
    db.commit()
    return UserOut.from_orm(user)


@router.get("/org")
def get_org(request: Request, db: Session = Depends(get_db)):
    ctx = get_tenant_context(request)
    org = db.get(Organization, ctx.organization_id)
    if not org:
        raise ResourceNotFoundError("Organisation not found")
    return OrgOut(
        id=org.id,
        name=org.name,
        slug=org.slug,
        industry=getattr(org, "industry", None),
        company_size=getattr(org, "company_size", None),
        country=getattr(org, "country", None),
        plan_tier=org.plan_tier,
        subscription_status=org.subscription_status,
        required_frameworks=getattr(org, "required_frameworks", None),
    )


@router.patch("/org")
def patch_org(payload: PatchOrgRequest, request: Request, db: Session = Depends(get_db)):
    ctx = get_tenant_context(request)
    admin = db.get(User, ctx.user_id)
    if not admin or admin.role not in ("admin", "org_admin"):
        raise AuthorizationError("Admin access required")
    org = db.get(Organization, ctx.organization_id)
    if not org:
        raise ResourceNotFoundError("Organisation not found")
    if payload.name is not None:
        org.name = payload.name
    if payload.industry is not None:
        org.industry = payload.industry
    if payload.company_size is not None:
        org.company_size = payload.company_size
    if payload.country is not None:
        org.country = payload.country
    db.commit()
    return OrgOut(
        id=org.id,
        name=org.name,
        slug=org.slug,
        industry=getattr(org, "industry", None),
        company_size=getattr(org, "company_size", None),
        country=getattr(org, "country", None),
        plan_tier=org.plan_tier,
        subscription_status=org.subscription_status,
        required_frameworks=getattr(org, "required_frameworks", None),
    )

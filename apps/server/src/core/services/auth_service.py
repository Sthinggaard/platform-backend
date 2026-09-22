"""Authentication helpers for local login and session handling."""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import secrets
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Optional

from jose import jwt
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from src.core.config import settings
from src.core.exceptions import (
    AuthenticationError,
    RefreshTokenReuseDetected,
    ValidationError,
)
from src.core.models import (
    AuthTenantSettings,
    InviteToken,
    Organization,
    PasswordResetToken,
    User,
    UserSession,
    UserStatus,
)
from src.core.utils.jwt_secrets import get_jwt_secret_bytes, get_refresh_secret_bytes


@dataclass
class RefreshRotationResult:
    access_token: str
    refresh_token: str
    session: UserSession


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _as_utc(value: datetime) -> datetime:
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)


def is_access_expired(user: User) -> bool:
    """DISC-44 — true once a time-boxed grant (e.g. a consultant invite)
    has passed its access_expires_at. None means "never expires." Checked
    at login and refresh (this module) and again in
    discovery_execution_permissions.py so an already-issued access token
    can't outlive the grant it was issued under between refreshes."""
    return user.access_expires_at is not None and _as_utc(user.access_expires_at) <= _now()


def hash_password(password: str) -> str:
    if len(password) < 8:
        raise ValidationError("Password must be at least 8 characters")
    salt = secrets.token_hex(16)
    iterations = 200_000
    digest = hashlib.pbkdf2_hmac(
        "sha256", password.encode("utf-8"), salt.encode("utf-8"), iterations
    )
    return f"pbkdf2_sha256${iterations}${salt}${digest.hex()}"


def verify_password(password: str, stored_hash: str) -> bool:
    try:
        scheme, iterations, salt, digest = stored_hash.split("$", 3)
    except ValueError:
        return False
    if scheme != "pbkdf2_sha256":
        return False
    computed = hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        salt.encode("utf-8"),
        int(iterations),
    ).hex()
    return hmac.compare_digest(computed, digest)


def hash_refresh_token(token: str) -> str:
    secret = get_refresh_secret_bytes()
    return hmac.new(secret, token.encode("utf-8"), hashlib.sha256).hexdigest()


def create_access_token(user: User, organization_id: int) -> str:
    secret = get_jwt_secret_bytes()
    now = int(_now().timestamp())
    ttl = settings.auth.access_token_ttl_minutes
    claims = {
        "sub": str(user.id),
        "tid": str(organization_id),
        "email": user.email,
        "roles": [user.role],
        "permissions": user.permissions or [],
        "iat": now,
        "exp": now + int(ttl * 60),
    }
    if settings.auth.jwt_issuer:
        claims["iss"] = settings.auth.jwt_issuer
    if settings.auth.jwt_audience:
        claims["aud"] = settings.auth.jwt_audience
    return jwt.encode(claims, secret, algorithm="HS256")


def create_refresh_session(
    db: Session,
    user: User,
    organization_id: int,
    ip: Optional[str],
    user_agent: Optional[str],
    rotated_from_session_id: Optional[int] = None,
    *,
    commit: bool = True,
) -> tuple[str, UserSession]:
    """`commit=False` is used by rotate_refresh_token: revoking the old
    session and creating its successor must land in one commit, or a
    concurrent reader can observe "revoked, but no successor exists yet" in
    the gap between two separate commits — indistinguishable from a genuinely
    dead chain, wrongly failing what is actually a benign race.
    """
    refresh_token = secrets.token_urlsafe(48)
    token_hash = hash_refresh_token(refresh_token)
    expires_at = _now() + timedelta(days=settings.auth.refresh_token_ttl_days)
    session = UserSession(
        organization_id=organization_id,
        user_id=user.id,
        refresh_token_hash=token_hash,
        rotated_from_session_id=rotated_from_session_id,
        expires_at=expires_at,
        ip=ip,
        user_agent=user_agent,
    )
    db.add(session)
    if commit:
        db.commit()
        db.refresh(session)
    return refresh_token, session


def _live_descendant(
    db: Session, session: UserSession, *, max_hops: int = 25
) -> Optional[UserSession]:
    """Walk the rotated_from_session_id chain forward to the current live session,
    if this token's lineage was already rotated onward by a sibling request.
    None if the chain is dead (no descendant, or it terminates in a
    revoked/expired leaf) — that's a genuine reuse, not a benign race.

    max_hops bounds a burst of *concurrent* siblings racing the same stale
    token, not elapsed time — that's already bounded by the grace window this
    is only reached within. A dashboard load has been observed firing close
    to 10 near-simultaneous refresh attempts in this session; 25 leaves
    comfortable headroom above that without being unbounded.
    """
    current = session
    for _ in range(max_hops):
        child = db.execute(
            select(UserSession).where(UserSession.rotated_from_session_id == current.id)
        ).scalar_one_or_none()
        if child is None:
            return None
        if child.revoked_at is None and _as_utc(child.expires_at) > _now():
            return child
        current = child
    return None


def rotate_refresh_token(
    db: Session,
    refresh_token: str,
    ip: Optional[str],
    user_agent: Optional[str],
) -> RefreshRotationResult:
    token_hash = hash_refresh_token(refresh_token)
    session = db.execute(
        select(UserSession).where(UserSession.refresh_token_hash == token_hash).with_for_update()
    ).scalar_one_or_none()
    if not session:
        raise AuthenticationError("Invalid refresh token")

    if session.revoked_at is not None:
        # Locking the row above makes this ordered rather than racy: a sibling
        # request that rotated this exact token microseconds ago looks
        # identical here to a token stolen and replayed hours later, unless we
        # distinguish by how recently it was revoked. Within the grace window,
        # hand the caller the live session it was already rotated into instead
        # of treating its own concurrent request as an attack on itself.
        grace = timedelta(seconds=settings.auth.refresh_token_reuse_grace_seconds)
        within_grace = _now() - _as_utc(session.revoked_at) <= grace
        live = _live_descendant(db, session) if within_grace else None
        if live is None:
            raise RefreshTokenReuseDetected(
                user_id=session.user_id,
                organization_id=session.organization_id,
                session_id=session.id,
            )
        session = live

    if _as_utc(session.expires_at) <= _now():
        raise AuthenticationError("Refresh token expired")

    user = db.execute(select(User).where(User.id == session.user_id)).scalar_one()
    if is_access_expired(user):
        raise AuthenticationError("Access has expired")
    # Epic A4 slice 2 — roles/permissions are baked into the JWT at issuance
    # and TenantContextMiddleware makes no DB calls, so a deactivated or
    # suspended user's session would otherwise keep rotating indefinitely
    # across the 30-day refresh window; mid-session revocation was only ever
    # caught by whichever individual route handlers happened to separately
    # re-check is_active. Same condition auth.py's own login path already
    # uses (status != ACTIVE or not is_active), applied here too.
    if user.status != UserStatus.ACTIVE or not user.is_active:
        raise AuthenticationError("Account is no longer active")

    session.revoked_at = _now()
    db.add(session)
    # Revoking the old session and creating its successor land in the SAME
    # commit (see create_refresh_session's commit=False) — otherwise a
    # concurrent reader can land in the gap between the two and see "revoked,
    # no successor yet", which _live_descendant can't tell apart from a
    # genuinely dead chain.
    new_refresh, new_session = create_refresh_session(
        db,
        user=user,
        organization_id=session.organization_id,
        ip=ip,
        user_agent=user_agent,
        rotated_from_session_id=session.id,
        commit=False,
    )
    db.commit()
    db.refresh(new_session)
    access_token = create_access_token(user, session.organization_id)
    return RefreshRotationResult(
        access_token=access_token,
        refresh_token=new_refresh,
        session=new_session,
    )


def get_session_by_refresh_token(db: Session, refresh_token: str) -> Optional[UserSession]:
    token_hash = hash_refresh_token(refresh_token)
    return db.execute(
        select(UserSession).where(UserSession.refresh_token_hash == token_hash)
    ).scalar_one_or_none()


def revoke_refresh_token(db: Session, refresh_token: str) -> bool:
    token_hash = hash_refresh_token(refresh_token)
    session = db.execute(
        select(UserSession).where(UserSession.refresh_token_hash == token_hash)
    ).scalar_one_or_none()
    if not session:
        return False
    session.revoked_at = _now()
    db.add(session)
    db.commit()
    return True


def revoke_user_sessions(db: Session, user_id: int) -> int:
    sessions = (
        db.execute(
            select(UserSession).where(
                UserSession.user_id == user_id, UserSession.revoked_at.is_(None)
            )
        )
        .scalars()
        .all()
    )
    for session in sessions:
        session.revoked_at = _now()
        db.add(session)
    db.commit()
    return len(sessions)


def resolve_tenant_for_login(db: Session, email: str, tenant_id: Optional[int]) -> Organization:
    if tenant_id:
        tenant = db.execute(
            select(Organization).where(Organization.id == tenant_id)
        ).scalar_one_or_none()
        if not tenant:
            raise AuthenticationError("Invalid tenant")
        if not tenant.auth_settings:
            raise AuthenticationError("Tenant auth settings missing")
        return tenant

    domain = email.split("@")[-1].lower()
    tenants = (
        db.execute(
            select(Organization)
            .join(AuthTenantSettings, AuthTenantSettings.organization_id == Organization.id)
            .where(AuthTenantSettings.domain_allowlist.any(domain))
            .order_by(Organization.updated_at.desc(), Organization.id.desc())
        )
        .scalars()
        .all()
    )
    if not tenants:
        raise AuthenticationError("Invalid tenant")

    if len(tenants) > 1:
        matching_org_ids = set(
            db.execute(
                select(User.organization_id).where(
                    User.organization_id.in_([tenant.id for tenant in tenants]),
                    func.lower(User.email) == email.lower(),
                )
            )
            .scalars()
            .all()
        )
        if len(matching_org_ids) == 1:
            tenant = next(tenant for tenant in tenants if tenant.id in matching_org_ids)
        else:
            tenant = tenants[0]
    else:
        tenant = tenants[0]

    if not tenant.auth_settings:
        raise AuthenticationError("Tenant auth settings missing")
    return tenant


def get_auth_settings(db: Session, organization_id: int) -> AuthTenantSettings:
    settings = db.execute(
        select(AuthTenantSettings).where(AuthTenantSettings.organization_id == organization_id)
    ).scalar_one_or_none()
    if not settings:
        raise AuthenticationError("Tenant auth settings missing")
    return settings


def find_user_by_email(db: Session, organization_id: int, email: str) -> Optional[User]:
    return db.execute(
        select(User).where(
            User.organization_id == organization_id,
            func.lower(User.email) == email.lower(),
        )
    ).scalar_one_or_none()


def create_password_reset_token(
    db: Session,
    user: User,
    organization_id: int,
    requested_ip: Optional[str],
) -> str:
    token = secrets.token_urlsafe(32)
    token_hash = hash_refresh_token(token)
    expires_at = _now() + timedelta(minutes=settings.auth.password_reset_ttl_minutes)
    record = PasswordResetToken(
        organization_id=organization_id,
        user_id=user.id,
        token_hash=token_hash,
        expires_at=expires_at,
        requested_ip=requested_ip,
    )
    db.add(record)
    db.commit()
    return token


def create_invite_token(
    db: Session,
    user: User,
    organization_id: int,
    invited_by_user_id: Optional[int],
) -> str:
    token = secrets.token_urlsafe(32)
    token_hash = hash_refresh_token(token)
    expires_at = _now() + timedelta(hours=settings.auth.invite_token_ttl_hours)
    record = InviteToken(
        organization_id=organization_id,
        user_id=user.id,
        invited_by_user_id=invited_by_user_id,
        token_hash=token_hash,
        expires_at=expires_at,
    )
    db.add(record)
    db.commit()
    return token


def validate_password_reset_token(db: Session, token: str) -> PasswordResetToken:
    token_hash = hash_refresh_token(token)
    record = db.execute(
        select(PasswordResetToken).where(PasswordResetToken.token_hash == token_hash)
    ).scalar_one_or_none()
    if not record:
        raise AuthenticationError("Invalid reset token")
    if record.used_at:
        raise AuthenticationError("Reset token already used")
    if _as_utc(record.expires_at) <= _now():
        raise AuthenticationError("Reset token expired")
    return record


def validate_invite_token(db: Session, token: str) -> InviteToken:
    token_hash = hash_refresh_token(token)
    record = db.execute(
        select(InviteToken).where(InviteToken.token_hash == token_hash)
    ).scalar_one_or_none()
    if not record:
        raise AuthenticationError("Invalid invite token")
    if record.used_at:
        raise AuthenticationError("Invite token already used")
    if _as_utc(record.expires_at) <= _now():
        raise AuthenticationError("Invite token expired")
    return record


def sign_state_payload(payload: dict) -> str:
    secret = get_refresh_secret_bytes()
    encoded = base64.urlsafe_b64encode(json.dumps(payload).encode("utf-8")).decode("utf-8")
    signature = hmac.new(secret, encoded.encode("utf-8"), hashlib.sha256).hexdigest()
    return f"{encoded}.{signature}"


def verify_state_payload(token: str) -> dict:
    try:
        encoded, signature = token.split(".", 1)
    except ValueError as exc:
        raise AuthenticationError("Invalid state token") from exc
    secret = get_refresh_secret_bytes()
    expected = hmac.new(secret, encoded.encode("utf-8"), hashlib.sha256).hexdigest()
    if not hmac.compare_digest(expected, signature):
        raise AuthenticationError("Invalid state signature")
    payload = json.loads(base64.urlsafe_b64decode(encoded.encode("utf-8")))
    return payload

"""Authentication endpoints for local login, refresh, reset, and SSO."""

from __future__ import annotations

import hashlib
import hmac
import secrets
from datetime import datetime, timedelta, timezone
from typing import Optional
from urllib.parse import urlencode

from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from fastapi.responses import JSONResponse, RedirectResponse
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from src.api.middleware.rate_limit import auth_rate_limiter
from src.api.middleware.tenant_context import get_tenant_context
from src.api.routes.activation import _draft_hash, _slugify, _unique_org_slug
from src.api.schemas.auth import (
    InviteAcceptRequest,
    InviteAcceptResponse,
    InviteCreateRequest,
    LoginRequest,
    LoginResponse,
    LogoutResponse,
    MessageResponse,
    MfaChallengeResponse,
    MfaDisableRequest,
    MfaEnrollStartRequest,
    MfaResendRequest,
    MfaVerifyRequest,
    PasswordResetConfirmRequest,
    PasswordResetRequest,
    RefreshRequest,
    RefreshResponse,
    SignupResendRequest,
    SignupStartRequest,
    SignupStartResponse,
    SignupVerifyRequest,
    SignupVerifyResponse,
)
from src.core.config import Environment, settings
from src.core.constants.app_routes import ACTIVATED_WORKSPACE_PATH
from src.core.database import get_db
from src.core.exceptions import (
    AuthenticationError,
    AuthorizationError,
    ConfigurationError,
    RefreshTokenReuseDetected,
    ValidationError,
)
from src.core.logging_config import get_logger
from src.core.models import (
    AuditEvent,
    AuthMsGroupRole,
    AuthMsTenantAllowlist,
    AuthTenantSettings,
    InviteToken,
    MfaChallenge,
    Organization,
    PasswordResetToken,
    User,
    UserIdentity,
    UserStatus,
)
from src.core.roles import ADMIN_ROLES, CONSULTANT_MAX_ACCESS_DAYS, ROLE_HIERARCHY, UserRole
from src.core.services.audit_service import log_audit_event
from src.core.services.auth_service import (
    create_access_token,
    create_invite_token,
    create_password_reset_token,
    create_refresh_session,
    find_user_by_email,
    get_auth_settings,
    get_session_by_refresh_token,
    hash_password,
    hash_refresh_token,
    is_access_expired,
    resolve_tenant_for_login,
    revoke_refresh_token,
    revoke_user_sessions,
    rotate_refresh_token,
    sign_state_payload,
    validate_invite_token,
    validate_password_reset_token,
    verify_password,
    verify_state_payload,
)
from src.core.services.email_service import (
    send_invite_email,
    send_password_reset_email,
    send_password_reset_sso_email,
    send_signup_verification_email,
)
from src.core.services.mfa_service import (
    MFA_PURPOSE_ENROLL,
    MFA_PURPOSE_LOGIN,
    create_mfa_challenge,
    generate_otp,
    resend_mfa_challenge,
    verify_mfa_challenge,
)
from src.core.services.oidc_service import (
    build_authorization_url,
    build_pkce_pair,
    exchange_code,
    verify_id_token,
)
from src.core.services.sms_service import send_sms
from src.pretenant.store import PRETENANT_STORE, DraftStatus, TokenStatus

logger = get_logger(__name__)

router = APIRouter(prefix="/api/v1/auth", tags=["Auth"])
app_auth_router = APIRouter(prefix="/app/auth", tags=["Auth"])

_SIGNUP_VERIFICATION_CODE_TTL_MINUTES = 10
_SIGNUP_VERIFICATION_MAX_ATTEMPTS = 5


def _client_ip(request: Request) -> Optional[str]:
    return request.client.host if request.client else None


def _rate_limit_key(prefix: str, value: str) -> str:
    return f"{prefix}:{hashlib.sha256(value.encode('utf-8')).hexdigest()}"


def _hash_signup_verification_code(code: str, salt: str) -> str:
    digest = hashlib.pbkdf2_hmac(
        "sha256",
        code.encode("utf-8"),
        salt.encode("utf-8"),
        150_000,
    )
    return digest.hex()


def _mask_email(email: str) -> str:
    local, _, domain = email.partition("@")
    if not local or not domain:
        return email
    if len(local) <= 2:
        masked_local = f"{local[0]}*" if len(local) == 2 else "*"
    else:
        masked_local = f"{local[0]}{'*' * (len(local) - 2)}{local[-1]}"
    return f"{masked_local}@{domain}"


def _activation_signup_http_error(status_value: str, activation_token: str) -> HTTPException:
    activation = PRETENANT_STORE.get_activation_token(activation_token)
    if status_value == "expired":
        return HTTPException(
            status_code=status.HTTP_410_GONE,
            detail={"error_type": "token_expired", "message": "Activation token expired"},
        )
    if status_value == "redeemed":
        return HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail={"error_type": "token_redeemed", "message": "Activation token already redeemed"},
        )
    if status_value == "revoked":
        if activation and activation.revocation_reason in {"token_expired", "session_expired"}:
            return HTTPException(
                status_code=status.HTTP_410_GONE,
                detail={"error_type": "token_expired", "message": "Activation token expired"},
            )
        return HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={"error_type": "invalid_token", "message": "Invalid activation token"},
        )
    return HTTPException(
        status_code=status.HTTP_400_BAD_REQUEST,
        detail={"error_type": "invalid_token", "message": "Invalid activation token"},
    )


def _signup_challenge_http_error(status_value: str) -> HTTPException:
    if status_value == "expired":
        return HTTPException(
            status_code=status.HTTP_410_GONE,
            detail={
                "error_type": "verification_code_expired",
                "message": "Verification code expired",
            },
        )
    if status_value == "used":
        return HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail={
                "error_type": "verification_code_used",
                "message": "Verification code already used",
            },
        )
    if status_value == "locked":
        return HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail={
                "error_type": "verification_code_locked",
                "message": "Too many invalid verification attempts",
            },
        )
    if status_value == "revoked":
        return HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={
                "error_type": "invalid_verification_challenge",
                "message": "Invalid verification challenge",
            },
        )
    return HTTPException(
        status_code=status.HTTP_400_BAD_REQUEST,
        detail={
            "error_type": "invalid_verification_challenge",
            "message": "Invalid verification challenge",
        },
    )


def _issue_signup_email_challenge(
    *,
    activation_token: str,
    session_id: str,
    normalized_email: str,
    password_hash: str,
) -> JSONResponse:
    code = generate_otp()
    code_salt = secrets.token_hex(16)
    code_hash = _hash_signup_verification_code(code, code_salt)

    challenge = PRETENANT_STORE.create_signup_challenge(
        activation_token=activation_token,
        email=normalized_email,
        password_hash=password_hash,
        code_hash=code_hash,
        code_salt=code_salt,
        ttl_minutes=_SIGNUP_VERIFICATION_CODE_TTL_MINUTES,
        max_attempts=_SIGNUP_VERIFICATION_MAX_ATTEMPTS,
    )
    if challenge is None:
        refreshed_status = PRETENANT_STORE.get_activation_token_status(activation_token)
        raise _activation_signup_http_error(refreshed_status, activation_token)

    try:
        send_signup_verification_email(normalized_email, code)
    except Exception:
        PRETENANT_STORE.record_audit_event(
            "signup_activation_challenge_failed",
            session_id,
            details={
                "challenge_id": challenge.id,
                "email_fingerprint": hashlib.sha256(normalized_email.encode("utf-8")).hexdigest()[
                    :16
                ],
                "reason": "email_delivery_failed",
            },
        )
        raise

    PRETENANT_STORE.record_audit_event(
        "signup_activation_challenge_issued",
        session_id,
        details={
            "challenge_id": challenge.id,
            "email_fingerprint": hashlib.sha256(normalized_email.encode("utf-8")).hexdigest()[:16],
            "token_fingerprint": hashlib.sha256(activation_token.encode("utf-8")).hexdigest()[:16],
            "expires_at": challenge.expires_at.isoformat(),
        },
    )

    return JSONResponse(
        status_code=status.HTTP_200_OK,
        content=SignupStartResponse(
            challenge_id=challenge.id,
            masked_destination=_mask_email(normalized_email),
            expires_at=challenge.expires_at,
            verification_method="email_code",
            message="Verification code sent to email.",
        ).model_dump(mode="json"),
    )


def _cookie_secure() -> bool:
    if settings.environment != Environment.PRODUCTION:
        return False
    return settings.auth.refresh_cookie_secure


def _is_admin_role(role: str) -> bool:
    return role in ADMIN_ROLES


def _serialize_auth_user(user: User, organization_id: int) -> dict[str, object]:
    return {
        "id": user.id,
        "organization_id": organization_id,
        "email": user.email,
        "first_name": user.first_name,
        "last_name": user.last_name,
        "title": user.title,
        "email_verified": user.email_verified,
        "status": user.status.value,
        "role": user.role,
        "permissions": user.permissions or [],
        "last_login_at": user.last_login_at,
        "mfa_enabled": user.mfa_enabled,
        "mfa_phone_e164": user.mfa_phone_e164,
        "mfa_phone_verified_at": user.mfa_phone_verified_at,
        "mfa_method": user.mfa_method,
        "mfa_enforced_by_policy": user.mfa_enforced_by_policy,
        # DISC-53 — a consultant's own session needs to know its own
        # expiry to render a presence indicator; null for every other
        # role (DISC-44's own invariant: only a consultant invite ever
        # sets this).
        "access_expires_at": user.access_expires_at,
    }


def _is_mfa_required(user: User, auth_settings: AuthTenantSettings) -> bool:
    if user.mfa_enabled:
        return True
    if auth_settings.mfa_required_for_all:
        return True
    if auth_settings.mfa_required_for_admins and _is_admin_role(user.role):
        return True
    return False


def _ensure_sms_mfa_enabled(auth_settings: AuthTenantSettings) -> None:
    if not auth_settings.mfa_sms_enabled:
        raise AuthenticationError("SMS MFA disabled for this tenant")


def _is_domain_allowed(email: str, auth_settings: AuthTenantSettings) -> bool:
    allowlist = auth_settings.domain_allowlist or []
    if not allowlist:
        return True
    domain = email.split("@")[-1].lower()
    return domain in allowlist


def _set_refresh_cookie(response: Response, token: str) -> None:
    max_age = int(settings.auth.refresh_token_ttl_days * 24 * 60 * 60)
    response.set_cookie(
        key=settings.auth.refresh_cookie_name,
        value=token,
        httponly=True,
        secure=_cookie_secure(),
        samesite=settings.auth.refresh_cookie_samesite,
        max_age=max_age,
        path="/",
        domain=settings.auth.refresh_cookie_domain,
    )


def _clear_refresh_cookie(response: Response) -> None:
    response.delete_cookie(
        key=settings.auth.refresh_cookie_name,
        path="/",
        domain=settings.auth.refresh_cookie_domain,
    )


def _get_refresh_token(request: Request, payload: RefreshRequest | None) -> Optional[str]:
    if payload and payload.refresh_token:
        return payload.refresh_token
    return request.cookies.get(settings.auth.refresh_cookie_name)


def _set_state_cookie(response: Response, token: str) -> None:
    ttl = settings.auth.sso_state_ttl_minutes * 60
    response.set_cookie(
        key=settings.auth.sso_state_cookie_name,
        value=token,
        httponly=True,
        secure=_cookie_secure(),
        samesite="lax",
        max_age=ttl,
        path="/",
        domain=settings.auth.refresh_cookie_domain,
    )


def _clear_state_cookie(response: Response) -> None:
    response.delete_cookie(
        key=settings.auth.sso_state_cookie_name,
        path="/",
        domain=settings.auth.refresh_cookie_domain,
    )


@router.post("/login", response_model=LoginResponse | MfaChallengeResponse)
def login(payload: LoginRequest, request: Request, db: Session = Depends(get_db)) -> Response:
    ip = _client_ip(request) or "unknown"
    auth_rate_limiter.check(_rate_limit_key("login_ip", ip), limit=5)
    auth_rate_limiter.check(_rate_limit_key("login_email", payload.email.lower()), limit=5)

    tenant = resolve_tenant_for_login(db, payload.email, payload.tenant_id)
    auth_settings = get_auth_settings(db, tenant.id)
    if not auth_settings.local_login_enabled:
        log_audit_event(
            db,
            organization_id=tenant.id,
            event_type="LOGIN_FAILED",
            actor_user_id=None,
            metadata={"ip": ip, "email": payload.email, "reason": "local_login_disabled"},
        )
        raise AuthenticationError("Local login disabled")
    if auth_settings.sso_required:
        log_audit_event(
            db,
            organization_id=tenant.id,
            event_type="LOGIN_FAILED",
            actor_user_id=None,
            metadata={"ip": ip, "email": payload.email, "reason": "sso_required"},
        )
        raise AuthenticationError("SSO required for this tenant")

    user = find_user_by_email(db, tenant.id, payload.email)
    if (
        not user
        or not user.password_hash
        or not verify_password(payload.password, user.password_hash)
    ):
        log_audit_event(
            db,
            organization_id=tenant.id,
            event_type="LOGIN_FAILED",
            actor_user_id=user.id if user else None,
            metadata={"ip": ip, "email": payload.email},
        )
        raise AuthenticationError("Invalid credentials")

    if user.status != UserStatus.ACTIVE or not user.is_active:
        log_audit_event(
            db,
            organization_id=tenant.id,
            event_type="LOGIN_FAILED",
            actor_user_id=user.id,
            metadata={"ip": ip, "reason": "user_inactive"},
        )
        raise AuthenticationError("User not active")

    if is_access_expired(user):
        revoke_user_sessions(db, user.id)
        log_audit_event(
            db,
            organization_id=tenant.id,
            event_type="LOGIN_FAILED",
            actor_user_id=user.id,
            metadata={"ip": ip, "reason": "access_expired"},
        )
        raise AuthenticationError("Access has expired")

    if _is_mfa_required(user, auth_settings):
        _ensure_sms_mfa_enabled(auth_settings)
        if not user.mfa_enabled or not user.mfa_phone_e164:
            log_audit_event(
                db,
                organization_id=tenant.id,
                event_type="MFA_LOGIN_REQUIRED",
                actor_user_id=user.id,
                metadata={"ip": ip, "reason": "mfa_not_enrolled"},
            )
            raise AuthenticationError("MFA enrollment required")

        challenge_payload = create_mfa_challenge(
            db,
            user=user,
            organization_id=tenant.id,
            phone_e164=user.mfa_phone_e164,
            purpose=MFA_PURPOSE_LOGIN,
            ip=ip,
        )
        send_sms(
            user.mfa_phone_e164,
            f"Risklence login code: {challenge_payload.code}",
            purpose="MFA_LOGIN",
        )
        log_audit_event(
            db,
            organization_id=tenant.id,
            event_type="MFA_LOGIN_REQUIRED",
            actor_user_id=user.id,
            metadata={
                "ip": ip,
                "challenge_id": challenge_payload.challenge.id,
                "method": "sms",
            },
        )
        return JSONResponse(
            status_code=status.HTTP_202_ACCEPTED,
            content=MfaChallengeResponse(
                mfa_required=True,
                challenge_id=challenge_payload.challenge.id,
                masked_destination=challenge_payload.masked_destination,
            ).model_dump(mode="json"),
        )

    user.last_login_at = datetime.now(timezone.utc)
    db.add(user)
    db.commit()

    access_token = create_access_token(user, tenant.id)
    refresh_token, session = create_refresh_session(
        db,
        user=user,
        organization_id=tenant.id,
        ip=ip,
        user_agent=request.headers.get("user-agent"),
    )
    log_audit_event(
        db,
        organization_id=tenant.id,
        event_type="LOGIN_SUCCESS",
        actor_user_id=user.id,
        metadata={"ip": ip, "session_id": session.id},
    )
    response = JSONResponse(
        status_code=status.HTTP_200_OK,
        content=LoginResponse(
            access_token=access_token,
            user=_serialize_auth_user(user, tenant.id),
            tenant={
                "id": tenant.id,
                "name": tenant.name,
                "sso_required": auth_settings.sso_required,
                "local_login_enabled": auth_settings.local_login_enabled,
            },
        ).model_dump(mode="json"),
    )
    _set_refresh_cookie(response, refresh_token)
    return response


@router.post("/signup", response_model=MessageResponse)
def reject_self_signup(request: Request) -> Response:
    """Direct self-signup is blocked; onboarding-gated signup flow must be used."""
    ip = _client_ip(request) or "unknown"
    auth_rate_limiter.check(_rate_limit_key("signup_ip", ip), limit=5)
    raise AuthorizationError("Complete onboarding first, then use the activation signup flow.")


@router.post("/signup/start", response_model=SignupStartResponse)
def signup_start(
    payload: SignupStartRequest, request: Request, db: Session = Depends(get_db)
) -> Response:
    """Start onboarding-gated signup by issuing an email verification code."""
    ip = _client_ip(request) or "unknown"
    auth_rate_limiter.check(_rate_limit_key("signup_start_ip", ip), limit=5)
    auth_rate_limiter.check(_rate_limit_key("signup_start_email", payload.email.lower()), limit=5)
    auth_rate_limiter.check(
        _rate_limit_key("signup_start_token", payload.activation_token), limit=5
    )

    normalized_email = payload.email.strip().lower()
    if not payload.password:
        raise ValidationError("Password is required")
    if len(payload.password) < 8:
        raise ValidationError("Password must be at least 8 characters")

    token_status = PRETENANT_STORE.get_activation_token_status(payload.activation_token)
    if token_status != TokenStatus.ACTIVE:
        raise _activation_signup_http_error(token_status, payload.activation_token)

    activation = PRETENANT_STORE.get_activation_token(payload.activation_token)
    if activation is None:
        raise _activation_signup_http_error("missing", payload.activation_token)

    draft_org = PRETENANT_STORE.get_draft_org(activation.session_id)
    if not draft_org:
        raise HTTPException(
            status_code=status.HTTP_410_GONE,
            detail={"error_type": "session_expired", "message": "Draft session expired"},
        )
    if draft_org.status != DraftStatus.LOCKED:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail={
                "error_type": "draft_not_locked",
                "message": "Draft must be finalized before signup",
            },
        )

    existing_user_id = db.execute(
        select(User.id).where(func.lower(User.email) == normalized_email)
    ).scalar_one_or_none()
    if existing_user_id is not None:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail={
                "error_type": "email_already_in_use",
                "message": "Email already in use. Sign in to continue activation.",
            },
        )

    password_hash = hash_password(payload.password)
    return _issue_signup_email_challenge(
        activation_token=payload.activation_token,
        session_id=activation.session_id,
        normalized_email=normalized_email,
        password_hash=password_hash,
    )


@app_auth_router.post("/signup/start", response_model=SignupStartResponse)
def app_signup_start(
    payload: SignupStartRequest, request: Request, db: Session = Depends(get_db)
) -> Response:
    return signup_start(payload, request, db)


@router.post("/signup/resend", response_model=SignupStartResponse)
def signup_resend(payload: SignupResendRequest, request: Request) -> Response:
    """Resend signup verification code for an active onboarding-gated signup challenge."""
    ip = _client_ip(request) or "unknown"
    auth_rate_limiter.check(_rate_limit_key("signup_resend_ip", ip), limit=10)
    auth_rate_limiter.check(
        _rate_limit_key("signup_resend_challenge", payload.challenge_id), limit=5
    )
    auth_rate_limiter.check(
        _rate_limit_key("signup_resend_token", payload.activation_token), limit=5
    )

    challenge_status = PRETENANT_STORE.get_signup_challenge_status(payload.challenge_id)
    if challenge_status != "active":
        raise _signup_challenge_http_error(challenge_status)
    challenge = PRETENANT_STORE.get_signup_challenge(payload.challenge_id)
    if challenge is None:
        raise _signup_challenge_http_error("missing")
    if challenge.activation_token_hash != PRETENANT_STORE.hash_activation_token(
        payload.activation_token
    ):
        raise _signup_challenge_http_error("missing")

    token_status = PRETENANT_STORE.get_activation_token_status(payload.activation_token)
    if token_status != TokenStatus.ACTIVE:
        raise _activation_signup_http_error(token_status, payload.activation_token)

    activation = PRETENANT_STORE.get_activation_token(payload.activation_token)
    if activation is None:
        raise _activation_signup_http_error("missing", payload.activation_token)

    return _issue_signup_email_challenge(
        activation_token=payload.activation_token,
        session_id=activation.session_id,
        normalized_email=challenge.email,
        password_hash=challenge.password_hash,
    )


@app_auth_router.post("/signup/resend", response_model=SignupStartResponse)
def app_signup_resend(payload: SignupResendRequest, request: Request) -> Response:
    return signup_resend(payload, request)


@router.post("/signup/verify", response_model=SignupVerifyResponse)
def signup_verify(
    payload: SignupVerifyRequest, request: Request, db: Session = Depends(get_db)
) -> Response:
    """Complete onboarding-gated signup by verifying code and promoting draft to active tenant."""
    ip = _client_ip(request) or "unknown"
    auth_rate_limiter.check(_rate_limit_key("signup_verify_ip", ip), limit=10)
    auth_rate_limiter.check(
        _rate_limit_key("signup_verify_challenge", payload.challenge_id), limit=10
    )
    auth_rate_limiter.check(
        _rate_limit_key("signup_verify_token", payload.activation_token), limit=10
    )

    challenge_status = PRETENANT_STORE.get_signup_challenge_status(payload.challenge_id)
    if challenge_status != "active":
        raise _signup_challenge_http_error(challenge_status)

    challenge = PRETENANT_STORE.get_signup_challenge(payload.challenge_id)
    if challenge is None:
        raise _signup_challenge_http_error("missing")
    if challenge.activation_token_hash != PRETENANT_STORE.hash_activation_token(
        payload.activation_token
    ):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={
                "error_type": "invalid_verification_challenge",
                "message": "Invalid verification challenge",
            },
        )

    token_status = PRETENANT_STORE.get_activation_token_status(payload.activation_token)
    if token_status != TokenStatus.ACTIVE:
        raise _activation_signup_http_error(token_status, payload.activation_token)

    expected_hash = _hash_signup_verification_code(payload.code, challenge.code_salt)
    if not hmac.compare_digest(expected_hash, challenge.code_hash):
        updated = PRETENANT_STORE.increment_signup_challenge_attempt(payload.challenge_id)
        if updated is not None and updated.attempt_count >= updated.max_attempts:
            raise _signup_challenge_http_error("locked")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={
                "error_type": "invalid_verification_code",
                "message": "Invalid verification code",
            },
        )

    marked_challenge, mark_status = PRETENANT_STORE.mark_signup_challenge_used(payload.challenge_id)
    if mark_status != "used" or marked_challenge is None:
        raise _signup_challenge_http_error(mark_status)

    activation, consume_status = PRETENANT_STORE.consume_activation_token(payload.activation_token)
    if consume_status != TokenStatus.CONSUMED or activation is None:
        PRETENANT_STORE.reset_signup_challenge_use(payload.challenge_id)
        raise _activation_signup_http_error(consume_status, payload.activation_token)

    draft_org = PRETENANT_STORE.get_draft_org(activation.session_id)
    if not draft_org:
        PRETENANT_STORE.reset_activation_token_redemption(payload.activation_token)
        PRETENANT_STORE.reset_signup_challenge_use(payload.challenge_id)
        raise HTTPException(
            status_code=status.HTTP_410_GONE,
            detail={"error_type": "session_expired", "message": "Draft session expired"},
        )
    if draft_org.status != DraftStatus.LOCKED:
        PRETENANT_STORE.reset_activation_token_redemption(payload.activation_token)
        PRETENANT_STORE.reset_signup_challenge_use(payload.challenge_id)
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail={
                "error_type": "draft_not_locked",
                "message": "Draft must be finalized before signup",
            },
        )

    if (
        db.execute(
            select(User.id).where(func.lower(User.email) == challenge.email)
        ).scalar_one_or_none()
        is not None
    ):
        PRETENANT_STORE.reset_activation_token_redemption(payload.activation_token)
        PRETENANT_STORE.reset_signup_challenge_use(payload.challenge_id)
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail={
                "error_type": "email_already_in_use",
                "message": "Email already in use. Sign in to continue activation.",
            },
        )

    promoted_at = datetime.now(timezone.utc)
    token_fingerprint = hashlib.sha256(payload.activation_token.encode("utf-8")).hexdigest()[:16]
    draft_hash = _draft_hash(draft_org)
    org_name = draft_org.legal_name or draft_org.trade_name or f"Workspace {draft_org.id[:8]}"

    try:
        org_slug = _unique_org_slug(db, _slugify(org_name))
        organization = Organization(
            name=org_name,
            slug=org_slug,
            industry=draft_org.industry_code,
            company_size=draft_org.size_bracket,
            country=draft_org.country,
            cvr_number=draft_org.cvr,
            nace_code=draft_org.industry_code,
            subscription_status="active",
            onboarding_completed=False,
            onboarding_data={
                "source": "public_onboarding",
                "draft_session_id": activation.session_id,
                "draft_org_id": draft_org.id,
                "draft_hash": draft_hash,
                "baseline": {
                    "model_version": draft_org.baseline_model_version,
                    "landscape": draft_org.baseline_snapshot,
                    "generated_at": draft_org.baseline_generated_at.isoformat()
                    if draft_org.baseline_generated_at
                    else None,
                },
            },
        )
        db.add(organization)
        db.flush()

        user = User(
            organization_id=organization.id,
            email=challenge.email,
            email_verified=True,
            password_hash=challenge.password_hash,
            role=UserRole.ORG_ADMIN,
            permissions=[],
            is_active=True,
            status=UserStatus.ACTIVE,
            last_login_at=promoted_at,
        )
        db.add(user)

        auth_settings = AuthTenantSettings(organization_id=organization.id)
        db.add(auth_settings)
        db.flush()

        db.add(
            AuditEvent(
                organization_id=organization.id,
                actor_user_id=user.id,
                event_type="ACTIVATION_TOKEN_REDEEMED",
                metadata_json={
                    "token_fingerprint": token_fingerprint,
                    "draft_session_id": activation.session_id,
                    "draft_org_id": draft_org.id,
                    "via": "signup_verify",
                },
            )
        )
        db.add(
            AuditEvent(
                organization_id=organization.id,
                actor_user_id=user.id,
                event_type="DRAFT_PROMOTED",
                metadata_json={
                    "draft_hash": draft_hash,
                    "model_version": draft_org.baseline_model_version,
                    "draft_session_id": activation.session_id,
                    "draft_org_id": draft_org.id,
                    "token_fingerprint": token_fingerprint,
                    "via": "signup_verify",
                },
            )
        )
        db.add(
            AuditEvent(
                organization_id=organization.id,
                actor_user_id=user.id,
                event_type="SIGNUP_COMPLETED",
                metadata_json={"via": "public_onboarding_activation", "ip": ip},
            )
        )
        db.commit()
    except Exception as exc:
        if db.in_transaction():
            db.rollback()
        PRETENANT_STORE.reset_activation_token_redemption(payload.activation_token)
        PRETENANT_STORE.reset_signup_challenge_use(payload.challenge_id)
        logger.exception(
            "signup_verify_promotion_failed",
            session_id=activation.session_id,
            challenge_id=payload.challenge_id,
            error=str(exc),
        )
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail={
                "error_type": "signup_activation_failed",
                "message": "Failed to complete signup activation",
            },
        ) from exc

    refresh_token, session = create_refresh_session(
        db,
        user=user,
        organization_id=organization.id,
        ip=ip,
        user_agent=request.headers.get("user-agent"),
    )
    access_token = create_access_token(user, organization.id)

    try:
        PRETENANT_STORE.revoke_activation_tokens_for_session(
            activation.session_id, "token_redeemed"
        )
        PRETENANT_STORE.revoke_signup_challenges_for_activation(
            payload.activation_token, "signup_completed"
        )
        PRETENANT_STORE.record_audit_event(
            event_type="signup_activation_completed",
            session_id=activation.session_id,
            details={
                "challenge_id": payload.challenge_id,
                "token_fingerprint": token_fingerprint,
                "organization_id": organization.id,
                "user_id": user.id,
                "draft_hash": draft_hash,
                "model_version": draft_org.baseline_model_version,
            },
        )
    except Exception as exc:  # pragma: no cover - observability only
        logger.exception(
            "signup_verify_post_commit_audit_failed",
            session_id=activation.session_id,
            challenge_id=payload.challenge_id,
            error=str(exc),
        )

    response = JSONResponse(
        status_code=status.HTTP_200_OK,
        content=SignupVerifyResponse(
            access_token=access_token,
            user=_serialize_auth_user(user, organization.id),
            tenant={
                "id": organization.id,
                "name": organization.name,
                "sso_required": auth_settings.sso_required,
                "local_login_enabled": auth_settings.local_login_enabled,
            },
            workspace_url=ACTIVATED_WORKSPACE_PATH,
            activated_at=promoted_at,
            model_version=draft_org.baseline_model_version,
        ).model_dump(mode="json"),
    )
    _set_refresh_cookie(response, refresh_token)
    log_audit_event(
        db,
        organization_id=organization.id,
        event_type="LOGIN_SUCCESS",
        actor_user_id=user.id,
        metadata={"ip": ip, "session_id": session.id, "method": "signup_verify"},
    )
    return response


@app_auth_router.post("/signup/verify", response_model=SignupVerifyResponse)
def app_signup_verify(
    payload: SignupVerifyRequest, request: Request, db: Session = Depends(get_db)
) -> Response:
    return signup_verify(payload, request, db)


@router.post("/mfa/login/verify", response_model=LoginResponse)
def verify_login_mfa(
    payload: MfaVerifyRequest, request: Request, db: Session = Depends(get_db)
) -> Response:
    ip = _client_ip(request) or "unknown"
    auth_rate_limiter.check(
        _rate_limit_key("mfa_verify_ip", ip), limit=settings.auth.mfa_verify_rate_limit
    )
    auth_rate_limiter.check(
        _rate_limit_key("mfa_verify_challenge", str(payload.challenge_id)),
        limit=settings.auth.mfa_verify_rate_limit,
    )
    try:
        challenge = verify_mfa_challenge(db, payload.challenge_id, payload.code, MFA_PURPOSE_LOGIN)
    except AuthenticationError as exc:
        challenge_record = db.execute(
            select(MfaChallenge).where(MfaChallenge.id == payload.challenge_id)
        ).scalar_one_or_none()
        if challenge_record:
            log_audit_event(
                db,
                organization_id=challenge_record.organization_id,
                event_type="MFA_LOGIN_FAILED",
                actor_user_id=challenge_record.user_id,
                metadata={"ip": ip, "challenge_id": payload.challenge_id, "reason": str(exc)},
            )
        raise
    user = db.execute(select(User).where(User.id == challenge.user_id)).scalar_one_or_none()
    tenant = db.execute(
        select(Organization).where(Organization.id == challenge.organization_id)
    ).scalar_one_or_none()
    if not user or not tenant:
        raise AuthenticationError("Invalid MFA challenge")
    if user.status != UserStatus.ACTIVE or not user.is_active:
        raise AuthenticationError("User not active")

    user.last_login_at = datetime.now(timezone.utc)
    db.add(user)
    db.commit()

    access_token = create_access_token(user, tenant.id)
    refresh_token, session = create_refresh_session(
        db,
        user=user,
        organization_id=tenant.id,
        ip=ip,
        user_agent=request.headers.get("user-agent"),
    )
    log_audit_event(
        db,
        organization_id=tenant.id,
        event_type="MFA_LOGIN_SUCCESS",
        actor_user_id=user.id,
        metadata={"ip": ip, "session_id": session.id, "challenge_id": challenge.id},
    )
    response = JSONResponse(
        status_code=status.HTTP_200_OK,
        content=LoginResponse(
            access_token=access_token,
            user=_serialize_auth_user(user, tenant.id),
            tenant={
                "id": tenant.id,
                "name": tenant.name,
                "sso_required": get_auth_settings(db, tenant.id).sso_required,
                "local_login_enabled": get_auth_settings(db, tenant.id).local_login_enabled,
            },
        ).model_dump(mode="json"),
    )
    _set_refresh_cookie(response, refresh_token)
    return response


@router.post("/mfa/enroll/start", response_model=MfaChallengeResponse)
def mfa_enroll_start(
    payload: MfaEnrollStartRequest,
    request: Request,
    db: Session = Depends(get_db),
) -> Response:
    tenant_ctx = get_tenant_context(request)
    ip = _client_ip(request) or "unknown"
    auth_rate_limiter.check(
        _rate_limit_key("mfa_enroll_ip", ip), limit=settings.auth.mfa_resend_rate_limit
    )
    auth_rate_limiter.check(
        _rate_limit_key("mfa_enroll_user", str(tenant_ctx.user_id)),
        limit=settings.auth.mfa_resend_rate_limit,
    )
    auth_settings = get_auth_settings(db, tenant_ctx.organization_id)
    _ensure_sms_mfa_enabled(auth_settings)

    if not payload.phone_e164.startswith("+") or len(payload.phone_e164) < 8:
        raise ValidationError("Phone must be E.164 formatted")

    user = db.execute(select(User).where(User.id == tenant_ctx.user_id)).scalar_one_or_none()
    if not user:
        raise AuthenticationError("User not found")

    user.mfa_phone_e164 = payload.phone_e164
    user.mfa_phone_verified_at = None
    user.mfa_method = "sms"
    db.add(user)
    db.commit()

    challenge_payload = create_mfa_challenge(
        db,
        user=user,
        organization_id=tenant_ctx.organization_id,
        phone_e164=payload.phone_e164,
        purpose=MFA_PURPOSE_ENROLL,
        ip=ip,
    )
    send_sms(
        payload.phone_e164,
        f"Risklence verification code: {challenge_payload.code}",
        purpose="MFA_ENROLL",
    )
    log_audit_event(
        db,
        organization_id=tenant_ctx.organization_id,
        event_type="MFA_ENROLL_START",
        actor_user_id=user.id,
        metadata={"ip": ip, "challenge_id": challenge_payload.challenge.id},
    )
    return JSONResponse(
        status_code=status.HTTP_200_OK,
        content=MfaChallengeResponse(
            mfa_required=False,
            challenge_id=challenge_payload.challenge.id,
            masked_destination=challenge_payload.masked_destination,
        ).model_dump(mode="json"),
    )


@router.post("/mfa/enroll/verify", response_model=MessageResponse)
def mfa_enroll_verify(
    payload: MfaVerifyRequest, request: Request, db: Session = Depends(get_db)
) -> Response:
    tenant_ctx = get_tenant_context(request)
    ip = _client_ip(request) or "unknown"
    auth_rate_limiter.check(
        _rate_limit_key("mfa_enroll_verify_ip", ip), limit=settings.auth.mfa_verify_rate_limit
    )

    try:
        verify_mfa_challenge(db, payload.challenge_id, payload.code, MFA_PURPOSE_ENROLL)
    except AuthenticationError as exc:
        log_audit_event(
            db,
            organization_id=tenant_ctx.organization_id,
            event_type="MFA_ENROLL_FAILED",
            actor_user_id=tenant_ctx.user_id,
            metadata={"ip": ip, "challenge_id": payload.challenge_id, "reason": str(exc)},
        )
        raise

    user = db.execute(select(User).where(User.id == tenant_ctx.user_id)).scalar_one_or_none()
    if not user or not user.mfa_phone_e164:
        raise AuthenticationError("MFA enrollment invalid")

    auth_settings = get_auth_settings(db, tenant_ctx.organization_id)
    policy_required = auth_settings.mfa_required_for_all or (
        auth_settings.mfa_required_for_admins and _is_admin_role(user.role)
    )
    user.mfa_enabled = True
    user.mfa_phone_verified_at = datetime.now(timezone.utc)
    user.mfa_enforced_by_policy = policy_required
    db.add(user)
    db.commit()

    log_audit_event(
        db,
        organization_id=tenant_ctx.organization_id,
        event_type="MFA_ENROLL_SUCCESS",
        actor_user_id=user.id,
        metadata={"ip": ip},
    )
    return JSONResponse(
        status_code=status.HTTP_200_OK,
        content=MessageResponse(message="MFA enrollment complete.").model_dump(mode="json"),
    )


@router.post("/mfa/disable", response_model=MessageResponse)
def mfa_disable(
    payload: MfaDisableRequest, request: Request, db: Session = Depends(get_db)
) -> Response:
    tenant_ctx = get_tenant_context(request)
    ip = _client_ip(request) or "unknown"
    user = db.execute(select(User).where(User.id == tenant_ctx.user_id)).scalar_one_or_none()
    if not user:
        raise AuthenticationError("User not found")
    auth_settings = get_auth_settings(db, tenant_ctx.organization_id)
    if auth_settings.mfa_required_for_all or (
        auth_settings.mfa_required_for_admins and _is_admin_role(user.role)
    ):
        raise AuthenticationError("MFA required by tenant policy")

    if not user.password_hash or not verify_password(payload.password, user.password_hash):
        raise AuthenticationError("Invalid credentials")

    user.mfa_enabled = False
    user.mfa_enforced_by_policy = False
    user.mfa_phone_verified_at = None
    db.add(user)
    db.commit()

    log_audit_event(
        db,
        organization_id=tenant_ctx.organization_id,
        event_type="MFA_DISABLED",
        actor_user_id=user.id,
        metadata={"ip": ip},
    )
    return JSONResponse(
        status_code=status.HTTP_200_OK,
        content=MessageResponse(message="MFA disabled.").model_dump(mode="json"),
    )


@router.post("/mfa/challenge/resend", response_model=MfaChallengeResponse)
def mfa_resend_challenge(
    payload: MfaResendRequest,
    request: Request,
    db: Session = Depends(get_db),
) -> Response:
    ip = _client_ip(request) or "unknown"
    auth_rate_limiter.check(
        _rate_limit_key("mfa_resend_ip", ip), limit=settings.auth.mfa_resend_rate_limit
    )
    auth_rate_limiter.check(
        _rate_limit_key("mfa_resend_challenge", str(payload.challenge_id)),
        limit=settings.auth.mfa_resend_rate_limit,
    )
    challenge = db.execute(
        select(MfaChallenge).where(MfaChallenge.id == payload.challenge_id)
    ).scalar_one_or_none()
    if not challenge:
        raise AuthenticationError("Invalid MFA challenge")

    user = db.execute(select(User).where(User.id == challenge.user_id)).scalar_one_or_none()
    phone = user.mfa_phone_e164 if user else None
    if not phone:
        raise AuthenticationError("MFA phone missing")
    try:
        resend_payload = resend_mfa_challenge(db, payload.challenge_id, phone_e164=phone)
    except ValidationError as exc:
        raise HTTPException(status_code=status.HTTP_429_TOO_MANY_REQUESTS, detail=str(exc))
    send_sms(
        phone,
        f"Risklence verification code: {resend_payload.code}",
        purpose="MFA_RESEND",
    )
    log_audit_event(
        db,
        organization_id=challenge.organization_id,
        event_type="MFA_RESEND",
        actor_user_id=challenge.user_id,
        metadata={"ip": ip, "challenge_id": payload.challenge_id},
    )
    return JSONResponse(
        status_code=status.HTTP_200_OK,
        content=MfaChallengeResponse(
            mfa_required=True,
            challenge_id=resend_payload.challenge.id,
            masked_destination=resend_payload.masked_destination,
        ).model_dump(mode="json"),
    )


@router.post("/refresh", response_model=RefreshResponse)
def refresh(
    request: Request,
    payload: Optional[RefreshRequest] = None,
    db: Session = Depends(get_db),
) -> Response:
    refresh_token = _get_refresh_token(request, payload)
    if not refresh_token:
        raise AuthenticationError("Missing refresh token")

    try:
        rotation = rotate_refresh_token(
            db,
            refresh_token=refresh_token,
            ip=_client_ip(request),
            user_agent=request.headers.get("user-agent"),
        )
    except RefreshTokenReuseDetected as exc:
        revoke_user_sessions(db, exc.user_id)
        log_audit_event(
            db,
            organization_id=exc.organization_id,
            event_type="REFRESH_REUSED_TOKEN_DETECTED",
            actor_user_id=exc.user_id,
            metadata={"session_id": exc.session_id},
        )
        raise
    log_audit_event(
        db,
        organization_id=rotation.session.organization_id,
        event_type="REFRESH_SUCCESS",
        actor_user_id=rotation.session.user_id,
        metadata={"session_id": rotation.session.id},
    )
    response = JSONResponse(
        status_code=status.HTTP_200_OK,
        content=RefreshResponse(access_token=rotation.access_token).model_dump(mode="json"),
    )
    _set_refresh_cookie(response, rotation.refresh_token)
    return response


@router.post("/logout", response_model=LogoutResponse)
def logout(
    request: Request,
    payload: Optional[RefreshRequest] = None,
    db: Session = Depends(get_db),
) -> Response:
    refresh_token = _get_refresh_token(request, payload)
    revoked = False
    if refresh_token:
        session = get_session_by_refresh_token(db, refresh_token)
        revoked = revoke_refresh_token(db, refresh_token)
        if revoked and session:
            log_audit_event(
                db,
                organization_id=session.organization_id,
                event_type="LOGOUT",
                actor_user_id=session.user_id,
                metadata={"session_id": session.id},
            )
    response = JSONResponse(
        status_code=status.HTTP_200_OK,
        content=LogoutResponse(success=revoked).model_dump(mode="json"),
    )
    _clear_refresh_cookie(response)
    return response


@router.get("/me", response_model=LoginResponse)
def me(request: Request, db: Session = Depends(get_db)) -> Response:
    tenant_ctx = get_tenant_context(request)
    user = db.execute(select(User).where(User.id == tenant_ctx.user_id)).scalar_one_or_none()
    tenant = db.execute(
        select(Organization).where(Organization.id == tenant_ctx.organization_id)
    ).scalar_one_or_none()
    if not user or not tenant:
        raise AuthenticationError("User not found")
    auth_settings = get_auth_settings(db, tenant.id)
    access_token = create_access_token(user, tenant.id)
    response = JSONResponse(
        status_code=status.HTTP_200_OK,
        content=LoginResponse(
            access_token=access_token,
            user=_serialize_auth_user(user, tenant.id),
            tenant={
                "id": tenant.id,
                "name": tenant.name,
                "sso_required": auth_settings.sso_required,
                "local_login_enabled": auth_settings.local_login_enabled,
            },
        ).model_dump(mode="json"),
    )
    return response


@router.post("/password/reset/request", response_model=MessageResponse)
def request_password_reset(
    payload: PasswordResetRequest, request: Request, db: Session = Depends(get_db)
) -> Response:
    ip = _client_ip(request) or "unknown"
    try:
        auth_rate_limiter.check(_rate_limit_key("reset_ip", ip), limit=5)
        auth_rate_limiter.check(_rate_limit_key("reset_email", payload.email.lower()), limit=5)
    except HTTPException:
        logger.info("password_reset_rate_limited", ip=ip)
        return JSONResponse(
            status_code=status.HTTP_200_OK,
            content=MessageResponse(
                message="If the account exists, a reset link has been sent."
            ).model_dump(mode="json"),
        )

    user = db.execute(
        select(User).where(func.lower(User.email) == payload.email.lower())
    ).scalar_one_or_none()
    if user:
        tenant = db.execute(
            select(Organization).where(Organization.id == user.organization_id)
        ).scalar_one_or_none()
        auth_settings = None
        if tenant:
            try:
                auth_settings = get_auth_settings(db, tenant.id)
            except AuthenticationError:
                logger.warning("password_reset_missing_auth_settings", organization_id=tenant.id)
        if tenant and auth_settings:
            if auth_settings.local_login_enabled and user.password_hash:
                token = create_password_reset_token(db, user, tenant.id, ip)
                base_url = settings.auth.frontend_base_url or settings.auth.app_base_url
                if base_url:
                    reset_url = f"{base_url}/reset-password?token={token}"
                    try:
                        send_password_reset_email(user.email, reset_url)
                    except Exception:
                        logger.exception("password_reset_email_failed", organization_id=tenant.id)
                else:
                    logger.warning("password_reset_email_skipped_missing_base_url")
                log_audit_event(
                    db,
                    organization_id=tenant.id,
                    event_type="RESET_REQUESTED",
                    actor_user_id=user.id,
                    metadata={"ip": ip, "method": "local"},
                )
            else:
                try:
                    send_password_reset_sso_email(user.email)
                except Exception:
                    logger.exception("password_reset_sso_email_failed", organization_id=tenant.id)
                log_audit_event(
                    db,
                    organization_id=tenant.id,
                    event_type="RESET_REQUESTED",
                    actor_user_id=user.id,
                    metadata={"ip": ip, "method": "sso_only"},
                )

    return JSONResponse(
        status_code=status.HTTP_200_OK,
        content=MessageResponse(
            message="If the account exists, a reset link has been sent."
        ).model_dump(mode="json"),
    )


@router.post("/password/reset/confirm", response_model=MessageResponse)
def confirm_password_reset(
    payload: PasswordResetConfirmRequest, request: Request, db: Session = Depends(get_db)
) -> Response:
    token_hash = hash_refresh_token(payload.token)
    record = db.execute(
        select(PasswordResetToken).where(PasswordResetToken.token_hash == token_hash)
    ).scalar_one_or_none()
    try:
        record = validate_password_reset_token(db, payload.token)
        user = db.execute(select(User).where(User.id == record.user_id)).scalar_one_or_none()
        if not user:
            raise AuthenticationError("Invalid reset token")
    except AuthenticationError as exc:
        if record:
            log_audit_event(
                db,
                organization_id=record.organization_id,
                event_type="RESET_FAILED",
                actor_user_id=record.user_id,
                metadata={"ip": _client_ip(request), "reason": str(exc)},
            )
        raise

    try:
        user.password_hash = hash_password(payload.new_password)
    except ValidationError as exc:
        log_audit_event(
            db,
            organization_id=record.organization_id,
            event_type="RESET_FAILED",
            actor_user_id=user.id,
            metadata={"ip": _client_ip(request), "reason": str(exc)},
        )
        raise
    record.used_at = datetime.now(timezone.utc)
    db.add_all([user, record])
    db.commit()

    revoke_user_sessions(db, user.id)
    log_audit_event(
        db,
        organization_id=record.organization_id,
        event_type="RESET_COMPLETED",
        actor_user_id=user.id,
        metadata={"ip": _client_ip(request)},
    )
    return JSONResponse(
        status_code=status.HTTP_200_OK,
        content=MessageResponse(message="Password reset successful.").model_dump(mode="json"),
    )


@router.post("/invite/create", response_model=MessageResponse)
def create_invite(
    payload: InviteCreateRequest, request: Request, db: Session = Depends(get_db)
) -> Response:
    ip = _client_ip(request) or "unknown"
    auth_rate_limiter.check(_rate_limit_key("invite_ip", ip), limit=5)
    auth_rate_limiter.check(_rate_limit_key("invite_email", payload.email.lower()), limit=5)
    tenant_ctx = get_tenant_context(request)
    inviter = db.execute(select(User).where(User.id == tenant_ctx.user_id)).scalar_one_or_none()
    if not inviter or not _is_admin_role(inviter.role):
        raise AuthorizationError("Admin access required")

    auth_settings = get_auth_settings(db, tenant_ctx.organization_id)
    if not _is_domain_allowed(payload.email, auth_settings):
        raise ValidationError("Invite email domain not allowed")

    user = find_user_by_email(db, tenant_ctx.organization_id, payload.email)
    if user and user.status == UserStatus.ACTIVE and user.is_active:
        raise ValidationError("User already active")

    # DISC-44 — a consultant grant must always expire, and never for longer
    # than CONSULTANT_MAX_ACCESS_DAYS; every other role must never set an
    # expiry (this field exists for exactly one purpose). Evaluated against
    # the *effective* role (payload.role, falling back to an existing
    # invited-but-not-yet-accepted user's current role) so re-inviting an
    # already-consultant user without repeating role= can't silently drop
    # the expiry requirement. Every consultant invite call must explicitly
    # restate access_expires_at — it is never carried over implicitly.
    effective_role = payload.role or (user.role if user else None) or UserRole.MEMBER.value
    access_expires_at = payload.access_expires_at
    if effective_role == UserRole.CONSULTANT.value:
        if access_expires_at is None:
            raise ValidationError("A consultant invite must set access_expires_at")
        if access_expires_at.tzinfo is None:
            access_expires_at = access_expires_at.replace(tzinfo=timezone.utc)
        now = datetime.now(timezone.utc)
        if access_expires_at <= now:
            raise ValidationError("access_expires_at must be in the future")
        if access_expires_at > now + timedelta(days=CONSULTANT_MAX_ACCESS_DAYS):
            raise ValidationError(
                f"Consultant access cannot be granted for more than {CONSULTANT_MAX_ACCESS_DAYS} days"
            )
    elif access_expires_at is not None:
        raise ValidationError("access_expires_at is only allowed for role=consultant")

    if not user:
        user = User(
            organization_id=tenant_ctx.organization_id,
            auth0_user_id=None,
            email=payload.email,
            email_verified=False,
            password_hash=None,
            role=payload.role or UserRole.MEMBER,
            permissions=payload.permissions or [],
            is_active=False,
            status=UserStatus.INVITED,
            access_expires_at=access_expires_at,
        )
        db.add(user)
        db.commit()
        db.refresh(user)
    else:
        if payload.role:
            user.role = payload.role
        if payload.permissions is not None:
            user.permissions = payload.permissions
        user.access_expires_at = access_expires_at
        db.add(user)
        db.commit()

    token = create_invite_token(
        db,
        user=user,
        organization_id=tenant_ctx.organization_id,
        invited_by_user_id=inviter.id,
    )
    base_url = settings.auth.frontend_base_url or settings.auth.app_base_url
    if base_url:
        invite_url = f"{base_url}/auth/invite/accept?token={token}"
        try:
            send_invite_email(payload.email, invite_url, inviter.email)
        except Exception:
            logger.exception("invite_email_failed", organization_id=tenant_ctx.organization_id)
    else:
        logger.warning("invite_email_skipped_missing_base_url")

    log_audit_event(
        db,
        organization_id=tenant_ctx.organization_id,
        event_type="INVITE_CREATED",
        actor_user_id=inviter.id,
        metadata={
            "email": payload.email,
            "role": payload.role or "member",
            "access_expires_at": access_expires_at.isoformat() if access_expires_at else None,
        },
    )

    return JSONResponse(
        status_code=status.HTTP_200_OK,
        content=MessageResponse(message="Invite created.").model_dump(mode="json"),
    )


@router.post("/invite/accept", response_model=InviteAcceptResponse)
def accept_invite(
    payload: InviteAcceptRequest, request: Request, db: Session = Depends(get_db)
) -> Response:
    ip = _client_ip(request) or "unknown"
    auth_rate_limiter.check(_rate_limit_key("invite_accept_ip", ip), limit=10)
    token_record: InviteToken | None = None
    try:
        token_record = validate_invite_token(db, payload.token)
        user = db.execute(select(User).where(User.id == token_record.user_id)).scalar_one_or_none()
        tenant = db.execute(
            select(Organization).where(Organization.id == token_record.organization_id)
        ).scalar_one_or_none()
        if not user or not tenant:
            raise AuthenticationError("Invalid invite token")
        auth_settings = get_auth_settings(db, tenant.id)
        if not _is_domain_allowed(user.email, auth_settings):
            raise AuthenticationError("Invite email domain not allowed")

        if user.status == UserStatus.ACTIVE and user.is_active:
            return JSONResponse(
                status_code=status.HTTP_200_OK,
                content=InviteAcceptResponse(
                    message="Account already active.",
                    sso_required=auth_settings.sso_required,
                    sso_google_enabled=auth_settings.sso_google_enabled,
                    sso_ms_enabled=auth_settings.sso_ms_enabled,
                ).model_dump(mode="json"),
            )

        if auth_settings.sso_required or not auth_settings.local_login_enabled:
            user.status = UserStatus.ACTIVE
            user.is_active = True
            user.mfa_enforced_by_policy = auth_settings.mfa_required_for_all or (
                auth_settings.mfa_required_for_admins and _is_admin_role(user.role)
            )
            token_record.used_at = datetime.now(timezone.utc)
            db.add_all([user, token_record])
            db.commit()

            log_audit_event(
                db,
                organization_id=tenant.id,
                event_type="INVITE_ACCEPTED",
                actor_user_id=user.id,
                metadata={"method": "sso"},
            )
            return JSONResponse(
                status_code=status.HTTP_200_OK,
                content=InviteAcceptResponse(
                    sso_required=True,
                    sso_google_enabled=auth_settings.sso_google_enabled,
                    sso_ms_enabled=auth_settings.sso_ms_enabled,
                    message="Continue with SSO to finish setup.",
                ).model_dump(mode="json"),
            )

        if not payload.password:
            raise ValidationError("Password is required")

        user.password_hash = hash_password(payload.password)
        user.email_verified = True
        user.status = UserStatus.ACTIVE
        user.is_active = True
        user.mfa_enforced_by_policy = auth_settings.mfa_required_for_all or (
            auth_settings.mfa_required_for_admins and _is_admin_role(user.role)
        )
        token_record.used_at = datetime.now(timezone.utc)
        db.add_all([user, token_record])
        db.commit()

        refresh_token, _session = create_refresh_session(
            db,
            user=user,
            organization_id=tenant.id,
            ip=_client_ip(request),
            user_agent=request.headers.get("user-agent"),
        )
        access_token = create_access_token(user, tenant.id)

        log_audit_event(
            db,
            organization_id=tenant.id,
            event_type="INVITE_ACCEPTED",
            actor_user_id=user.id,
            metadata={"method": "local"},
        )
        response = JSONResponse(
            status_code=status.HTTP_200_OK,
            content=InviteAcceptResponse(
                access_token=access_token,
                user=_serialize_auth_user(user, tenant.id),
                tenant={
                    "id": tenant.id,
                    "name": tenant.name,
                    "sso_required": auth_settings.sso_required,
                    "local_login_enabled": auth_settings.local_login_enabled,
                },
            ).model_dump(mode="json"),
        )
        _set_refresh_cookie(response, refresh_token)
        return response
    except (AuthenticationError, ValidationError) as exc:
        if token_record:
            log_audit_event(
                db,
                organization_id=token_record.organization_id,
                event_type="INVITE_ACCEPT_FAILED",
                actor_user_id=token_record.user_id,
                metadata={"reason": str(exc)},
            )
        raise


@router.get("/sso/{provider}/start")
def sso_start(
    provider: str,
    request: Request,
    tenant_id: Optional[int] = None,
    db: Session = Depends(get_db),
) -> Response:
    if provider not in {"google", "microsoft"}:
        raise HTTPException(status_code=404, detail="Unknown provider")
    ip = _client_ip(request) or "unknown"
    auth_rate_limiter.check(_rate_limit_key("sso_start_ip", ip), limit=10)
    if tenant_id:
        tenant = db.execute(
            select(Organization).where(Organization.id == tenant_id)
        ).scalar_one_or_none()
        if not tenant:
            raise AuthenticationError("Invalid tenant")
        auth_settings = get_auth_settings(db, tenant.id)
        if provider == "google" and not auth_settings.sso_google_enabled:
            raise AuthenticationError("Google SSO disabled")
        if provider == "microsoft" and not auth_settings.sso_ms_enabled:
            raise AuthenticationError("Microsoft SSO disabled")

    state_id = secrets.token_urlsafe(16)
    nonce = secrets.token_urlsafe(16)
    code_verifier, code_challenge = build_pkce_pair()
    payload = {
        "state": state_id,
        "nonce": nonce,
        "code_verifier": code_verifier,
        "provider": provider,
        "tenant_id": tenant_id,
        "created_at": int(datetime.now(timezone.utc).timestamp()),
    }
    state_token = sign_state_payload(payload)
    auth_url = build_authorization_url(
        provider, state=state_id, nonce=nonce, code_challenge=code_challenge
    )
    response = RedirectResponse(auth_url, status_code=status.HTTP_302_FOUND)
    _set_state_cookie(response, state_token)
    if tenant_id:
        log_audit_event(
            db,
            organization_id=tenant_id,
            event_type="SSO_START",
            actor_user_id=None,
            metadata={"provider": provider},
        )
    return response


@router.get("/sso/{provider}/callback")
def sso_callback(
    provider: str,
    request: Request,
    code: Optional[str] = None,
    state: Optional[str] = None,
    error: Optional[str] = None,
    error_description: Optional[str] = None,
    db: Session = Depends(get_db),
) -> Response:
    if provider not in {"google", "microsoft"}:
        raise HTTPException(status_code=404, detail="Unknown provider")
    ip = _client_ip(request) or "unknown"
    auth_rate_limiter.check(_rate_limit_key("sso_callback_ip", ip), limit=15)
    tenant_claim = None
    if error:
        outcome = "cancelled" if error == "access_denied" else "action_required"
        redirect_to = settings.auth.sso_callback_url or settings.auth.frontend_base_url
        if redirect_to:
            response = RedirectResponse(
                f"{redirect_to}?sso={outcome}&provider={provider}",
                status_code=status.HTTP_302_FOUND,
            )
        else:
            response = JSONResponse(
                status_code=status.HTTP_200_OK,
                content=MessageResponse(message="SSO requires user action.").model_dump(
                    mode="json"
                ),
            )
        _clear_state_cookie(response)
        return response
    if not code or not state:
        raise AuthenticationError("Missing SSO response")
    tenant_id = None

    def _map_sso_error_code(message: str) -> str:
        lowered = message.lower()
        if "state" in lowered:
            return "STATE_MISMATCH"
        if "tenant not allowed" in lowered:
            return "TENANT_NOT_ALLOWED"
        if "domain not allowed" in lowered or "sso disabled" in lowered:
            return "NOT_ALLOWED"
        if "not linked" in lowered:
            return "LINK_REQUIRED"
        if "email not verified" in lowered:
            return "EMAIL_NOT_VERIFIED"
        if "mfa enrollment required" in lowered:
            return "MFA_ENROLL_REQUIRED"
        if "conditional access" in lowered or "claims challenge" in lowered:
            return "CA_FAILED"
        return "FAILED"

    try:
        state_cookie = request.cookies.get(settings.auth.sso_state_cookie_name)
        if not state_cookie:
            raise AuthenticationError("SSO state missing")
        payload = verify_state_payload(state_cookie)
        if payload.get("state") != state or payload.get("provider") != provider:
            raise AuthenticationError("SSO state mismatch")
        created_at = payload.get("created_at", 0)
        if (
            int(datetime.now(timezone.utc).timestamp()) - int(created_at)
            > settings.auth.sso_state_ttl_minutes * 60
        ):
            raise AuthenticationError("SSO state expired")

        tokens = exchange_code(provider, code, payload["code_verifier"])
        id_token = tokens.get("id_token")
        if not id_token:
            raise AuthenticationError("Missing SSO token")
        claims = verify_id_token(provider, id_token, payload["nonce"])
        email = claims.get("email") or claims.get("preferred_username") or claims.get("upn")
        if not email:
            raise AuthenticationError("Missing email claim")
        email_verified = claims.get("email_verified")

        tenant_id = payload.get("tenant_id")
        tenant = None
        if tenant_id:
            tenant = db.execute(
                select(Organization).where(Organization.id == tenant_id)
            ).scalar_one_or_none()
        if not tenant:
            tenant = resolve_tenant_for_login(db, email, None)
            tenant_id = tenant.id

        auth_settings = get_auth_settings(db, tenant.id)
        if provider == "google" and not auth_settings.sso_google_enabled:
            raise AuthenticationError("Google SSO disabled")
        if provider == "microsoft" and not auth_settings.sso_ms_enabled:
            raise AuthenticationError("Microsoft SSO disabled")
        if provider == "google":
            domain = email.split("@")[-1].lower()
            allowlist = auth_settings.domain_allowlist or []
            if allowlist and domain not in allowlist:
                raise AuthenticationError("Google SSO domain not allowed")
        if provider == "microsoft":
            tenant_claim = claims.get("tid")
            if not tenant_claim:
                raise AuthenticationError("Missing tenant claim")
            allowlist = (
                db.execute(
                    select(AuthMsTenantAllowlist.tenant_id).where(
                        AuthMsTenantAllowlist.auth_settings_id == auth_settings.id
                    )
                )
                .scalars()
                .all()
            )
            if allowlist and tenant_claim not in allowlist:
                raise AuthenticationError("Microsoft tenant not allowed")

        identity = db.execute(
            select(UserIdentity).where(
                UserIdentity.provider == provider,
                UserIdentity.provider_subject == claims.get("sub"),
            )
        ).scalar_one_or_none()

        if identity:
            user = db.execute(select(User).where(User.id == identity.user_id)).scalar_one()
        else:
            user = find_user_by_email(db, tenant.id, email)
            if user and settings.auth.sso_auto_link:
                if email_verified is False and provider == "google":
                    raise AuthenticationError("Email not verified")
                identity = UserIdentity(
                    organization_id=tenant.id,
                    user_id=user.id,
                    provider=provider,
                    provider_subject=claims.get("sub"),
                    provider_tenant=claims.get("tid"),
                    email=email,
                )
                db.add(identity)
                db.commit()
            elif not user and settings.auth.sso_auto_provision:
                if email_verified is False and provider == "google":
                    raise AuthenticationError("Email not verified")
                user = User(
                    organization_id=tenant.id,
                    auth0_user_id=None,
                    email=email,
                    email_verified=bool(claims.get("email_verified", True)),
                    role="member",
                    permissions=[],
                    is_active=True,
                    status=UserStatus.ACTIVE,
                )
                db.add(user)
                db.commit()
                db.refresh(user)
                identity = UserIdentity(
                    organization_id=tenant.id,
                    user_id=user.id,
                    provider=provider,
                    provider_subject=claims.get("sub"),
                    provider_tenant=claims.get("tid"),
                    email=email,
                )
                db.add(identity)
                db.commit()
            else:
                raise AuthenticationError("SSO account not linked")

        if user.status != UserStatus.ACTIVE or not user.is_active:
            raise AuthenticationError("User not active")

        if provider == "microsoft":
            groups = claims.get("groups") if isinstance(claims.get("groups"), list) else []
            if groups:
                mappings = db.execute(
                    select(AuthMsGroupRole.group_id, AuthMsGroupRole.role).where(
                        AuthMsGroupRole.auth_settings_id == auth_settings.id,
                        AuthMsGroupRole.group_id.in_(groups),
                    )
                ).all()
                if mappings:
                    _role_order = {r.value: i for i, r in enumerate(ROLE_HIERARCHY)}
                    allowed_roles = set(_role_order.keys())
                    mapped_roles = [role for _, role in mappings if role in allowed_roles]
                    if mapped_roles:
                        top_role = max(mapped_roles, key=lambda value: _role_order[value])
                        user.role = top_role

        if _is_mfa_required(user, auth_settings):
            _ensure_sms_mfa_enabled(auth_settings)
            if not user.mfa_enabled or not user.mfa_phone_e164:
                log_audit_event(
                    db,
                    organization_id=tenant.id,
                    event_type="MFA_LOGIN_REQUIRED",
                    actor_user_id=user.id,
                    metadata={"provider": provider, "reason": "mfa_not_enrolled"},
                )
                raise AuthenticationError("MFA enrollment required")

            challenge_payload = create_mfa_challenge(
                db,
                user=user,
                organization_id=tenant.id,
                phone_e164=user.mfa_phone_e164,
                purpose=MFA_PURPOSE_LOGIN,
                ip=_client_ip(request),
            )
            send_sms(
                user.mfa_phone_e164,
                f"Risklence login code: {challenge_payload.code}",
                purpose="MFA_LOGIN",
            )
            log_audit_event(
                db,
                organization_id=tenant.id,
                event_type="MFA_LOGIN_REQUIRED",
                actor_user_id=user.id,
                metadata={
                    "provider": provider,
                    "challenge_id": challenge_payload.challenge.id,
                },
            )
            redirect_to = settings.auth.sso_callback_url or settings.auth.frontend_base_url
            if not redirect_to:
                raise ConfigurationError("SSO_CALLBACK_URL not configured")
            query = urlencode(
                {
                    "mfa": "required",
                    "challenge_id": challenge_payload.challenge.id,
                    "provider": provider,
                    "masked_destination": challenge_payload.masked_destination,
                }
            )
            response = RedirectResponse(f"{redirect_to}?{query}", status_code=status.HTTP_302_FOUND)
            _clear_state_cookie(response)
            return response

        user.last_login_at = datetime.now(timezone.utc)
        db.add(user)
        db.commit()

        access_token = create_access_token(user, tenant.id)
        refresh_token, session = create_refresh_session(
            db,
            user=user,
            organization_id=tenant.id,
            ip=_client_ip(request),
            user_agent=request.headers.get("user-agent"),
        )
        log_audit_event(
            db,
            organization_id=tenant.id,
            event_type="SSO_SUCCESS",
            actor_user_id=user.id,
            metadata={
                "provider": provider,
                "session_id": session.id,
                "tid": tenant_claim,
                "ip": ip,
                "user_agent": request.headers.get("user-agent"),
            },
        )

        redirect_to = settings.auth.sso_callback_url or settings.auth.frontend_base_url
        if not redirect_to:
            raise ConfigurationError("SSO_CALLBACK_URL not configured")
        response = RedirectResponse(redirect_to, status_code=status.HTTP_302_FOUND)
        _set_refresh_cookie(response, refresh_token)
        _clear_state_cookie(response)
        return response
    except AuthenticationError as exc:
        if tenant_id:
            log_audit_event(
                db,
                organization_id=tenant_id,
                event_type="SSO_FAILED",
                actor_user_id=None,
                metadata={
                    "provider": provider,
                    "ip": ip,
                    "user_agent": request.headers.get("user-agent"),
                    "tid": tenant_claim,
                    "reason": str(exc),
                },
            )
        redirect_to = settings.auth.sso_callback_url or settings.auth.frontend_base_url
        if redirect_to:
            query = urlencode(
                {
                    "sso": "failed",
                    "provider": provider,
                    "code": _map_sso_error_code(str(exc)),
                }
            )
            response = RedirectResponse(f"{redirect_to}?{query}", status_code=status.HTTP_302_FOUND)
            _clear_state_cookie(response)
            return response
        raise

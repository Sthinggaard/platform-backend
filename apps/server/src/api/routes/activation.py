from __future__ import annotations

import hashlib
import json
import os
import re
from datetime import datetime, timezone
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import select
from sqlalchemy.orm import Session

from src.api.middleware.tenant_context import get_tenant_context
from src.core.constants.app_routes import ACTIVATED_WORKSPACE_PATH
from src.core.database import get_db
from src.core.logging_config import get_logger
from src.core.models import (
    ActivationAuditOutbox,
    AuditEvent,
    AuthTenantSettings,
    Organization,
    User,
)
from src.core.services.baseline_risk_hypothesis_service import (
    create_public_onboarding_handoff_hypothesis,
)
from src.pretenant.store import PRETENANT_STORE, DraftOrganisation, DraftStatus, TokenStatus
from src.pretenant.workspace_contracts import OnboardingValueStreamProfile
from src.core.model_defs.common import to_utc_iso
from src.api.schemas.timestamps import UtcTimestamp

router = APIRouter(prefix="/app/activate", tags=["Activation"])
logger = get_logger(__name__)

_EXPIRED_TOKEN_REASONS = {"token_expired", "session_expired"}
_SLUG_INVALID_CHARS = re.compile(r"[^a-z0-9]+")
_SLUG_TRIM = re.compile(r"^-+|-+$")
_ACTIVATION_AUDIT_DURABILITY_MODES = {"fail_closed", "transactional_outbox"}


class RedeemActivationRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    token: str = Field(..., min_length=12, max_length=512)


class RedeemActivationResponse(BaseModel):
    model_config = ConfigDict(populate_by_name=True)

    outcome: str = Field(default="ACTIVATED")
    message: str | None = None
    organization_id: int | None = Field(default=None, alias="organizationId")
    organization_name: str | None = Field(default=None, alias="organizationName")
    organization_slug: str | None = Field(default=None, alias="organizationSlug")
    user_id: int | None = Field(default=None, alias="userId")
    user_email: str | None = Field(default=None, alias="userEmail")
    workspace_url: str | None = Field(default=None, alias="workspaceUrl")
    activated_at: UtcTimestamp | None = Field(default=None, alias="activatedAt")
    model_version: str | None = Field(default=None, alias="modelVersion")


def _token_fingerprint(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()[:16]


def _token_hash_prefix(token: str) -> str:
    return PRETENANT_STORE.hash_activation_token(token)[:16]


def _draft_hash(draft_org: DraftOrganisation) -> str:
    payload = {
        "id": draft_org.id,
        "status": draft_org.status,
        "cvr": draft_org.cvr,
        "legal_name": draft_org.legal_name,
        "trade_name": draft_org.trade_name,
        "address": draft_org.address,
        "postal_code": draft_org.postal_code,
        "city": draft_org.city,
        "country": draft_org.country,
        "industry_code": draft_org.industry_code,
        "baseline_snapshot": draft_org.baseline_snapshot,
        "baseline_model_version": draft_org.baseline_model_version,
    }
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    return hashlib.sha256(encoded.encode("utf-8")).hexdigest()


def _baseline_snapshot_hash(draft_org: DraftOrganisation) -> str | None:
    if draft_org.baseline_snapshot is None:
        return None
    encoded = json.dumps(
        draft_org.baseline_snapshot,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    )
    return hashlib.sha256(encoded.encode("utf-8")).hexdigest()


def _slugify(value: str) -> str:
    lowered = value.strip().lower()
    normalized = _SLUG_INVALID_CHARS.sub("-", lowered)
    trimmed = _SLUG_TRIM.sub("", normalized)
    return trimmed[:80] or "workspace"


def _unique_org_slug(db: Session, base_slug: str) -> str:
    candidate = base_slug
    suffix = 2
    while db.execute(select(Organization.id).where(Organization.slug == candidate)).scalar_one_or_none() is not None:
        candidate = f"{base_slug[:72]}-{suffix}"
        suffix += 1
    return candidate


def _extract_workspace_value_stream_profile(
    workspace_snapshot: dict[str, Any] | None,
) -> OnboardingValueStreamProfile | None:
    if not isinstance(workspace_snapshot, dict):
        return None

    raw_profile = workspace_snapshot.get("valueStreamProfile")
    if raw_profile is None:
        return None

    try:
        return OnboardingValueStreamProfile.model_validate(raw_profile)
    except Exception:
        logger.warning("activation_value_stream_profile_invalid")
        return None


def _build_handoff_process_candidates(
    *,
    workspace_snapshot: dict[str, Any] | None,
) -> list[dict[str, Any]]:
    profile = _extract_workspace_value_stream_profile(workspace_snapshot)
    if profile is None or len(profile.streams) == 0:
        return []

    candidates = []
    seen_keys: set[str] = set()
    for stream in profile.streams:
        if stream.key in seen_keys:
            continue
        seen_keys.add(stream.key)
        candidates.append(
            {
                "key": stream.key,
                "name": stream.name,
                "priority": stream.priority,
                "confidence": stream.confidence,
                "inference_reason": stream.inference_reason,
                # #281 — this candidate travels on as a plain dict, so it leaves the
                # reach of the response model's serialiser. Formatted through the one
                # rule here rather than passed through: whatever string the workspace
                # JSON happened to hold used to propagate unchecked, including a naive
                # one.
                "public_confirmation_at": (
                    to_utc_iso(profile.confirmed_at) if profile.confirmed_at else None
                ),
            }
        )
    return candidates


def _activation_http_error(status_value: TokenStatus, token: str) -> HTTPException:
    activation = PRETENANT_STORE.get_activation_token(token)
    if status_value == TokenStatus.EXPIRED:
        return HTTPException(
            status_code=status.HTTP_410_GONE,
            detail={"error_type": "token_expired", "message": "Activation token expired"},
        )
    if status_value == TokenStatus.REDEEMED:
        return HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail={"error_type": "token_redeemed", "message": "Activation token already redeemed"},
        )
    if status_value == TokenStatus.REVOKED:
        if activation and activation.revocation_reason in _EXPIRED_TOKEN_REASONS:
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


def _response_from_promoted_records(
    *,
    organization: Organization,
    user: User,
    activated_at: datetime,
) -> dict[str, object]:
    model_version = None
    onboarding_data = organization.onboarding_data if isinstance(organization.onboarding_data, dict) else {}
    baseline = onboarding_data.get("baseline_handoff") if isinstance(onboarding_data, dict) else None
    if isinstance(baseline, dict):
        value = baseline.get("model_version")
        model_version = value if isinstance(value, str) else None

    return {
        "outcome": "ACTIVATED",
        "organizationId": organization.id,
        "organizationName": organization.name,
        "organizationSlug": organization.slug,
        "userId": user.id,
        "userEmail": user.email,
        "workspaceUrl": ACTIVATED_WORKSPACE_PATH,
        "activatedAt": activated_at,
        "modelVersion": model_version,
    }


def _extract_org_cvr(organization: Organization) -> str | None:
    onboarding_data = organization.onboarding_data if isinstance(organization.onboarding_data, dict) else None
    if not onboarding_data:
        return None
    raw = onboarding_data.get("cvr")
    if isinstance(raw, str) and raw.strip():
        return raw.strip()
    return None


def _find_active_org_by_cvr(db: Session, cvr: str) -> Organization | None:
    target = cvr.strip()
    if not target:
        return None
    candidates = db.execute(select(Organization)).scalars().all()
    for organization in candidates:
        if (organization.subscription_status or "").lower() != "active":
            continue
        org_cvr = _extract_org_cvr(organization)
        if org_cvr == target:
            return organization
    return None


def _activation_audit_durability_mode() -> str:
    value = (os.getenv("ACTIVATION_AUDIT_DURABILITY_MODE") or "fail_closed").strip().lower()
    if value not in _ACTIVATION_AUDIT_DURABILITY_MODES:
        raise ValueError(f"Unsupported ACTIVATION_AUDIT_DURABILITY_MODE: {value}")
    return value


def _stage_activation_audit_outbox_entries(db: Session) -> int:
    pending_audits = [obj for obj in list(db.new) if isinstance(obj, AuditEvent)]
    if not pending_audits:
        return 0
    for event in pending_audits:
        db.expunge(event)
        db.add(
            ActivationAuditOutbox(
                organization_id=event.organization_id,
                actor_user_id=event.actor_user_id,
                event_type=event.event_type,
                metadata_json=event.metadata_json,
                status="pending",
            )
        )
    return len(pending_audits)


def _flush_activation_audit_outbox_best_effort(db: Session) -> int:
    pending_rows = (
        db.execute(
            select(ActivationAuditOutbox)
            .where(ActivationAuditOutbox.status == "pending")
            .order_by(ActivationAuditOutbox.id.asc())
        )
        .scalars()
        .all()
    )
    if not pending_rows:
        return 0

    now = datetime.now(timezone.utc)
    for row in pending_rows:
        db.add(
            AuditEvent(
                organization_id=row.organization_id,
                actor_user_id=row.actor_user_id,
                event_type=row.event_type,
                metadata_json=row.metadata_json,
            )
        )
        row.status = "sent"
        row.processed_at = now
        row.last_error = None
    db.commit()
    return len(pending_rows)


def process_activation_audit_outbox(db: Session) -> int:
    """Process pending activation audit outbox rows.

    Safe to call repeatedly; returns number of rows flushed into AuditEvent.
    """
    try:
        return _flush_activation_audit_outbox_best_effort(db)
    except Exception:
        if db.in_transaction():
            db.rollback()
        raise


def _commit_activation_transaction_fail_closed(
    *,
    db: Session,
    token: str,
    token_hash_prefix: str,
    session_id: str,
    log_event: str,
    log_context: dict[str, object],
) -> None:
    try:
        durability_mode = _activation_audit_durability_mode()
    except ValueError as exc:
        if db.in_transaction():
            db.rollback()
        PRETENANT_STORE.reset_activation_token_redemption(token)
        logger.exception(
            "activation_redeem_invalid_audit_durability_mode",
            session_id=session_id,
            token_hash_prefix=token_hash_prefix,
            error=str(exc),
        )
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail={"error_type": "activation_failed", "message": "Failed to activate workspace"},
        ) from exc

    staged_outbox_count = 0
    if durability_mode == "transactional_outbox":
        try:
            staged_outbox_count = _stage_activation_audit_outbox_entries(db)
        except Exception as exc:
            if db.in_transaction():
                db.rollback()
            PRETENANT_STORE.reset_activation_token_redemption(token)
            logger.exception(
                "activation_redeem_outbox_stage_failed",
                session_id=session_id,
                token_hash_prefix=token_hash_prefix,
                error=str(exc),
                **log_context,
            )
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail={"error_type": "activation_failed", "message": "Failed to activate workspace"},
            ) from exc

    try:
        db.commit()
    except Exception as exc:
        if db.in_transaction():
            db.rollback()
        PRETENANT_STORE.reset_activation_token_redemption(token)
        logger.exception(
            log_event,
            session_id=session_id,
            token_hash_prefix=token_hash_prefix,
            error=str(exc),
            **log_context,
        )
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail={"error_type": "activation_failed", "message": "Failed to activate workspace"},
        ) from exc

    if durability_mode == "transactional_outbox" and staged_outbox_count > 0:
        try:
            flushed = _flush_activation_audit_outbox_best_effort(db)
            logger.info(
                "activation_redeem_outbox_flushed",
                session_id=session_id,
                token_hash_prefix=token_hash_prefix,
                staged_outbox_count=staged_outbox_count,
                flushed_outbox_count=flushed,
            )
        except Exception as exc:  # pragma: no cover - defensive; outbox rows remain durable
            if db.in_transaction():
                db.rollback()
            logger.exception(
                "activation_redeem_outbox_flush_failed",
                session_id=session_id,
                token_hash_prefix=token_hash_prefix,
                error=str(exc),
                staged_outbox_count=staged_outbox_count,
            )


def _resolve_idempotent_redeem_response(
    *,
    db: Session,
    token: str,
    user_email: str,
) -> dict[str, object] | None:
    activation = PRETENANT_STORE.get_activation_token(token)
    if not activation:
        return None

    token_hash_prefix = _token_hash_prefix(token)
    events = PRETENANT_STORE.get_audit_events(
        session_id=activation.session_id,
        event_type="activation_token_redeemed",
    )
    for event in reversed(events):
        details = event.details or {}
        # Backward-compatible read during migration from token_fingerprint -> token_hash_prefix.
        if details.get("token_hash_prefix") != token_hash_prefix and details.get("token_fingerprint") != _token_fingerprint(token):
            continue
        organization_id = details.get("organization_id")
        user_id = details.get("user_id")
        if not isinstance(organization_id, int) or not isinstance(user_id, int):
            continue

        organization = db.execute(select(Organization).where(Organization.id == organization_id)).scalar_one_or_none()
        user = db.execute(select(User).where(User.id == user_id)).scalar_one_or_none()
        if not organization or not user:
            continue
        if user.organization_id != organization.id:
            continue
        if user.email.strip().lower() != user_email.strip().lower():
            # Do not disclose workspace context to a different authenticated user.
            return None

        activated_at = activation.redeemed_at or event.created_at
        return _response_from_promoted_records(
            organization=organization,
            user=user,
            activated_at=activated_at,
        )
    return None


@router.post("/redeem", response_model=RedeemActivationResponse, response_model_exclude_none=True)
def redeem_activation_token(
    payload: RedeemActivationRequest,
    request: Request,
    db: Session = Depends(get_db),
):
    tenant = get_tenant_context(request)
    user_email = tenant.email.strip().lower()
    if not user_email:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={"error_type": "invalid_user_context", "message": "Authenticated email is required"},
        )

    token_status = PRETENANT_STORE.get_activation_token_status(payload.token)
    if token_status == TokenStatus.REDEEMED:
        idempotent = _resolve_idempotent_redeem_response(
            db=db,
            token=payload.token,
            user_email=user_email,
        )
        if idempotent is not None:
            logger.info(
                "activation_redeem_idempotent_success",
                token_hash_prefix=_token_hash_prefix(payload.token),
            )
            return idempotent
        raise _activation_http_error(token_status, payload.token)
    if token_status != TokenStatus.ACTIVE:
        raise _activation_http_error(token_status, payload.token)

    activation, consume_status = PRETENANT_STORE.consume_activation_token(payload.token)
    if consume_status == TokenStatus.REDEEMED:
        idempotent = _resolve_idempotent_redeem_response(
            db=db,
            token=payload.token,
            user_email=user_email,
        )
        if idempotent is not None:
            logger.info(
                "activation_redeem_idempotent_success_race",
                token_hash_prefix=_token_hash_prefix(payload.token),
            )
            return idempotent
    if consume_status != TokenStatus.CONSUMED or activation is None:
        raise _activation_http_error(consume_status, payload.token)

    draft_org = PRETENANT_STORE.get_draft_org(activation.session_id)
    if not draft_org:
        PRETENANT_STORE.reset_activation_token_redemption(payload.token)
        raise HTTPException(
            status_code=status.HTTP_410_GONE,
            detail={"error_type": "session_expired", "message": "Draft session expired"},
        )
    if draft_org.status != DraftStatus.LOCKED:
        PRETENANT_STORE.reset_activation_token_redemption(payload.token)
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail={"error_type": "draft_not_locked", "message": "Draft must be finalized before activation"},
        )

    promoted_at = datetime.now(timezone.utc)
    token_hash_prefix = _token_hash_prefix(payload.token)
    draft_hash = _draft_hash(draft_org)
    baseline_snapshot_hash = _baseline_snapshot_hash(draft_org)
    draft_cvr = (draft_org.cvr or "").strip()

    duplicate_org = _find_active_org_by_cvr(db, draft_cvr) if draft_cvr else None
    if duplicate_org is not None:
        duplicate_org_id = duplicate_org.id
        existing_user = db.execute(
            select(User).where(
                User.id == tenant.user_id,
                User.organization_id == duplicate_org_id,
            )
        ).scalar_one_or_none()
        try:
            db.add(
                AuditEvent(
                    organization_id=duplicate_org_id,
                    actor_user_id=None,
                    event_type="ACTIVATION_TOKEN_REDEEM_ATTEMPTED",
                    metadata_json={
                        "token_hash_prefix": token_hash_prefix,
                        "draft_session_id": activation.session_id,
                        "draft_org_id": draft_org.id,
                    },
                )
            )
            db.add(
                AuditEvent(
                    organization_id=duplicate_org_id,
                    actor_user_id=None,
                    event_type="ACTIVATION_TOKEN_REDEEM_FAILED",
                    metadata_json={
                        "reason": "duplicate_cvr",
                        "token_hash_prefix": token_hash_prefix,
                        "draft_session_id": activation.session_id,
                        "draft_org_id": draft_org.id,
                    },
                )
            )
            _commit_activation_transaction_fail_closed(
                db=db,
                token=payload.token,
                token_hash_prefix=token_hash_prefix,
                session_id=activation.session_id,
                log_event="activation_duplicate_cvr_audit_commit_failed",
                log_context={"organization_id": duplicate_org_id},
            )
        except HTTPException:
            raise
        try:
            PRETENANT_STORE.revoke_activation_tokens_for_session(activation.session_id, "duplicate_cvr")
            PRETENANT_STORE.record_audit_event(
                event_type="activation_token_redeem_failed",
                session_id=activation.session_id,
                details={
                    "reason": "duplicate_cvr",
                    "token_hash_prefix": token_hash_prefix,
                    "draft_hash": draft_hash,
                },
            )
        except Exception as exc:  # pragma: no cover - defensive observability
            logger.exception(
                "activation_duplicate_cvr_post_commit_audit_failed",
                session_id=activation.session_id,
                organization_id=duplicate_org_id,
                error=str(exc),
            )
        if existing_user is not None:
            try:
                db.add(
                    AuditEvent(
                        organization_id=duplicate_org_id,
                        actor_user_id=existing_user.id,
                        event_type="ACTIVATION_TOKEN_REDEEM_SUCCEEDED",
                        metadata_json={
                            "reason": "already_registered_existing_member",
                            "token_hash_prefix": token_hash_prefix,
                            "draft_session_id": activation.session_id,
                            "draft_org_id": draft_org.id,
                        },
                    )
                )
                db.commit()
            except Exception as exc:  # pragma: no cover - defensive audit path
                if db.in_transaction():
                    db.rollback()
                logger.exception(
                    "activation_duplicate_cvr_success_audit_failed",
                    session_id=activation.session_id,
                    organization_id=duplicate_org_id,
                    user_id=existing_user.id,
                    error=str(exc),
                )
            return _response_from_promoted_records(
                organization=duplicate_org,
                user=existing_user,
                activated_at=promoted_at,
            )
        return {
            "outcome": "ALREADY_REGISTERED",
            "message": "Organisation already registered. Please contact your administrator.",
        }

    org_name = draft_org.legal_name or draft_org.trade_name or f"Workspace {draft_org.id[:8]}"
    handoff_process_candidates = _build_handoff_process_candidates(
        workspace_snapshot=draft_org.workspace_snapshot,
    )

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
                "cvr": draft_org.cvr,
                "workspace": draft_org.workspace_snapshot,
                "baseline_handoff": {
                    "model_version": draft_org.baseline_model_version,
                    "generated_at": draft_org.baseline_generated_at.isoformat()
                    if draft_org.baseline_generated_at
                    else None,
                    "status": "pending_human_review",
                },
            },
        )
        db.add(organization)
        db.flush()

        handoff_hypothesis = create_public_onboarding_handoff_hypothesis(
            db,
            organization,
            baseline_snapshot=draft_org.baseline_snapshot,
            model_version=draft_org.baseline_model_version,
            generated_at=draft_org.baseline_generated_at,
            process_candidates=handoff_process_candidates,
            source_session_id=activation.session_id,
            source_draft_id=draft_org.id,
        )
        organization.onboarding_data["baseline_handoff"]["hypothesis_id"] = handoff_hypothesis.id
        db.add(organization)

        user = User(
            organization_id=organization.id,
            email=user_email,
            email_verified=True,
            role="org_admin",
            permissions=[],
            is_active=True,
        )
        db.add(user)

        auth_settings = AuthTenantSettings(organization_id=organization.id)
        db.add(auth_settings)
        db.flush()

        db.add(
            AuditEvent(
                organization_id=organization.id,
                actor_user_id=user.id,
                event_type="ACTIVATION_TOKEN_REDEEM_ATTEMPTED",
                metadata_json={
                    "token_hash_prefix": token_hash_prefix,
                    "draft_session_id": activation.session_id,
                    "draft_org_id": draft_org.id,
                },
            )
        )
        db.add(
            AuditEvent(
                organization_id=organization.id,
                actor_user_id=user.id,
                event_type="ACTIVATION_TOKEN_REDEEMED",
                metadata_json={
                    "token_hash_prefix": token_hash_prefix,
                    "draft_session_id": activation.session_id,
                    "draft_org_id": draft_org.id,
                },
            )
        )
        db.add(
            AuditEvent(
                organization_id=organization.id,
                actor_user_id=user.id,
                event_type="ACTIVATION_TOKEN_REDEEM_SUCCEEDED",
                metadata_json={
                    "token_hash_prefix": token_hash_prefix,
                    "draft_session_id": activation.session_id,
                    "draft_org_id": draft_org.id,
                    "model_version": draft_org.baseline_model_version,
                    "baseline_snapshot_hash": baseline_snapshot_hash,
                    "baseline_hypothesis_id": handoff_hypothesis.id,
                },
            )
        )
        db.add(
            AuditEvent(
                organization_id=organization.id,
                actor_user_id=user.id,
                event_type="ORGANISATION_ACTIVATED",
                metadata_json={
                    "token_hash_prefix": token_hash_prefix,
                    "draft_session_id": activation.session_id,
                    "draft_org_id": draft_org.id,
                    "cvr_hash": hashlib.sha256((draft_org.cvr or "").encode("utf-8")).hexdigest()[:16]
                    if draft_org.cvr
                    else None,
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
                    "baseline_snapshot_hash": baseline_snapshot_hash,
                    "model_version": draft_org.baseline_model_version,
                    "draft_session_id": activation.session_id,
                    "draft_org_id": draft_org.id,
                    "token_hash_prefix": token_hash_prefix,
                    "proposed_process_count": len(handoff_process_candidates),
                    "baseline_hypothesis_id": handoff_hypothesis.id,
                },
            )
        )
        _commit_activation_transaction_fail_closed(
            db=db,
            token=payload.token,
            token_hash_prefix=token_hash_prefix,
            session_id=activation.session_id,
            log_event="activation_redeem_failed",
            log_context={},
        )
    except HTTPException:
        raise
    except Exception as exc:
        if db.in_transaction():
            db.rollback()
        PRETENANT_STORE.reset_activation_token_redemption(payload.token)
        logger.exception(
            "activation_redeem_failed_pre_commit",
            token_hash_prefix=token_hash_prefix,
            session_id=activation.session_id,
            error=str(exc),
        )
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail={"error_type": "activation_failed", "message": "Failed to activate workspace"},
        ) from exc

    try:
        PRETENANT_STORE.revoke_activation_tokens_for_session(activation.session_id, "token_redeemed")
        PRETENANT_STORE.record_audit_event(
            event_type="activation_token_redeemed",
            session_id=activation.session_id,
            details={
                "token_hash_prefix": token_hash_prefix,
                "draft_hash": draft_hash,
                "model_version": draft_org.baseline_model_version,
                "organization_id": organization.id,
                "user_id": user.id,
            },
        )
    except Exception as exc:  # pragma: no cover - defensive observability
        logger.exception(
            "activation_redeem_post_commit_audit_failed",
            session_id=activation.session_id,
            organization_id=organization.id,
            error=str(exc),
        )

    logger.info(
        "activation_redeemed",
        session_id=activation.session_id,
        organization_id=organization.id,
        user_id=user.id,
        token_hash_prefix=token_hash_prefix,
    )
    return _response_from_promoted_records(
        organization=organization,
        user=user,
        activated_at=promoted_at,
    )

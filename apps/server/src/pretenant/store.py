from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from enum import Enum
import hashlib
import hmac
import json
import os
from pathlib import Path
import secrets
import threading
from typing import Any, Dict


class DraftStatus(str, Enum):
    DRAFT = "DRAFT"
    LOCKED = "LOCKED"


class TokenStatus(str, Enum):
    ACTIVE = "active"
    REDEEMED = "redeemed"
    REVOKED = "revoked"
    EXPIRED = "expired"
    MISSING = "missing"
    CONSUMED = "consumed"

_DEV_ACTIVATION_TOKEN_HASH_SECRET = "pretenant-activation-token-dev-secret"
_DEFAULT_ACTIVATION_TOKEN_TTL_MINUTES = 30
_MIN_ACTIVATION_TOKEN_TTL_MINUTES = 1
_MAX_ACTIVATION_TOKEN_TTL_MINUTES = 60


def _is_production_env() -> bool:
    return (os.getenv("ENVIRONMENT") or "").strip().lower() == "production"


def _resolve_activation_token_hash_secret() -> bytes:
    configured = (os.getenv("PRETENANT_ACTIVATION_TOKEN_HASH_SECRET") or "").strip()
    if configured:
        return configured.encode("utf-8")
    if _is_production_env():
        raise RuntimeError("PRETENANT_ACTIVATION_TOKEN_HASH_SECRET is required in production")
    return _DEV_ACTIVATION_TOKEN_HASH_SECRET.encode("utf-8")


def _resolve_activation_token_ttl_minutes() -> int:
    raw = (os.getenv("PRETENANT_ACTIVATION_TOKEN_TTL_MINUTES") or "").strip()
    if not raw:
        return _DEFAULT_ACTIVATION_TOKEN_TTL_MINUTES
    try:
        value = int(raw)
    except ValueError as exc:
        raise RuntimeError("PRETENANT_ACTIVATION_TOKEN_TTL_MINUTES must be an integer") from exc
    if value < _MIN_ACTIVATION_TOKEN_TTL_MINUTES or value > _MAX_ACTIVATION_TOKEN_TTL_MINUTES:
        raise RuntimeError(
            f"PRETENANT_ACTIVATION_TOKEN_TTL_MINUTES must be between "
            f"{_MIN_ACTIVATION_TOKEN_TTL_MINUTES} and {_MAX_ACTIVATION_TOKEN_TTL_MINUTES}"
        )
    return value


def _resolve_persistence_path() -> str | None:
    configured = (os.getenv("PRETENANT_STORE_FILE") or "").strip()
    if configured:
        return configured
    if _is_production_env():
        raise RuntimeError("PRETENANT_STORE_FILE is required in production")
    return None


@dataclass(frozen=True)
class DraftOrganisation:
    id: str
    status: str
    expires_at: datetime
    cvr: str | None = None
    legal_name: str | None = None
    trade_name: str | None = None
    address: str | None = None
    postal_code: str | None = None
    city: str | None = None
    country: str | None = None
    industry_code: str | None = None
    industry_description: str | None = None
    size_bracket: str | None = None
    geography: str | None = None
    locations: int | None = None
    it_dependency: str | None = None
    risk_appetite: str | None = None
    selected_asset_categories: list[str] | None = None
    regulatory_flags: list[str] | None = None
    last_enriched_at: datetime | None = None
    baseline_snapshot: dict[str, Any] | None = None
    baseline_model_version: str | None = None
    baseline_generated_at: datetime | None = None
    baseline_input_hash: str | None = None
    baseline_stale: bool = False
    workspace_snapshot: dict[str, Any] | None = None
    business_context: dict[str, str | list[str]] | None = None


@dataclass(frozen=True)
class VerifiedOrganisationProfile:
    vat: str
    name: str
    industry_cluster: str
    org_size_band: str
    legal_form_band: str
    site_count: int
    multi_site: bool
    lifecycle_stage: str
    confirmation_timestamp: datetime
    session_id: str


@dataclass(frozen=True)
class OnboardingSession:
    id: str
    draft_org_id: str
    expires_at: datetime
    created_at: datetime


@dataclass(frozen=True)
class ActivationToken:
    token_hash: str
    session_id: str
    draft_org_id: str
    expires_at: datetime
    created_at: datetime
    redeemed_at: datetime | None = None
    revoked_at: datetime | None = None
    revocation_reason: str | None = None
    token: str | None = None


@dataclass(frozen=True)
class SignupChallenge:
    id: str
    activation_token_hash: str
    session_id: str
    email: str
    password_hash: str
    code_hash: str
    code_salt: str
    expires_at: datetime
    created_at: datetime
    attempt_count: int = 0
    max_attempts: int = 5
    used_at: datetime | None = None
    revoked_at: datetime | None = None
    revocation_reason: str | None = None


@dataclass(frozen=True)
class AuditEvent:
    event_type: str
    session_id: str
    created_at: datetime
    details: dict[str, Any] | None = None


class PreTenantStore:
    def __init__(
        self,
        ttl_minutes: int = 30,
        activation_token_ttl_minutes: int = 10,
        persistence_path: str | None = None,
    ):
        self.ttl_minutes = ttl_minutes
        self.activation_token_ttl_minutes = activation_token_ttl_minutes
        self._persistence_path = Path(persistence_path).expanduser() if persistence_path else None
        self._activation_token_hash_secret = _resolve_activation_token_hash_secret()
        self._sessions: Dict[str, OnboardingSession] = {}
        self._orgs: Dict[str, DraftOrganisation] = {}
        self._verified_org_profiles: Dict[str, VerifiedOrganisationProfile] = {}
        self._activation_tokens: Dict[str, ActivationToken] = {}
        self._signup_challenges: Dict[str, SignupChallenge] = {}
        self._audit_events: list[AuditEvent] = []
        self._expired: Dict[str, datetime] = {}
        self._lock = threading.Lock()
        self._load_persisted()

    @staticmethod
    def _dt_to_str(value: datetime | None) -> str | None:
        if value is None:
            return None
        return value.isoformat()

    @staticmethod
    def _str_to_dt(value: str | None) -> datetime | None:
        if value is None:
            return None
        return datetime.fromisoformat(value)

    def hash_activation_token(self, token: str) -> str:
        return hmac.new(
            self._activation_token_hash_secret,
            token.encode("utf-8"),
            hashlib.sha256,
        ).hexdigest()

    def _dump_payload_locked(self) -> dict[str, Any]:
        return {
            "ttl_minutes": self.ttl_minutes,
            "activation_token_ttl_minutes": self.activation_token_ttl_minutes,
            "sessions": {
                session_id: {
                    "id": session.id,
                    "draft_org_id": session.draft_org_id,
                    "expires_at": self._dt_to_str(session.expires_at),
                    "created_at": self._dt_to_str(session.created_at),
                }
                for session_id, session in self._sessions.items()
            },
            "orgs": {
                org_id: {
                    "id": org.id,
                    "status": org.status,
                    "expires_at": self._dt_to_str(org.expires_at),
                    "cvr": org.cvr,
                    "legal_name": org.legal_name,
                    "trade_name": org.trade_name,
                    "address": org.address,
                    "postal_code": org.postal_code,
                    "city": org.city,
                    "country": org.country,
                    "industry_code": org.industry_code,
                    "industry_description": org.industry_description,
                    "size_bracket": org.size_bracket,
                    "geography": org.geography,
                    "locations": org.locations,
                    "it_dependency": org.it_dependency,
                    "risk_appetite": org.risk_appetite,
                    "selected_asset_categories": org.selected_asset_categories,
                    "regulatory_flags": org.regulatory_flags,
                    "last_enriched_at": self._dt_to_str(org.last_enriched_at),
                    "baseline_snapshot": org.baseline_snapshot,
                    "baseline_model_version": org.baseline_model_version,
                    "baseline_generated_at": self._dt_to_str(org.baseline_generated_at),
                    "baseline_input_hash": org.baseline_input_hash,
                    "baseline_stale": org.baseline_stale,
                    "workspace_snapshot": org.workspace_snapshot,
                    "business_context": org.business_context,
                }
                for org_id, org in self._orgs.items()
            },
            "verified_org_profiles": {
                session_id: {
                    "vat": profile.vat,
                    "name": profile.name,
                    "industry_cluster": profile.industry_cluster,
                    "org_size_band": profile.org_size_band,
                    "legal_form_band": profile.legal_form_band,
                    "site_count": profile.site_count,
                    "multi_site": profile.multi_site,
                    "lifecycle_stage": profile.lifecycle_stage,
                    "confirmation_timestamp": self._dt_to_str(profile.confirmation_timestamp),
                    "session_id": profile.session_id,
                }
                for session_id, profile in self._verified_org_profiles.items()
            },
            "expired": {session_id: self._dt_to_str(expires_at) for session_id, expires_at in self._expired.items()},
            "activation_tokens": {
                token_hash: {
                    "token_hash": activation.token_hash,
                    "session_id": activation.session_id,
                    "draft_org_id": activation.draft_org_id,
                    "expires_at": self._dt_to_str(activation.expires_at),
                    "created_at": self._dt_to_str(activation.created_at),
                    "redeemed_at": self._dt_to_str(activation.redeemed_at),
                    "revoked_at": self._dt_to_str(activation.revoked_at),
                    "revocation_reason": activation.revocation_reason,
                }
                for token_hash, activation in self._activation_tokens.items()
            },
            "signup_challenges": {
                challenge_id: {
                    "id": challenge.id,
                    "activation_token_hash": challenge.activation_token_hash,
                    "session_id": challenge.session_id,
                    "email": challenge.email,
                    "password_hash": challenge.password_hash,
                    "code_hash": challenge.code_hash,
                    "code_salt": challenge.code_salt,
                    "expires_at": self._dt_to_str(challenge.expires_at),
                    "created_at": self._dt_to_str(challenge.created_at),
                    "attempt_count": challenge.attempt_count,
                    "max_attempts": challenge.max_attempts,
                    "used_at": self._dt_to_str(challenge.used_at),
                    "revoked_at": self._dt_to_str(challenge.revoked_at),
                    "revocation_reason": challenge.revocation_reason,
                }
                for challenge_id, challenge in self._signup_challenges.items()
            },
            "audit_events": [
                {
                    "event_type": event.event_type,
                    "session_id": event.session_id,
                    "created_at": self._dt_to_str(event.created_at),
                    "details": event.details,
                }
                for event in self._audit_events
            ],
        }

    def _persist_locked(self) -> None:
        if self._persistence_path is None:
            return
        payload = self._dump_payload_locked()
        self._persistence_path.parent.mkdir(parents=True, exist_ok=True)
        tmp_path = self._persistence_path.with_suffix(f"{self._persistence_path.suffix}.tmp")
        tmp_path.write_text(json.dumps(payload), encoding="utf-8")
        tmp_path.replace(self._persistence_path)

    def _load_persisted(self) -> None:
        if self._persistence_path is None or not self._persistence_path.exists():
            return
        try:
            raw = self._persistence_path.read_text(encoding="utf-8")
            data = json.loads(raw)
        except (OSError, json.JSONDecodeError):
            return

        with self._lock:
            self.ttl_minutes = int(data.get("ttl_minutes", self.ttl_minutes))
            self.activation_token_ttl_minutes = int(
                data.get("activation_token_ttl_minutes", self.activation_token_ttl_minutes)
            )
            self._sessions = {
                sid: OnboardingSession(
                    id=payload["id"],
                    draft_org_id=payload["draft_org_id"],
                    expires_at=self._str_to_dt(payload.get("expires_at")) or datetime.now(timezone.utc),
                    created_at=self._str_to_dt(payload.get("created_at")) or datetime.now(timezone.utc),
                )
                for sid, payload in (data.get("sessions") or {}).items()
            }
            self._orgs = {
                oid: DraftOrganisation(
                    id=payload["id"],
                    status=payload.get("status", DraftStatus.DRAFT),
                    expires_at=self._str_to_dt(payload.get("expires_at")) or datetime.now(timezone.utc),
                    cvr=payload.get("cvr"),
                    legal_name=payload.get("legal_name"),
                    trade_name=payload.get("trade_name"),
                    address=payload.get("address"),
                    postal_code=payload.get("postal_code"),
                    city=payload.get("city"),
                    country=payload.get("country"),
                    industry_code=payload.get("industry_code"),
                    industry_description=payload.get("industry_description"),
                    size_bracket=payload.get("size_bracket"),
                    geography=payload.get("geography"),
                    locations=payload.get("locations"),
                    it_dependency=payload.get("it_dependency"),
                    risk_appetite=payload.get("risk_appetite"),
                    selected_asset_categories=payload.get("selected_asset_categories"),
                    regulatory_flags=payload.get("regulatory_flags"),
                    last_enriched_at=self._str_to_dt(payload.get("last_enriched_at")),
                    baseline_snapshot=payload.get("baseline_snapshot"),
                    baseline_model_version=payload.get("baseline_model_version"),
                    baseline_generated_at=self._str_to_dt(payload.get("baseline_generated_at")),
                    baseline_input_hash=payload.get("baseline_input_hash"),
                    baseline_stale=bool(payload.get("baseline_stale", False)),
                    workspace_snapshot=payload.get("workspace_snapshot"),
                    business_context=payload.get("business_context"),
                )
                for oid, payload in (data.get("orgs") or {}).items()
            }
            self._verified_org_profiles = {
                session_id: VerifiedOrganisationProfile(
                    vat=payload["vat"],
                    name=payload["name"],
                    industry_cluster=payload["industry_cluster"],
                    org_size_band=payload["org_size_band"],
                    legal_form_band=payload["legal_form_band"],
                    site_count=int(payload["site_count"]),
                    multi_site=bool(payload["multi_site"]),
                    lifecycle_stage=payload["lifecycle_stage"],
                    confirmation_timestamp=self._str_to_dt(payload.get("confirmation_timestamp")) or datetime.now(timezone.utc),
                    session_id=payload.get("session_id", session_id),
                )
                for session_id, payload in (data.get("verified_org_profiles") or {}).items()
                if isinstance(payload, dict)
            }
            self._expired = {
                sid: self._str_to_dt(expires_at) or datetime.now(timezone.utc)
                for sid, expires_at in (data.get("expired") or {}).items()
            }
            self._activation_tokens = {
                (
                    payload.get("token_hash")
                    or self.hash_activation_token(payload.get("token") or token)
                ): ActivationToken(
                    token_hash=payload.get("token_hash") or self.hash_activation_token(payload.get("token") or token),
                    session_id=payload["session_id"],
                    draft_org_id=payload["draft_org_id"],
                    expires_at=self._str_to_dt(payload.get("expires_at")) or datetime.now(timezone.utc),
                    created_at=self._str_to_dt(payload.get("created_at")) or datetime.now(timezone.utc),
                    redeemed_at=self._str_to_dt(payload.get("redeemed_at")),
                    revoked_at=self._str_to_dt(payload.get("revoked_at")),
                    revocation_reason=payload.get("revocation_reason"),
                    token=None,
                )
                for token, payload in (data.get("activation_tokens") or {}).items()
            }
            self._signup_challenges = {
                challenge_id: SignupChallenge(
                    id=payload["id"],
                    activation_token_hash=payload.get("activation_token_hash")
                    or self.hash_activation_token(payload["activation_token"]),
                    session_id=payload["session_id"],
                    email=payload["email"],
                    password_hash=payload["password_hash"],
                    code_hash=payload["code_hash"],
                    code_salt=payload["code_salt"],
                    expires_at=self._str_to_dt(payload.get("expires_at")) or datetime.now(timezone.utc),
                    created_at=self._str_to_dt(payload.get("created_at")) or datetime.now(timezone.utc),
                    attempt_count=int(payload.get("attempt_count", 0)),
                    max_attempts=int(payload.get("max_attempts", 5)),
                    used_at=self._str_to_dt(payload.get("used_at")),
                    revoked_at=self._str_to_dt(payload.get("revoked_at")),
                    revocation_reason=payload.get("revocation_reason"),
                )
                for challenge_id, payload in (data.get("signup_challenges") or {}).items()
            }
            self._audit_events = [
                AuditEvent(
                    event_type=payload["event_type"],
                    session_id=payload["session_id"],
                    created_at=self._str_to_dt(payload.get("created_at")) or datetime.now(timezone.utc),
                    details=payload.get("details"),
                )
                for payload in (data.get("audit_events") or [])
            ]

    def create_session(self) -> tuple[OnboardingSession, DraftOrganisation]:
        now = datetime.now(timezone.utc)
        expires_at = now + timedelta(minutes=self.ttl_minutes)
        for _ in range(5):
            session_id = secrets.token_urlsafe(32)
            draft_org_id = secrets.token_urlsafe(16)
            with self._lock:
                if session_id in self._sessions or draft_org_id in self._orgs:
                    continue
                session = OnboardingSession(
                    id=session_id,
                    draft_org_id=draft_org_id,
                    expires_at=expires_at,
                    created_at=now,
                )
                draft_org = DraftOrganisation(
                    id=draft_org_id,
                    status=DraftStatus.DRAFT,
                    expires_at=expires_at,
                )
                self._sessions[session_id] = session
                self._orgs[draft_org_id] = draft_org
                self._persist_locked()
                return session, draft_org
        raise RuntimeError("Failed to generate unique onboarding session IDs")

    def get_session(self, session_id: str) -> OnboardingSession | None:
        self._purge_expired()
        return self._sessions.get(session_id)

    def get_draft_org(self, session_id: str) -> DraftOrganisation | None:
        self._purge_expired()
        session = self._sessions.get(session_id)
        if not session:
            return None
        return self._orgs.get(session.draft_org_id)

    def update_draft_org(self, session_id: str, **updates) -> DraftOrganisation | None:
        self._purge_expired()
        session = self._sessions.get(session_id)
        if not session:
            return None
        with self._lock:
            draft_org = self._orgs.get(session.draft_org_id)
            if not draft_org:
                return None
            updated = DraftOrganisation(
                id=draft_org.id,
                status=updates.get("status", draft_org.status),
                expires_at=draft_org.expires_at,
                cvr=updates.get("cvr", draft_org.cvr),
                legal_name=updates.get("legal_name", draft_org.legal_name),
                trade_name=updates.get("trade_name", draft_org.trade_name),
                address=updates.get("address", draft_org.address),
                postal_code=updates.get("postal_code", draft_org.postal_code),
                city=updates.get("city", draft_org.city),
                country=updates.get("country", draft_org.country),
                industry_code=updates.get("industry_code", draft_org.industry_code),
                industry_description=updates.get(
                    "industry_description", draft_org.industry_description
                ),
                size_bracket=updates.get("size_bracket", draft_org.size_bracket),
                geography=updates.get("geography", draft_org.geography),
                locations=updates.get("locations", draft_org.locations),
                it_dependency=updates.get("it_dependency", draft_org.it_dependency),
                risk_appetite=updates.get("risk_appetite", draft_org.risk_appetite),
                selected_asset_categories=updates.get(
                    "selected_asset_categories", draft_org.selected_asset_categories
                ),
                regulatory_flags=updates.get("regulatory_flags", draft_org.regulatory_flags),
                last_enriched_at=updates.get("last_enriched_at", draft_org.last_enriched_at),
                baseline_snapshot=updates.get("baseline_snapshot", draft_org.baseline_snapshot),
                baseline_model_version=updates.get("baseline_model_version", draft_org.baseline_model_version),
                baseline_generated_at=updates.get("baseline_generated_at", draft_org.baseline_generated_at),
                baseline_input_hash=updates.get("baseline_input_hash", draft_org.baseline_input_hash),
                baseline_stale=updates.get("baseline_stale", draft_org.baseline_stale),
                workspace_snapshot=updates.get("workspace_snapshot", draft_org.workspace_snapshot),
                business_context=updates.get("business_context", draft_org.business_context),
            )
            self._orgs[draft_org.id] = updated
            self._persist_locked()
            return updated

    def save_verified_org_profile(self, session_id: str, profile: VerifiedOrganisationProfile) -> VerifiedOrganisationProfile | None:
        self._purge_expired()
        session = self._sessions.get(session_id)
        if not session:
            return None
        with self._lock:
            if session_id not in self._sessions:
                return None
            self._verified_org_profiles[session_id] = profile
            self._persist_locked()
            return profile

    def get_verified_org_profile(self, session_id: str) -> VerifiedOrganisationProfile | None:
        self._purge_expired()
        return self._verified_org_profiles.get(session_id)

    def get_session_status(self, session_id: str) -> str:
        self._purge_expired()
        if session_id in self._sessions:
            return "active"
        if session_id in self._expired:
            return "expired"
        return "missing"

    def create_activation_token(self, session_id: str, ttl_minutes: int | None = None) -> ActivationToken | None:
        self._purge_expired()
        session = self._sessions.get(session_id)
        if not session:
            return None
        now = datetime.now(timezone.utc)
        requested_ttl = self.activation_token_ttl_minutes if ttl_minutes is None else ttl_minutes
        token_expires_at = now + timedelta(minutes=requested_ttl)
        expires_at = min(session.expires_at, token_expires_at)
        with self._lock:
            self._revoke_activation_tokens_for_session_locked(session_id, "superseded")
            for _ in range(5):
                token_value = secrets.token_urlsafe(32)
                token_hash = self.hash_activation_token(token_value)
                if token_hash in self._activation_tokens:
                    continue
                stored_token = ActivationToken(
                    token_hash=token_hash,
                    session_id=session.id,
                    draft_org_id=session.draft_org_id,
                    expires_at=expires_at,
                    created_at=now,
                )
                self._activation_tokens[token_hash] = stored_token
                self._persist_locked()
                return ActivationToken(
                    token_hash=token_hash,
                    session_id=stored_token.session_id,
                    draft_org_id=stored_token.draft_org_id,
                    expires_at=stored_token.expires_at,
                    created_at=stored_token.created_at,
                    redeemed_at=stored_token.redeemed_at,
                    revoked_at=stored_token.revoked_at,
                    revocation_reason=stored_token.revocation_reason,
                    token=token_value,
                )
        raise RuntimeError("Failed to generate unique activation token")

    def get_activation_token(self, token: str) -> ActivationToken | None:
        self._purge_expired()
        return self._activation_tokens.get(self.hash_activation_token(token))

    def get_activation_token_status(self, token: str) -> TokenStatus:
        self._purge_expired()
        activation = self._activation_tokens.get(self.hash_activation_token(token))
        if not activation:
            return TokenStatus.MISSING
        if activation.redeemed_at is not None:
            return TokenStatus.REDEEMED
        if activation.revoked_at is not None:
            return TokenStatus.REVOKED
        if activation.expires_at <= datetime.now(timezone.utc):
            return TokenStatus.EXPIRED
        return TokenStatus.ACTIVE

    def consume_activation_token(self, token: str) -> tuple[ActivationToken | None, TokenStatus]:
        self._purge_expired()
        now = datetime.now(timezone.utc)
        token_hash = self.hash_activation_token(token)
        with self._lock:
            activation = self._activation_tokens.get(token_hash)
            if not activation:
                return None, TokenStatus.MISSING
            if activation.revoked_at is not None:
                return None, TokenStatus.REVOKED
            if activation.redeemed_at is not None:
                return None, TokenStatus.REDEEMED
            if activation.expires_at <= now:
                revoked = ActivationToken(
                    token_hash=activation.token_hash,
                    session_id=activation.session_id,
                    draft_org_id=activation.draft_org_id,
                    expires_at=activation.expires_at,
                    created_at=activation.created_at,
                    redeemed_at=activation.redeemed_at,
                    revoked_at=now,
                    revocation_reason="token_expired",
                    token=None,
                )
                self._activation_tokens[token_hash] = revoked
                self._persist_locked()
                return None, TokenStatus.EXPIRED
            consumed = ActivationToken(
                token_hash=activation.token_hash,
                session_id=activation.session_id,
                draft_org_id=activation.draft_org_id,
                expires_at=activation.expires_at,
                created_at=activation.created_at,
                redeemed_at=now,
                revoked_at=activation.revoked_at,
                revocation_reason=activation.revocation_reason,
                token=None,
            )
            self._activation_tokens[token_hash] = consumed
            self._persist_locked()
            return consumed, TokenStatus.CONSUMED

    def reset_activation_token_redemption(self, token: str) -> bool:
        token_hash = self.hash_activation_token(token)
        with self._lock:
            activation = self._activation_tokens.get(token_hash)
            if not activation:
                return False
            if activation.redeemed_at is None:
                return False
            if activation.revoked_at is not None:
                return False
            restored = ActivationToken(
                token_hash=activation.token_hash,
                session_id=activation.session_id,
                draft_org_id=activation.draft_org_id,
                expires_at=activation.expires_at,
                created_at=activation.created_at,
                redeemed_at=None,
                revoked_at=None,
                revocation_reason=None,
                token=None,
            )
            self._activation_tokens[token_hash] = restored
            self._persist_locked()
            return True

    def create_signup_challenge(
        self,
        *,
        activation_token: str,
        email: str,
        password_hash: str,
        code_hash: str,
        code_salt: str,
        ttl_minutes: int = 10,
        max_attempts: int = 5,
    ) -> SignupChallenge | None:
        self._purge_expired()
        activation_token_hash = self.hash_activation_token(activation_token)
        activation = self._activation_tokens.get(activation_token_hash)
        if not activation:
            return None
        now = datetime.now(timezone.utc)
        if activation.revoked_at is not None or activation.redeemed_at is not None or activation.expires_at <= now:
            return None
        expires_at = min(activation.expires_at, now + timedelta(minutes=ttl_minutes))
        with self._lock:
            self._revoke_signup_challenges_for_activation_hash_locked(activation_token_hash, "superseded", now)
            for _ in range(5):
                challenge_id = secrets.token_urlsafe(24)
                if challenge_id in self._signup_challenges:
                    continue
                challenge = SignupChallenge(
                    id=challenge_id,
                    activation_token_hash=activation_token_hash,
                    session_id=activation.session_id,
                    email=email,
                    password_hash=password_hash,
                    code_hash=code_hash,
                    code_salt=code_salt,
                    expires_at=expires_at,
                    created_at=now,
                    attempt_count=0,
                    max_attempts=max_attempts,
                )
                self._signup_challenges[challenge_id] = challenge
                self._persist_locked()
                return challenge
        raise RuntimeError("Failed to generate unique signup challenge IDs")

    def get_signup_challenge(self, challenge_id: str) -> SignupChallenge | None:
        self._purge_expired()
        return self._signup_challenges.get(challenge_id)

    def get_signup_challenge_status(self, challenge_id: str) -> str:
        self._purge_expired()
        challenge = self._signup_challenges.get(challenge_id)
        if not challenge:
            return "missing"
        if challenge.used_at is not None:
            return "used"
        if challenge.revoked_at is not None:
            return "revoked"
        if challenge.expires_at <= datetime.now(timezone.utc):
            return "expired"
        if challenge.attempt_count >= challenge.max_attempts:
            return "locked"
        return "active"

    def increment_signup_challenge_attempt(self, challenge_id: str) -> SignupChallenge | None:
        self._purge_expired()
        now = datetime.now(timezone.utc)
        with self._lock:
            challenge = self._signup_challenges.get(challenge_id)
            if not challenge:
                return None
            if challenge.used_at is not None or challenge.revoked_at is not None or challenge.expires_at <= now:
                return challenge
            updated = SignupChallenge(
                id=challenge.id,
                activation_token_hash=challenge.activation_token_hash,
                session_id=challenge.session_id,
                email=challenge.email,
                password_hash=challenge.password_hash,
                code_hash=challenge.code_hash,
                code_salt=challenge.code_salt,
                expires_at=challenge.expires_at,
                created_at=challenge.created_at,
                attempt_count=challenge.attempt_count + 1,
                max_attempts=challenge.max_attempts,
                used_at=challenge.used_at,
                revoked_at=challenge.revoked_at,
                revocation_reason=challenge.revocation_reason,
            )
            self._signup_challenges[challenge_id] = updated
            self._persist_locked()
            return updated

    def mark_signup_challenge_used(self, challenge_id: str) -> tuple[SignupChallenge | None, str]:
        self._purge_expired()
        now = datetime.now(timezone.utc)
        with self._lock:
            challenge = self._signup_challenges.get(challenge_id)
            if not challenge:
                return None, "missing"
            if challenge.used_at is not None:
                return challenge, "used"
            if challenge.revoked_at is not None:
                return challenge, "revoked"
            if challenge.expires_at <= now:
                expired = SignupChallenge(
                    id=challenge.id,
                    activation_token_hash=challenge.activation_token_hash,
                    session_id=challenge.session_id,
                    email=challenge.email,
                    password_hash=challenge.password_hash,
                    code_hash=challenge.code_hash,
                    code_salt=challenge.code_salt,
                    expires_at=challenge.expires_at,
                    created_at=challenge.created_at,
                    attempt_count=challenge.attempt_count,
                    max_attempts=challenge.max_attempts,
                    used_at=challenge.used_at,
                    revoked_at=now,
                    revocation_reason="challenge_expired",
                )
                self._signup_challenges[challenge_id] = expired
                self._persist_locked()
                return expired, "expired"
            if challenge.attempt_count >= challenge.max_attempts:
                return challenge, "locked"
            used = SignupChallenge(
                id=challenge.id,
                activation_token_hash=challenge.activation_token_hash,
                session_id=challenge.session_id,
                email=challenge.email,
                password_hash=challenge.password_hash,
                code_hash=challenge.code_hash,
                code_salt=challenge.code_salt,
                expires_at=challenge.expires_at,
                created_at=challenge.created_at,
                attempt_count=challenge.attempt_count,
                max_attempts=challenge.max_attempts,
                used_at=now,
                revoked_at=challenge.revoked_at,
                revocation_reason=challenge.revocation_reason,
            )
            self._signup_challenges[challenge_id] = used
            self._persist_locked()
            return used, "used"

    def reset_signup_challenge_use(self, challenge_id: str) -> bool:
        with self._lock:
            challenge = self._signup_challenges.get(challenge_id)
            if not challenge:
                return False
            if challenge.used_at is None:
                return False
            if challenge.revoked_at is not None:
                return False
            restored = SignupChallenge(
                id=challenge.id,
                activation_token_hash=challenge.activation_token_hash,
                session_id=challenge.session_id,
                email=challenge.email,
                password_hash=challenge.password_hash,
                code_hash=challenge.code_hash,
                code_salt=challenge.code_salt,
                expires_at=challenge.expires_at,
                created_at=challenge.created_at,
                attempt_count=challenge.attempt_count,
                max_attempts=challenge.max_attempts,
                used_at=None,
                revoked_at=None,
                revocation_reason=None,
            )
            self._signup_challenges[challenge_id] = restored
            self._persist_locked()
            return True

    def revoke_signup_challenges_for_activation(self, activation_token: str, reason: str) -> int:
        now = datetime.now(timezone.utc)
        activation_token_hash = self.hash_activation_token(activation_token)
        with self._lock:
            revoked = self._revoke_signup_challenges_for_activation_hash_locked(activation_token_hash, reason, now)
            if revoked:
                self._persist_locked()
            return revoked

    def record_audit_event(self, event_type: str, session_id: str, details: dict[str, Any] | None = None) -> AuditEvent:
        event = AuditEvent(
            event_type=event_type,
            session_id=session_id,
            created_at=datetime.now(timezone.utc),
            details=details,
        )
        with self._lock:
            self._record_audit_event_locked(event)
        return event

    def _record_audit_event_locked(self, event: AuditEvent) -> None:
        self._audit_events.append(event)
        self._persist_locked()

    def get_audit_events(self, session_id: str | None = None, event_type: str | None = None) -> list[AuditEvent]:
        with self._lock:
            events = list(self._audit_events)
        if session_id is not None:
            events = [event for event in events if event.session_id == session_id]
        if event_type is not None:
            events = [event for event in events if event.event_type == event_type]
        return events

    def revoke_activation_tokens_for_session(self, session_id: str, reason: str) -> int:
        now = datetime.now(timezone.utc)
        with self._lock:
            revoked = self._revoke_activation_tokens_for_session_locked(session_id, reason, now)
            if revoked:
                self._persist_locked()
            return revoked

    def _revoke_activation_tokens_for_session_locked(
        self,
        session_id: str,
        reason: str,
        now: datetime | None = None,
    ) -> int:
        ts = now or datetime.now(timezone.utc)
        revoked = 0
        for token_key, token in list(self._activation_tokens.items()):
            if token.session_id != session_id:
                continue
            if token.redeemed_at is not None or token.revoked_at is not None:
                continue
            self._activation_tokens[token_key] = ActivationToken(
                token_hash=token.token_hash,
                session_id=token.session_id,
                draft_org_id=token.draft_org_id,
                expires_at=token.expires_at,
                created_at=token.created_at,
                redeemed_at=token.redeemed_at,
                revoked_at=ts,
                revocation_reason=reason,
                token=None,
            )
            revoked += 1
        return revoked

    def _revoke_signup_challenges_for_activation_hash_locked(
        self,
        activation_token_hash: str,
        reason: str,
        now: datetime | None = None,
    ) -> int:
        ts = now or datetime.now(timezone.utc)
        revoked = 0
        for challenge_id, challenge in list(self._signup_challenges.items()):
            if challenge.activation_token_hash != activation_token_hash:
                continue
            if challenge.used_at is not None or challenge.revoked_at is not None:
                continue
            self._signup_challenges[challenge_id] = SignupChallenge(
                id=challenge.id,
                activation_token_hash=challenge.activation_token_hash,
                session_id=challenge.session_id,
                email=challenge.email,
                password_hash=challenge.password_hash,
                code_hash=challenge.code_hash,
                code_salt=challenge.code_salt,
                expires_at=challenge.expires_at,
                created_at=challenge.created_at,
                attempt_count=challenge.attempt_count,
                max_attempts=challenge.max_attempts,
                used_at=challenge.used_at,
                revoked_at=ts,
                revocation_reason=reason,
            )
            revoked += 1
        return revoked

    def _purge_expired(self) -> None:
        now = datetime.now(timezone.utc)
        with self._lock:
            changed = False
            expired_sessions = [sid for sid, s in self._sessions.items() if s.expires_at <= now]
            for sid in expired_sessions:
                draft_org_id = self._sessions[sid].draft_org_id
                revoked = self._revoke_activation_tokens_for_session_locked(sid, "session_expired", now)
                revoked_challenges = 0
                for token in self._activation_tokens.values():
                    if token.session_id != sid:
                        continue
                    revoked_challenges += self._revoke_signup_challenges_for_activation_hash_locked(
                        token.token_hash,
                        "session_expired",
                        now,
                    )
                if revoked or revoked_challenges:
                    changed = True
                self._record_audit_event_locked(
                    AuditEvent(
                        event_type="pretenant_session_expired",
                        session_id=sid,
                        created_at=now,
                        details={
                            "reason": "ttl_expired",
                            "revoked_activation_tokens": revoked,
                            "revoked_signup_challenges": revoked_challenges,
                        },
                    )
                )
                self._expired[sid] = self._sessions[sid].expires_at
                self._sessions.pop(sid, None)
                self._orgs.pop(draft_org_id, None)
                self._verified_org_profiles.pop(sid, None)
                changed = True
            for token_key, token in list(self._activation_tokens.items()):
                if token.redeemed_at is not None or token.revoked_at is not None:
                    continue
                if token.expires_at > now:
                    continue
                self._activation_tokens[token_key] = ActivationToken(
                    token_hash=token.token_hash,
                    session_id=token.session_id,
                    draft_org_id=token.draft_org_id,
                    expires_at=token.expires_at,
                    created_at=token.created_at,
                    redeemed_at=token.redeemed_at,
                    revoked_at=now,
                    revocation_reason="token_expired",
                    token=None,
                )
                changed = True
            for challenge_id, challenge in list(self._signup_challenges.items()):
                if challenge.used_at is None and challenge.revoked_at is None and challenge.expires_at <= now:
                    self._signup_challenges[challenge_id] = SignupChallenge(
                        id=challenge.id,
                        activation_token_hash=challenge.activation_token_hash,
                        session_id=challenge.session_id,
                        email=challenge.email,
                        password_hash=challenge.password_hash,
                        code_hash=challenge.code_hash,
                        code_salt=challenge.code_salt,
                        expires_at=challenge.expires_at,
                        created_at=challenge.created_at,
                        attempt_count=challenge.attempt_count,
                        max_attempts=challenge.max_attempts,
                        used_at=challenge.used_at,
                        revoked_at=now,
                        revocation_reason="challenge_expired",
                    )
                    changed = True
            if self._signup_challenges:
                retention_minutes = self.ttl_minutes if self.ttl_minutes > 0 else 5
                challenge_cutoff = now - timedelta(minutes=retention_minutes)
                stale_challenges = [
                    challenge_id
                    for challenge_id, challenge in self._signup_challenges.items()
                    if (
                        challenge.used_at is not None
                        and challenge.used_at <= challenge_cutoff
                    )
                    or (
                        challenge.revoked_at is not None
                        and challenge.revoked_at <= challenge_cutoff
                    )
                ]
                for challenge_id in stale_challenges:
                    self._signup_challenges.pop(challenge_id, None)
                    changed = True
            if self._expired:
                retention_minutes = self.ttl_minutes if self.ttl_minutes > 0 else 5
                expired_cutoff = now - timedelta(minutes=retention_minutes)
                stale_expired = [sid for sid, expires_at in self._expired.items() if expires_at <= expired_cutoff]
                for sid in stale_expired:
                    self._expired.pop(sid, None)
                    changed = True
            if changed:
                self._persist_locked()

PRETENANT_STORE = PreTenantStore(
    persistence_path=_resolve_persistence_path(),
    activation_token_ttl_minutes=_resolve_activation_token_ttl_minutes(),
)

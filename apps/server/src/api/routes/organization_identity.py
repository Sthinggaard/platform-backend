"""Organisation Identity Setup routes — post-signup identity confirmation & scoping.

Sits ahead of Leadership Authorisation in the onboarding readiness sequence.
Mutations require the platform ``org_admin``/``admin`` role (this stage
precedes any Business Process/Service-scoped mandate, so the
``CanonicalMandateRole`` system does not apply here), following the same
``_require_org_admin`` pattern as ``leadership_authorization.py``.
"""

from __future__ import annotations

from fastapi import APIRouter, Depends
from pydantic import BaseModel
from sqlalchemy.orm import Session

from src.api.middleware.tenant_context import TenantContext, get_tenant_context
from src.core.constants.organization_identity_enums import (
    OPERATING_CONTEXT_AUDIT_EVENTS,
    ORG_IDENTITY_AUDIT_CONFIRMED,
    ORG_IDENTITY_AUDIT_CORRECTED,
    ORG_IDENTITY_AUDIT_DOMAIN_ADDED,
    ORG_IDENTITY_AUDIT_DOMAIN_VERIFIED,
    ORG_IDENTITY_AUDIT_ENTITY_ADDED,
    ORG_IDENTITY_AUDIT_ENTITY_CONFIRMED,
    ORG_IDENTITY_AUDIT_ENTITY_EXCLUDED,
    ORG_IDENTITY_AUDIT_EVIDENCE_IMPORTED,
    ORG_IDENTITY_AUDIT_REGISTRY_LOOKUP_REQUESTED,
    ORG_IDENTITY_AUDIT_SCOPE_CONFIRMED,
    ORG_IDENTITY_AUDIT_SCOPE_CREATED,
    ORG_IDENTITY_AUDIT_SETUP_COMPLETED,
    ORG_IDENTITY_ERROR_ADMIN_REQUIRED,
    ORG_IDENTITY_ERROR_DOMAIN_NOT_FOUND,
    ORG_IDENTITY_ERROR_ENTITY_NOT_FOUND,
    ORG_IDENTITY_ERROR_NOT_FOUND,
    ORG_IDENTITY_ERROR_OPERATING_CONTEXT_DECISION_REQUIRED,
    ORG_IDENTITY_ERROR_OPERATING_CONTEXT_NOT_FOUND,
    ORG_IDENTITY_ERROR_SCOPE_NOT_FOUND,
    OrganizationDomainType,
    OrganizationEntityType,
    OrganizationOperatingContextSuggestionType,
    OrganizationScopeType,
    OrganizationType,
    RegistryLookupStatus,
    SuggestionDecision,
)
from src.core.database import get_db
from src.core.exceptions import AuthorizationError, ResourceNotFoundError, ValidationError
from src.core.model_defs.organization_identity import (
    OrganizationDomain,
    OrganizationIdentityConfirmation,
    OrganizationLegalEntity,
    OrganizationOperatingContextSuggestion,
    OrganizationScope,
)
from src.core.models import AuditEvent, Organization, User
from src.core.repository import TenantRepository
from src.core.roles import ADMIN_ROLES
from src.core.services.organization_identity_readiness_service import (
    build_prepared_organisation_identity,
    evaluate_identity_readiness,
    get_signup_identity_context,
)
from src.core.services.organization_identity_service import (
    OrganizationIdentityRegistryLookupError,
    OrganizationIdentityValidationError,
    add_domain,
    confirm_legal_entity,
    confirm_organization_identity,
    confirm_scope,
    create_legal_entity,
    create_scope,
    exclude_legal_entity,
    get_active_identity_confirmation,
    record_manual_identity_evidence,
    run_registry_lookup,
    upsert_primary_legal_entity,
    verify_domain,
)
from src.core.services.organization_operating_context_service import (
    add_operating_context_suggestion,
    decide_operating_context_suggestion,
    list_current_operating_context_suggestions,
    prepare_operating_context_suggestions,
)
from src.api.schemas.timestamps import UtcTimestamp

router = APIRouter(prefix="/api/v1/organization-identity", tags=["Organisation identity"])


class RegistryLookupRequest(BaseModel):
    registration_country: str
    registration_number: str


class ManualEvidenceRequest(BaseModel):
    legal_name: str
    registration_country: str


class SignupContextResponse(BaseModel):
    has_data: bool
    legal_name: str | None = None
    registration_number: str | None = None
    registration_country: str | None = None
    industry_code: str | None = None
    industry_label: str | None = None


class EvidenceResponse(BaseModel):
    id: str
    source_type: str
    source_reference: str | None = None
    raw_legal_name: str | None = None
    raw_industry_code: str | None = None
    raw_legal_form: str | None = None


class RegistryLookupResponse(BaseModel):
    status: RegistryLookupStatus
    evidence: EvidenceResponse | None = None
    candidates: list[EvidenceResponse] = []
    message: str | None = None


class ConfirmIdentityRequest(BaseModel):
    legal_name: str
    registration_country: str
    organization_type: OrganizationType
    evidence_id: str | None = None
    correction_reason: str | None = None


class IdentityConfirmationResponse(BaseModel):
    id: str
    status: str
    version: int
    confirmed_legal_name: str | None = None
    confirmed_registration_country: str | None = None
    confirmed_organization_type: str | None = None
    confirmed_by_user_id: int | None = None
    correction_reason: str | None = None
    backfilled: bool


class LegalEntityRequest(BaseModel):
    legal_name: str
    registration_country: str
    entity_type: OrganizationEntityType
    registration_number: str | None = None
    is_primary: bool = False
    parent_entity_id: str | None = None
    source_evidence_id: str | None = None


class LegalEntityResponse(BaseModel):
    id: str
    legal_name: str
    registration_number: str | None = None
    registration_country: str
    entity_type: str
    status: str
    is_primary: bool
    parent_entity_id: str | None = None


class PrimaryLegalEntityRequest(BaseModel):
    legal_name: str
    registration_country: str
    registration_number: str | None = None
    source_evidence_id: str | None = None


class ScopeRequest(BaseModel):
    scope_type: OrganizationScopeType
    name: str
    description: str | None = None
    included_entity_ids: list[str] = []
    excluded_entity_ids: list[str] = []
    included_countries: list[str] = []


class ScopeResponse(BaseModel):
    id: str
    scope_type: str
    name: str
    description: str | None = None
    status: str
    included_entity_ids: list[str] = []
    excluded_entity_ids: list[str] = []
    included_countries: list[str] = []


class DomainRequest(BaseModel):
    domain: str
    domain_type: OrganizationDomainType


class DomainResponse(BaseModel):
    id: str
    domain: str
    domain_type: str
    verification_status: str
    verification_method: str | None = None
    verified_by_user_id: int | None = None
    verified_at: UtcTimestamp | None = None


class OperatingContextSuggestionRequest(BaseModel):
    suggestion_type: OrganizationOperatingContextSuggestionType
    suggestion_key: str


class OperatingContextDecisionRequest(BaseModel):
    status: SuggestionDecision


class OperatingContextSuggestionResponse(BaseModel):
    id: str
    suggestion_type: str
    suggestion_key: str
    source_type: str
    source_reference: str | None = None
    status: str
    decided_by_user_id: int | None = None
    decided_at: UtcTimestamp | None = None


class ActiveIdentityConfirmationResponse(BaseModel):
    resolved: bool
    confirmation: IdentityConfirmationResponse | None = None


class ReadinessResponse(BaseModel):
    ready: bool
    readiness: str
    missing_reasons: list[str]


class EntityContextResponse(BaseModel):
    included_entity_ids: list[str]
    known_related_entity_ids: list[str]
    excluded_entity_ids: list[str]
    included_countries: list[str]


class IndustryContextResponse(BaseModel):
    registry_industry: str | None
    confirmed_archetypes: list[str]
    confirmed_operating_characteristics: list[str]
    unresolved_suggestions: int


class PreparedIdentityResponse(BaseModel):
    organization_id: int
    primary_entity_id: str | None
    confirmed_scope_id: str | None
    legal_name: str | None
    registration_number: str | None
    registration_country: str | None
    verified_domains: list[str]
    unverified_domains: list[str]
    entity_context: EntityContextResponse
    industry_context: IndustryContextResponse
    readiness: str


def _require_org_admin(db: Session, ctx: TenantContext) -> None:
    user = TenantRepository(db, User, ctx.organization_id).get_by_id(ctx.user_id)
    if user is None or not user.is_active or user.role not in ADMIN_ROLES:
        raise AuthorizationError(ORG_IDENTITY_ERROR_ADMIN_REQUIRED)


def _write_audit(db: Session, *, ctx: TenantContext, event_type: str, metadata: dict) -> None:
    db.add(
        AuditEvent(
            organization_id=ctx.organization_id,
            actor_user_id=ctx.user_id,
            event_type=event_type,
            metadata_json=metadata,
        )
    )


def _confirmation_response(
    confirmation: OrganizationIdentityConfirmation,
) -> IdentityConfirmationResponse:
    return IdentityConfirmationResponse(
        id=confirmation.id,
        status=confirmation.status,
        version=confirmation.version,
        confirmed_legal_name=confirmation.confirmed_legal_name,
        confirmed_registration_country=confirmation.confirmed_registration_country,
        confirmed_organization_type=confirmation.confirmed_organization_type,
        confirmed_by_user_id=confirmation.confirmed_by_user_id,
        correction_reason=confirmation.correction_reason,
        backfilled=bool(confirmation.backfilled),
    )


def _entity_response(entity: OrganizationLegalEntity) -> LegalEntityResponse:
    return LegalEntityResponse(
        id=entity.id,
        legal_name=entity.legal_name,
        registration_number=entity.registration_number,
        registration_country=entity.registration_country,
        entity_type=entity.entity_type,
        status=entity.status,
        is_primary=entity.is_primary,
        parent_entity_id=entity.parent_entity_id,
    )


def _scope_response(scope: OrganizationScope) -> ScopeResponse:
    return ScopeResponse(
        id=scope.id,
        scope_type=scope.scope_type,
        name=scope.name,
        description=scope.description,
        status=scope.status,
        included_entity_ids=scope.included_entity_ids or [],
        excluded_entity_ids=scope.excluded_entity_ids or [],
        included_countries=scope.included_countries or [],
    )


def _domain_response(domain: OrganizationDomain) -> DomainResponse:
    return DomainResponse(
        id=domain.id,
        domain=domain.domain,
        domain_type=domain.domain_type,
        verification_status=domain.verification_status,
        verification_method=domain.verification_method,
        verified_by_user_id=domain.verified_by_user_id,
        verified_at=domain.verified_at.isoformat() if domain.verified_at else None,
    )


def _operating_context_response(
    suggestion: OrganizationOperatingContextSuggestion,
) -> OperatingContextSuggestionResponse:
    return OperatingContextSuggestionResponse(
        id=suggestion.id,
        suggestion_type=suggestion.suggestion_type,
        suggestion_key=suggestion.suggestion_key,
        source_type=suggestion.source_type,
        source_reference=suggestion.source_reference,
        status=suggestion.status,
        decided_by_user_id=suggestion.decided_by_user_id,
        decided_at=suggestion.decided_at.isoformat() if suggestion.decided_at else None,
    )


@router.get("/signup-context", response_model=SignupContextResponse)
def get_signup_context(
    ctx: TenantContext = Depends(get_tenant_context),
    db: Session = Depends(get_db),
) -> SignupContextResponse:
    """Identity facts already captured during pretenant signup. This stage
    reviews and confirms these — it never asks the user to search for or
    re-enter an organisation Risklence has already identified."""
    context = get_signup_identity_context(db, ctx.organization_id)
    return SignupContextResponse(
        has_data=context.has_data,
        legal_name=context.legal_name,
        registration_number=context.registration_number,
        registration_country=context.registration_country,
        industry_code=context.industry_code,
        industry_label=context.industry_label,
    )


@router.post("/registry-lookup", response_model=RegistryLookupResponse)
def registry_lookup(
    body: RegistryLookupRequest,
    ctx: TenantContext = Depends(get_tenant_context),
    db: Session = Depends(get_db),
) -> RegistryLookupResponse:
    _require_org_admin(db, ctx)
    _write_audit(
        db,
        ctx=ctx,
        event_type=ORG_IDENTITY_AUDIT_REGISTRY_LOOKUP_REQUESTED,
        metadata={"registration_country": body.registration_country},
    )
    try:
        evidence = run_registry_lookup(
            db,
            organization_id=ctx.organization_id,
            registration_country=body.registration_country,
            registration_number=body.registration_number,
        )
    except OrganizationIdentityRegistryLookupError as exc:
        for candidate in exc.candidates:
            _write_audit(
                db,
                ctx=ctx,
                event_type=ORG_IDENTITY_AUDIT_EVIDENCE_IMPORTED,
                metadata={"evidence_id": candidate.id, "source_type": candidate.source_type},
            )
        db.commit()
        return RegistryLookupResponse(
            status=exc.status,
            candidates=[
                EvidenceResponse(
                    id=candidate.id,
                    source_type=candidate.source_type,
                    source_reference=candidate.source_reference,
                    raw_legal_name=candidate.raw_legal_name,
                    raw_industry_code=candidate.raw_industry_code,
                    raw_legal_form=candidate.raw_legal_form,
                )
                for candidate in exc.candidates
            ],
            message=str(exc),
        )
    except OrganizationIdentityValidationError as exc:
        raise ValidationError(str(exc)) from exc
    _write_audit(
        db,
        ctx=ctx,
        event_type=ORG_IDENTITY_AUDIT_EVIDENCE_IMPORTED,
        metadata={"evidence_id": evidence.id, "source_type": evidence.source_type},
    )
    db.commit()
    db.refresh(evidence)
    return RegistryLookupResponse(
        status=RegistryLookupStatus.MATCH,
        evidence=EvidenceResponse(
            id=evidence.id,
            source_type=evidence.source_type,
            source_reference=evidence.source_reference,
            raw_legal_name=evidence.raw_legal_name,
            raw_industry_code=evidence.raw_industry_code,
            raw_legal_form=evidence.raw_legal_form,
        ),
    )


@router.post("/manual-evidence", response_model=EvidenceResponse)
def manual_evidence(
    body: ManualEvidenceRequest,
    ctx: TenantContext = Depends(get_tenant_context),
    db: Session = Depends(get_db),
) -> EvidenceResponse:
    _require_org_admin(db, ctx)
    try:
        evidence = record_manual_identity_evidence(
            db,
            organization_id=ctx.organization_id,
            legal_name=body.legal_name,
            registration_country=body.registration_country,
        )
    except OrganizationIdentityValidationError as exc:
        raise ValidationError(str(exc)) from exc
    _write_audit(
        db,
        ctx=ctx,
        event_type=ORG_IDENTITY_AUDIT_EVIDENCE_IMPORTED,
        metadata={"evidence_id": evidence.id, "source_type": evidence.source_type},
    )
    db.commit()
    db.refresh(evidence)
    return EvidenceResponse(
        id=evidence.id, source_type=evidence.source_type, raw_legal_name=evidence.raw_legal_name
    )


@router.post("/confirm", response_model=IdentityConfirmationResponse)
def confirm_identity(
    body: ConfirmIdentityRequest,
    ctx: TenantContext = Depends(get_tenant_context),
    db: Session = Depends(get_db),
) -> IdentityConfirmationResponse:
    _require_org_admin(db, ctx)
    is_correction = get_active_identity_confirmation(db, ctx.organization_id) is not None
    try:
        confirmation = confirm_organization_identity(
            db,
            organization_id=ctx.organization_id,
            confirmed_by_user_id=ctx.user_id,
            legal_name=body.legal_name,
            registration_country=body.registration_country,
            organization_type=body.organization_type,
            evidence_id=body.evidence_id,
            correction_reason=body.correction_reason,
        )
    except OrganizationIdentityValidationError as exc:
        raise ValidationError(str(exc)) from exc
    _write_audit(
        db,
        ctx=ctx,
        event_type=ORG_IDENTITY_AUDIT_CORRECTED if is_correction else ORG_IDENTITY_AUDIT_CONFIRMED,
        metadata={"confirmation_id": confirmation.id, "version": confirmation.version},
    )
    db.commit()
    db.refresh(confirmation)
    return _confirmation_response(confirmation)


@router.get("/confirmation", response_model=ActiveIdentityConfirmationResponse)
def get_confirmation(
    ctx: TenantContext = Depends(get_tenant_context),
    db: Session = Depends(get_db),
) -> ActiveIdentityConfirmationResponse:
    confirmation = get_active_identity_confirmation(db, ctx.organization_id)
    if confirmation is None:
        return ActiveIdentityConfirmationResponse(resolved=False)
    return ActiveIdentityConfirmationResponse(
        resolved=True, confirmation=_confirmation_response(confirmation)
    )


@router.get("/entities", response_model=list[LegalEntityResponse])
def list_entities(
    ctx: TenantContext = Depends(get_tenant_context),
    db: Session = Depends(get_db),
) -> list[LegalEntityResponse]:
    entities = (
        db.query(OrganizationLegalEntity)
        .filter(OrganizationLegalEntity.organization_id == ctx.organization_id)
        .order_by(OrganizationLegalEntity.created_at.asc())
        .all()
    )
    return [_entity_response(e) for e in entities]


@router.post("/entities", response_model=LegalEntityResponse)
def add_entity(
    body: LegalEntityRequest,
    ctx: TenantContext = Depends(get_tenant_context),
    db: Session = Depends(get_db),
) -> LegalEntityResponse:
    _require_org_admin(db, ctx)
    try:
        entity = create_legal_entity(
            db,
            organization_id=ctx.organization_id,
            legal_name=body.legal_name,
            registration_country=body.registration_country,
            entity_type=body.entity_type,
            registration_number=body.registration_number,
            is_primary=body.is_primary,
            parent_entity_id=body.parent_entity_id,
            source_evidence_id=body.source_evidence_id,
        )
    except OrganizationIdentityValidationError as exc:
        raise ValidationError(str(exc)) from exc
    _write_audit(
        db, ctx=ctx, event_type=ORG_IDENTITY_AUDIT_ENTITY_ADDED, metadata={"entity_id": entity.id}
    )
    db.commit()
    db.refresh(entity)
    return _entity_response(entity)


@router.post("/entities/primary", response_model=LegalEntityResponse)
def upsert_primary_entity(
    body: PrimaryLegalEntityRequest,
    ctx: TenantContext = Depends(get_tenant_context),
    db: Session = Depends(get_db),
) -> LegalEntityResponse:
    """Confirm the one legal entity that represents the organisation identity.

    This differs from generic entity creation: retries and corrections update
    the existing primary record, preserving a single unambiguous root.
    """
    _require_org_admin(db, ctx)
    try:
        entity, created = upsert_primary_legal_entity(
            db,
            organization_id=ctx.organization_id,
            legal_name=body.legal_name,
            registration_country=body.registration_country,
            registration_number=body.registration_number,
            source_evidence_id=body.source_evidence_id,
        )
    except OrganizationIdentityValidationError as exc:
        raise ValidationError(str(exc)) from exc
    if created:
        _write_audit(
            db,
            ctx=ctx,
            event_type=ORG_IDENTITY_AUDIT_ENTITY_ADDED,
            metadata={"entity_id": entity.id},
        )
    _write_audit(
        db,
        ctx=ctx,
        event_type=ORG_IDENTITY_AUDIT_ENTITY_CONFIRMED,
        metadata={"entity_id": entity.id, "created": created},
    )
    db.commit()
    db.refresh(entity)
    return _entity_response(entity)


def _require_entity(db: Session, *, ctx: TenantContext, entity_id: str) -> OrganizationLegalEntity:
    entity = TenantRepository(db, OrganizationLegalEntity, ctx.organization_id).get_by_id(entity_id)
    if entity is None:
        raise ResourceNotFoundError(ORG_IDENTITY_ERROR_ENTITY_NOT_FOUND)
    return entity


@router.post("/entities/{entity_id}/confirm", response_model=LegalEntityResponse)
def confirm_entity(
    entity_id: str,
    ctx: TenantContext = Depends(get_tenant_context),
    db: Session = Depends(get_db),
) -> LegalEntityResponse:
    _require_org_admin(db, ctx)
    entity = _require_entity(db, ctx=ctx, entity_id=entity_id)
    confirm_legal_entity(db, entity)
    _write_audit(
        db,
        ctx=ctx,
        event_type=ORG_IDENTITY_AUDIT_ENTITY_CONFIRMED,
        metadata={"entity_id": entity.id},
    )
    db.commit()
    db.refresh(entity)
    return _entity_response(entity)


@router.post("/entities/{entity_id}/exclude", response_model=LegalEntityResponse)
def exclude_entity(
    entity_id: str,
    ctx: TenantContext = Depends(get_tenant_context),
    db: Session = Depends(get_db),
) -> LegalEntityResponse:
    _require_org_admin(db, ctx)
    entity = _require_entity(db, ctx=ctx, entity_id=entity_id)
    exclude_legal_entity(db, entity)
    _write_audit(
        db,
        ctx=ctx,
        event_type=ORG_IDENTITY_AUDIT_ENTITY_EXCLUDED,
        metadata={"entity_id": entity.id},
    )
    db.commit()
    db.refresh(entity)
    return _entity_response(entity)


@router.get("/scopes", response_model=list[ScopeResponse])
def list_scopes(
    ctx: TenantContext = Depends(get_tenant_context),
    db: Session = Depends(get_db),
) -> list[ScopeResponse]:
    scopes = (
        db.query(OrganizationScope)
        .filter(OrganizationScope.organization_id == ctx.organization_id)
        .order_by(OrganizationScope.created_at.asc())
        .all()
    )
    return [_scope_response(s) for s in scopes]


@router.post("/scopes", response_model=ScopeResponse)
def add_scope(
    body: ScopeRequest,
    ctx: TenantContext = Depends(get_tenant_context),
    db: Session = Depends(get_db),
) -> ScopeResponse:
    _require_org_admin(db, ctx)
    try:
        scope = create_scope(
            db,
            organization_id=ctx.organization_id,
            scope_type=body.scope_type,
            name=body.name,
            description=body.description,
            included_entity_ids=body.included_entity_ids,
            excluded_entity_ids=body.excluded_entity_ids,
            included_countries=body.included_countries,
        )
    except OrganizationIdentityValidationError as exc:
        raise ValidationError(str(exc)) from exc
    _write_audit(
        db, ctx=ctx, event_type=ORG_IDENTITY_AUDIT_SCOPE_CREATED, metadata={"scope_id": scope.id}
    )
    db.commit()
    db.refresh(scope)
    return _scope_response(scope)


@router.post("/scopes/{scope_id}/confirm", response_model=ScopeResponse)
def confirm_scope_route(
    scope_id: str,
    ctx: TenantContext = Depends(get_tenant_context),
    db: Session = Depends(get_db),
) -> ScopeResponse:
    _require_org_admin(db, ctx)
    scope = TenantRepository(db, OrganizationScope, ctx.organization_id).get_by_id(scope_id)
    if scope is None:
        raise ResourceNotFoundError(ORG_IDENTITY_ERROR_SCOPE_NOT_FOUND)
    confirm_scope(db, scope, confirmed_by_user_id=ctx.user_id)
    _write_audit(
        db, ctx=ctx, event_type=ORG_IDENTITY_AUDIT_SCOPE_CONFIRMED, metadata={"scope_id": scope.id}
    )
    db.commit()
    db.refresh(scope)
    return _scope_response(scope)


@router.get("/domains", response_model=list[DomainResponse])
def list_domains(
    ctx: TenantContext = Depends(get_tenant_context),
    db: Session = Depends(get_db),
) -> list[DomainResponse]:
    domains = TenantRepository(db, OrganizationDomain, ctx.organization_id).get_all()
    domains.sort(key=lambda domain: domain.created_at)
    return [_domain_response(d) for d in domains]


@router.post("/domains", response_model=DomainResponse)
def add_domain_route(
    body: DomainRequest,
    ctx: TenantContext = Depends(get_tenant_context),
    db: Session = Depends(get_db),
) -> DomainResponse:
    _require_org_admin(db, ctx)
    try:
        domain = add_domain(
            db,
            organization_id=ctx.organization_id,
            domain=body.domain,
            domain_type=body.domain_type,
        )
    except OrganizationIdentityValidationError as exc:
        raise ValidationError(str(exc)) from exc
    _write_audit(
        db, ctx=ctx, event_type=ORG_IDENTITY_AUDIT_DOMAIN_ADDED, metadata={"domain_id": domain.id}
    )
    db.commit()
    db.refresh(domain)
    return _domain_response(domain)


@router.post("/domains/{domain_id}/verify", response_model=DomainResponse)
def verify_domain_route(
    domain_id: str,
    ctx: TenantContext = Depends(get_tenant_context),
    db: Session = Depends(get_db),
) -> DomainResponse:
    _require_org_admin(db, ctx)
    domain = TenantRepository(db, OrganizationDomain, ctx.organization_id).get_by_id(domain_id)
    if domain is None:
        raise ResourceNotFoundError(ORG_IDENTITY_ERROR_DOMAIN_NOT_FOUND)
    verify_domain(db, domain, verified_by_user_id=ctx.user_id, verification_method="manual")
    _write_audit(
        db,
        ctx=ctx,
        event_type=ORG_IDENTITY_AUDIT_DOMAIN_VERIFIED,
        metadata={"domain_id": domain.id},
    )
    db.commit()
    db.refresh(domain)
    return _domain_response(domain)


@router.post("/operating-context/prepare", response_model=list[OperatingContextSuggestionResponse])
def prepare_operating_context(
    ctx: TenantContext = Depends(get_tenant_context),
    db: Session = Depends(get_db),
) -> list[OperatingContextSuggestionResponse]:
    _require_org_admin(db, ctx)
    # Organization has no organization_id column (it IS the tenant, keyed by
    # its own id) — TenantRepository's contract requires that column (A1
    # security remediation, H2), so fetch the caller's own org directly
    # rather than route it through TenantRepository.
    organization = db.query(Organization).filter(Organization.id == ctx.organization_id).first()
    if organization is None:
        raise ResourceNotFoundError(ORG_IDENTITY_ERROR_NOT_FOUND)
    suggestions = prepare_operating_context_suggestions(db, organization)
    db.commit()
    return [_operating_context_response(suggestion) for suggestion in suggestions]


@router.get("/operating-context", response_model=list[OperatingContextSuggestionResponse])
def list_operating_context(
    ctx: TenantContext = Depends(get_tenant_context),
    db: Session = Depends(get_db),
) -> list[OperatingContextSuggestionResponse]:
    return [
        _operating_context_response(suggestion)
        for suggestion in list_current_operating_context_suggestions(db, ctx.organization_id)
    ]


@router.post("/operating-context", response_model=OperatingContextSuggestionResponse)
def add_operating_context(
    body: OperatingContextSuggestionRequest,
    ctx: TenantContext = Depends(get_tenant_context),
    db: Session = Depends(get_db),
) -> OperatingContextSuggestionResponse:
    _require_org_admin(db, ctx)
    try:
        suggestion = add_operating_context_suggestion(
            db,
            organization_id=ctx.organization_id,
            suggestion_type=body.suggestion_type,
            suggestion_key=body.suggestion_key,
        )
    except ValueError as exc:
        raise ValidationError(str(exc)) from exc
    db.commit()
    return _operating_context_response(suggestion)


@router.post(
    "/operating-context/{suggestion_id}/decision", response_model=OperatingContextSuggestionResponse
)
def decide_operating_context(
    suggestion_id: str,
    body: OperatingContextDecisionRequest,
    ctx: TenantContext = Depends(get_tenant_context),
    db: Session = Depends(get_db),
) -> OperatingContextSuggestionResponse:
    _require_org_admin(db, ctx)
    suggestion_repository = TenantRepository(
        db, OrganizationOperatingContextSuggestion, ctx.organization_id
    )
    suggestion = suggestion_repository.get_by_id(suggestion_id)
    if suggestion is None:
        raise ResourceNotFoundError(ORG_IDENTITY_ERROR_OPERATING_CONTEXT_NOT_FOUND)
    if body.status == SuggestionDecision.SUGGESTED:
        raise ValidationError(ORG_IDENTITY_ERROR_OPERATING_CONTEXT_DECISION_REQUIRED)
    if suggestion.superseded_by_id is not None:
        successor = suggestion_repository.get_by_id(suggestion.superseded_by_id)
        if successor is not None and successor.status == body.status.value:
            return _operating_context_response(successor)
        raise ResourceNotFoundError(ORG_IDENTITY_ERROR_OPERATING_CONTEXT_NOT_FOUND)
    decision = decide_operating_context_suggestion(
        db, suggestion, status=body.status, decided_by_user_id=ctx.user_id
    )
    event_type = OPERATING_CONTEXT_AUDIT_EVENTS[
        (
            OrganizationOperatingContextSuggestionType(decision.suggestion_type),
            SuggestionDecision(decision.status),
        )
    ]
    _write_audit(
        db,
        ctx=ctx,
        event_type=event_type,
        metadata={
            "suggestion_id": decision.id,
            "suggestion_key": decision.suggestion_key,
            "source_type": decision.source_type,
        },
    )
    db.commit()
    return _operating_context_response(decision)


@router.get("/readiness", response_model=ReadinessResponse)
def get_readiness(
    ctx: TenantContext = Depends(get_tenant_context),
    db: Session = Depends(get_db),
) -> ReadinessResponse:
    result = evaluate_identity_readiness(db, ctx.organization_id)
    return ReadinessResponse(
        ready=result.ready, readiness=result.readiness.value, missing_reasons=result.missing_reasons
    )


@router.get("/prepared", response_model=PreparedIdentityResponse)
def get_prepared_identity(
    ctx: TenantContext = Depends(get_tenant_context),
    db: Session = Depends(get_db),
) -> PreparedIdentityResponse:
    prepared = build_prepared_organisation_identity(db, ctx.organization_id)
    return PreparedIdentityResponse(
        organization_id=prepared.organization_id,
        primary_entity_id=prepared.primary_entity_id,
        confirmed_scope_id=prepared.confirmed_scope_id,
        legal_name=prepared.legal_name,
        registration_number=prepared.registration_number,
        registration_country=prepared.registration_country,
        verified_domains=prepared.verified_domains,
        unverified_domains=prepared.unverified_domains,
        entity_context=EntityContextResponse(
            included_entity_ids=prepared.entity_context.included_entity_ids,
            known_related_entity_ids=prepared.entity_context.known_related_entity_ids,
            excluded_entity_ids=prepared.entity_context.excluded_entity_ids,
            included_countries=prepared.entity_context.included_countries,
        ),
        industry_context=IndustryContextResponse(
            registry_industry=prepared.industry_context.registry_industry,
            confirmed_archetypes=prepared.industry_context.confirmed_archetypes,
            confirmed_operating_characteristics=prepared.industry_context.confirmed_operating_characteristics,
            unresolved_suggestions=prepared.industry_context.unresolved_suggestions,
        ),
        readiness=prepared.readiness.value,
    )


@router.post("/complete", response_model=ReadinessResponse)
def complete_identity_setup(
    ctx: TenantContext = Depends(get_tenant_context),
    db: Session = Depends(get_db),
) -> ReadinessResponse:
    """Idempotent: records completion once readiness is genuinely satisfied,
    a no-op audit-wise if already recorded — never declares readiness that
    the evaluator itself disagrees with."""
    _require_org_admin(db, ctx)
    result = evaluate_identity_readiness(db, ctx.organization_id)
    if not result.ready:
        raise ValidationError(
            "Organisation identity is not yet ready to complete: "
            + ", ".join(result.missing_reasons)
        )
    _write_audit(
        db,
        ctx=ctx,
        event_type=ORG_IDENTITY_AUDIT_SETUP_COMPLETED,
        metadata={"organization_id": ctx.organization_id},
    )
    db.commit()
    return ReadinessResponse(
        ready=result.ready, readiness=result.readiness.value, missing_reasons=[]
    )

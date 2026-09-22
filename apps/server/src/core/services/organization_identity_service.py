"""Organisation Identity Setup — lifecycle and CRUD (post-signup stage).

Owns: identity evidence capture (a thin wrapper around the existing
``CvrEnrichmentClient`` — no new registry-lookup provider), the versioned
identity-confirmation lifecycle (mirrors ``leadership_authorization_service``
exactly: append-only, real ``User`` FK, ``superseded_by_id`` corrections),
and legal-entity/scope/domain management. Readiness evaluation and the
``PreparedOrganisationIdentity`` read model live in
``organization_identity_readiness_service`` (SRP).
"""

from __future__ import annotations

from sqlalchemy.orm import Session

from src.core.constants.organization_identity_enums import (
    OrganizationDomainType,
    OrganizationEntityStatus,
    OrganizationEntityType,
    OrganizationIdentityConfirmationStatus,
    OrganizationIdentityEvidenceSource,
    OrganizationScopeStatus,
    OrganizationScopeType,
    OrganizationType,
    RegistryLookupStatus,
)
from src.core.model_defs.common import utcnow
from src.core.model_defs.organization_identity import (
    OrganizationDomain,
    OrganizationIdentityConfirmation,
    OrganizationIdentityEvidence,
    OrganizationLegalEntity,
    OrganizationScope,
)
from src.core.model_defs.tenant_identity import User
from src.core.model_defs.tenant_org import Organization
from src.core.services.organization_registry_provider import (
    OrganisationRegistryProvider,
    RegistryLookupResult,
    RegistryProviderInactiveError,
    RegistryProviderMultipleMatchesError,
    RegistryProviderNotFoundError,
    RegistryProviderNotSupportedError,
    RegistryProviderUnavailableError,
    get_registry_provider_for_country,
)


class OrganizationIdentityValidationError(ValueError):
    """Raised when an organisation identity lifecycle transition is invalid."""


class OrganizationIdentityRegistryLookupError(OrganizationIdentityValidationError):
    """Typed registry outcome requiring user review or recovery."""

    def __init__(
        self,
        status: RegistryLookupStatus,
        message: str,
        candidates: list[OrganizationIdentityEvidence] | None = None,
    ):
        super().__init__(message)
        self.status = status
        self.candidates = candidates or []


class OrganizationIdentityRegistryUnavailableError(OrganizationIdentityRegistryLookupError):
    """Raised when the upstream registry provider times out or errors."""

    def __init__(self, message: str):
        super().__init__(RegistryLookupStatus.UNAVAILABLE, message)


def get_active_identity_confirmation(
    db: Session, organization_id: int
) -> OrganizationIdentityConfirmation | None:
    """Return the current confirmed identity for the org, if any."""
    return (
        db.query(OrganizationIdentityConfirmation)
        .filter(
            OrganizationIdentityConfirmation.organization_id == organization_id,
            OrganizationIdentityConfirmation.status
            == OrganizationIdentityConfirmationStatus.CONFIRMED.value,
        )
        .order_by(OrganizationIdentityConfirmation.version.desc())
        .first()
    )


def run_registry_lookup(
    db: Session,
    *,
    organization_id: int,
    registration_country: str,
    registration_number: str,
    provider: OrganisationRegistryProvider | None = None,
) -> OrganizationIdentityEvidence:
    """Look up the organisation's registry record and store it as evidence.

    Depends only on ``OrganisationRegistryProvider`` — the concrete provider
    is selected by ``registration_country`` via
    ``get_registry_provider_for_country`` when the caller doesn't supply one
    explicitly, so this function never hard-codes a single country's
    registry. A not-found, unavailable, or unsupported-country result is
    surfaced as a typed error so the caller can fall back to manual entry —
    it never fails silently into fabricated evidence.
    """
    if not registration_number.strip():
        raise OrganizationIdentityValidationError("A registration number is required.")
    try:
        active_provider = provider or get_registry_provider_for_country(registration_country)
        result = active_provider.lookup(registration_number.strip())
    except RegistryProviderNotFoundError as exc:
        raise OrganizationIdentityRegistryLookupError(
            RegistryLookupStatus.NO_MATCH,
            "No registry match was found. Enter the organisation manually.",
        ) from exc
    except RegistryProviderMultipleMatchesError as exc:
        candidates = [
            _record_registry_evidence(
                db,
                organization_id=organization_id,
                registration_country=registration_country,
                result=candidate,
            )
            for candidate in exc.candidates
        ]
        raise OrganizationIdentityRegistryLookupError(
            RegistryLookupStatus.MULTIPLE_MATCHES,
            "More than one registry match was found. Select the correct organisation, refine the registration number, or enter it manually.",
            candidates,
        ) from exc
    except RegistryProviderInactiveError as exc:
        raise OrganizationIdentityRegistryLookupError(
            RegistryLookupStatus.INACTIVE,
            "The registry record is inactive. Confirm the current legal identity manually.",
        ) from exc
    except RegistryProviderNotSupportedError as exc:
        raise OrganizationIdentityRegistryLookupError(
            RegistryLookupStatus.MANUAL_REQUIRED,
            "Registry lookup is not available for this country. Enter the organisation manually.",
        ) from exc
    except RegistryProviderUnavailableError as exc:
        raise OrganizationIdentityRegistryUnavailableError(str(exc)) from exc

    return _record_registry_evidence(
        db,
        organization_id=organization_id,
        registration_country=registration_country,
        result=result,
    )


def _record_registry_evidence(
    db: Session,
    *,
    organization_id: int,
    registration_country: str,
    result: RegistryLookupResult,
) -> OrganizationIdentityEvidence:
    """Persist the small, source-attributable fact set shown to a reviewer.

    Registry provider payloads remain outside normal domain tables; this only
    retains the reviewed facts and provider reference needed for provenance.
    """
    source_type = (
        OrganizationIdentityEvidenceSource.CVR.value
        if registration_country.strip().upper() == "DK"
        else OrganizationIdentityEvidenceSource.COMPANY_REGISTRY.value
    )
    evidence = OrganizationIdentityEvidence(
        organization_id=organization_id,
        source_type=source_type,
        source_reference=result.reference,
        observed_at=result.observed_at,
        raw_legal_name=result.legal_name,
        raw_industry_code=result.industry_code,
        raw_legal_form=result.legal_form,
        raw_address={
            "address": result.address,
            "postal_code": result.postal_code,
            "city": result.city,
            "country": result.country or registration_country,
        },
    )
    db.add(evidence)
    db.flush()
    return evidence


def record_manual_identity_evidence(
    db: Session,
    *,
    organization_id: int,
    legal_name: str,
    registration_country: str,
) -> OrganizationIdentityEvidence:
    """Record a user-entered identity fact set when no registry match exists."""
    if not legal_name.strip():
        raise OrganizationIdentityValidationError("A legal name is required.")
    evidence = OrganizationIdentityEvidence(
        organization_id=organization_id,
        source_type=OrganizationIdentityEvidenceSource.USER.value,
        observed_at=utcnow(),
        raw_legal_name=legal_name.strip(),
    )
    db.add(evidence)
    db.flush()
    return evidence


def _auto_evidence_from_signup(db: Session, organization_id: int) -> str | None:
    """Registry facts must remain attributable to their source. When this
    stage confirms identity without a fresh lookup — the common case, since
    pretenant signup already ran CvrEnrichmentClient and persisted the
    result on Organization — attach evidence pointing at that same CVR
    record rather than leaving the confirmation's provenance blank."""
    organization = db.query(Organization).filter(Organization.id == organization_id).first()
    if organization is None or not organization.cvr_number:
        return None
    existing = (
        db.query(OrganizationIdentityEvidence)
        .filter(
            OrganizationIdentityEvidence.organization_id == organization_id,
            OrganizationIdentityEvidence.source_reference == organization.cvr_number,
        )
        .first()
    )
    if existing is not None:
        return existing.id
    evidence = OrganizationIdentityEvidence(
        organization_id=organization_id,
        source_type=OrganizationIdentityEvidenceSource.CVR.value,
        source_reference=organization.cvr_number,
        observed_at=organization.created_at,
        raw_legal_name=organization.name,
        raw_industry_code=organization.nace_code,
    )
    db.add(evidence)
    db.flush()
    return evidence.id


def confirm_organization_identity(
    db: Session,
    *,
    organization_id: int,
    confirmed_by_user_id: int,
    legal_name: str,
    registration_country: str,
    organization_type: OrganizationType,
    evidence_id: str | None = None,
    correction_reason: str | None = None,
) -> OrganizationIdentityConfirmation:
    """Confirm (or correct) the organisation's identity.

    Mirrors ``approve_leadership_authorization_draft``'s supersede pattern:
    writing a new confirmed version supersedes the previous one rather than
    mutating it, so corrections retain full history and provenance. A
    correction reason is required whenever a previously confirmed record is
    being replaced (never required for the first confirmation).
    """
    if not legal_name.strip():
        raise OrganizationIdentityValidationError("A legal name is required.")
    if evidence_id is None:
        evidence_id = _auto_evidence_from_signup(db, organization_id)
    elif (
        db.query(OrganizationIdentityEvidence)
        .filter(
            OrganizationIdentityEvidence.id == evidence_id,
            OrganizationIdentityEvidence.organization_id == organization_id,
        )
        .first()
        is None
    ):
        raise OrganizationIdentityValidationError(
            "The identity evidence must belong to this organisation."
        )
    confirmer = (
        db.query(User)
        .filter(User.id == confirmed_by_user_id, User.organization_id == organization_id)
        .first()
    )
    if confirmer is None or not confirmer.is_active:
        raise OrganizationIdentityValidationError(
            "The confirming user must be an active user of this organisation."
        )

    predecessor = get_active_identity_confirmation(db, organization_id)
    if predecessor is not None and not (correction_reason or "").strip():
        raise OrganizationIdentityValidationError(
            "A reason is required to correct a confirmed organisation identity."
        )

    latest = (
        db.query(OrganizationIdentityConfirmation)
        .filter(OrganizationIdentityConfirmation.organization_id == organization_id)
        .order_by(OrganizationIdentityConfirmation.version.desc())
        .first()
    )
    confirmation = OrganizationIdentityConfirmation(
        organization_id=organization_id,
        status=OrganizationIdentityConfirmationStatus.CONFIRMED.value,
        version=(latest.version + 1) if latest else 1,
        confirmed_legal_name=legal_name.strip(),
        confirmed_registration_country=registration_country,
        confirmed_organization_type=organization_type.value,
        evidence_id=evidence_id,
        confirmed_by_user_id=confirmed_by_user_id,
        confirmed_at=utcnow(),
        correction_reason=(correction_reason or "").strip() or None,
    )
    if predecessor is not None:
        predecessor.status = OrganizationIdentityConfirmationStatus.SUPERSEDED.value
        db.add(predecessor)
    db.add(confirmation)
    db.flush()
    if predecessor is not None:
        predecessor.superseded_by_id = confirmation.id
        db.add(predecessor)

    organization = db.query(Organization).filter(Organization.id == organization_id).first()
    if organization is not None:
        organization.name = legal_name.strip()
        organization.country = registration_country
        organization.organization_type = organization_type.value
        db.add(organization)
    return confirmation


def create_legal_entity(
    db: Session,
    *,
    organization_id: int,
    legal_name: str,
    registration_country: str,
    entity_type: OrganizationEntityType,
    registration_number: str | None = None,
    is_primary: bool = False,
    status: OrganizationEntityStatus = OrganizationEntityStatus.SUGGESTED,
    parent_entity_id: str | None = None,
    source_evidence_id: str | None = None,
) -> OrganizationLegalEntity:
    """Add a legal entity. Does not require a complete group structure."""
    if not legal_name.strip():
        raise OrganizationIdentityValidationError("A legal entity name is required.")
    if parent_entity_id:
        parent = (
            db.query(OrganizationLegalEntity)
            .filter(
                OrganizationLegalEntity.id == parent_entity_id,
                OrganizationLegalEntity.organization_id == organization_id,
            )
            .first()
        )
        if parent is None:
            raise OrganizationIdentityValidationError(
                "The parent legal entity must belong to this organisation."
            )
    if is_primary:
        db.query(OrganizationLegalEntity).filter(
            OrganizationLegalEntity.organization_id == organization_id,
            OrganizationLegalEntity.is_primary.is_(True),
        ).update({"is_primary": False})
    entity = OrganizationLegalEntity(
        organization_id=organization_id,
        legal_name=legal_name.strip(),
        registration_number=registration_number,
        registration_country=registration_country,
        entity_type=entity_type.value,
        status=status.value,
        is_primary=is_primary,
        parent_entity_id=parent_entity_id,
        source_evidence_id=source_evidence_id,
    )
    db.add(entity)
    db.flush()
    return entity


def confirm_legal_entity(db: Session, entity: OrganizationLegalEntity) -> OrganizationLegalEntity:
    entity.status = OrganizationEntityStatus.CONFIRMED.value
    db.add(entity)
    return entity


def upsert_primary_legal_entity(
    db: Session,
    *,
    organization_id: int,
    legal_name: str,
    registration_country: str,
    registration_number: str | None = None,
    source_evidence_id: str | None = None,
) -> tuple[OrganizationLegalEntity, bool]:
    """Create or update the one primary entity representing confirmed identity.

    Identity confirmation can be retried after a network error or revisited as
    an auditable correction. In either case, it must update the same primary
    legal-entity record instead of accumulating indistinguishable primaries.
    """
    if not legal_name.strip():
        raise OrganizationIdentityValidationError("A legal entity name is required.")
    if source_evidence_id is not None and (
        db.query(OrganizationIdentityEvidence)
        .filter(
            OrganizationIdentityEvidence.id == source_evidence_id,
            OrganizationIdentityEvidence.organization_id == organization_id,
        )
        .first()
        is None
    ):
        raise OrganizationIdentityValidationError(
            "The legal-entity evidence must belong to this organisation."
        )

    entity = (
        db.query(OrganizationLegalEntity)
        .filter(
            OrganizationLegalEntity.organization_id == organization_id,
            OrganizationLegalEntity.is_primary.is_(True),
        )
        .first()
    )
    if entity is None and registration_number:
        entity = (
            db.query(OrganizationLegalEntity)
            .filter(
                OrganizationLegalEntity.organization_id == organization_id,
                OrganizationLegalEntity.registration_number == registration_number,
                OrganizationLegalEntity.registration_country == registration_country,
            )
            .first()
        )

    created = entity is None
    if entity is None:
        entity = OrganizationLegalEntity(
            organization_id=organization_id,
            legal_name=legal_name.strip(),
            registration_number=registration_number,
            registration_country=registration_country,
            entity_type=OrganizationEntityType.PARENT.value,
            status=OrganizationEntityStatus.CONFIRMED.value,
            is_primary=True,
            source_evidence_id=source_evidence_id,
        )
        db.add(entity)
        db.flush()
        return entity, created

    db.query(OrganizationLegalEntity).filter(
        OrganizationLegalEntity.organization_id == organization_id,
        OrganizationLegalEntity.is_primary.is_(True),
        OrganizationLegalEntity.id != entity.id,
    ).update({"is_primary": False})
    entity.legal_name = legal_name.strip()
    entity.registration_number = registration_number
    entity.registration_country = registration_country
    entity.entity_type = OrganizationEntityType.PARENT.value
    entity.status = OrganizationEntityStatus.CONFIRMED.value
    entity.is_primary = True
    entity.source_evidence_id = source_evidence_id
    db.add(entity)
    return entity, created


def exclude_legal_entity(db: Session, entity: OrganizationLegalEntity) -> OrganizationLegalEntity:
    entity.status = OrganizationEntityStatus.EXCLUDED.value
    entity.is_primary = False
    db.add(entity)
    return entity


def get_primary_confirmed_entity(
    db: Session, organization_id: int
) -> OrganizationLegalEntity | None:
    return (
        db.query(OrganizationLegalEntity)
        .filter(
            OrganizationLegalEntity.organization_id == organization_id,
            OrganizationLegalEntity.is_primary.is_(True),
            OrganizationLegalEntity.status == OrganizationEntityStatus.CONFIRMED.value,
        )
        .first()
    )


def create_scope(
    db: Session,
    *,
    organization_id: int,
    scope_type: OrganizationScopeType,
    name: str,
    description: str | None = None,
    included_entity_ids: list[str] | None = None,
    excluded_entity_ids: list[str] | None = None,
    included_countries: list[str] | None = None,
) -> OrganizationScope:
    if not name.strip():
        raise OrganizationIdentityValidationError("A scope name is required.")
    included_ids = list(dict.fromkeys(included_entity_ids or []))
    excluded_ids = list(dict.fromkeys(excluded_entity_ids or []))
    countries = list(
        dict.fromkeys(
            country.strip().upper() for country in included_countries or [] if country.strip()
        )
    )
    if set(included_ids) & set(excluded_ids):
        raise OrganizationIdentityValidationError(
            "A legal entity cannot be both included in and excluded from the same scope."
        )
    if scope_type == OrganizationScopeType.ENTIRE_ORGANIZATION and (
        included_ids or excluded_ids or countries
    ):
        raise OrganizationIdentityValidationError(
            "An entire-organisation scope cannot contain explicit inclusions or exclusions."
        )
    if scope_type == OrganizationScopeType.LEGAL_ENTITY and not included_ids:
        raise OrganizationIdentityValidationError(
            "Select at least one legal entity for a legal-entity scope."
        )
    if scope_type == OrganizationScopeType.COUNTRY and not countries:
        raise OrganizationIdentityValidationError(
            "Select at least one country for a country scope."
        )
    if scope_type == OrganizationScopeType.LEGAL_ENTITY and countries:
        raise OrganizationIdentityValidationError(
            "A legal-entity scope cannot include countries directly."
        )
    if scope_type == OrganizationScopeType.COUNTRY and (included_ids or excluded_ids):
        raise OrganizationIdentityValidationError(
            "A country scope cannot include legal entities directly."
        )
    selected_entity_ids = included_ids + excluded_ids
    if selected_entity_ids:
        tenant_entity_count = (
            db.query(OrganizationLegalEntity)
            .filter(
                OrganizationLegalEntity.organization_id == organization_id,
                OrganizationLegalEntity.id.in_(selected_entity_ids),
            )
            .count()
        )
        if tenant_entity_count != len(selected_entity_ids):
            raise OrganizationIdentityValidationError(
                "Every selected legal entity must belong to this organisation."
            )
    scope = OrganizationScope(
        organization_id=organization_id,
        scope_type=scope_type.value,
        name=name.strip(),
        description=description,
        status=OrganizationScopeStatus.DRAFT.value,
        included_entity_ids=included_ids,
        excluded_entity_ids=excluded_ids,
        included_countries=countries,
    )
    db.add(scope)
    db.flush()
    return scope


def confirm_scope(
    db: Session, scope: OrganizationScope, *, confirmed_by_user_id: int
) -> OrganizationScope:
    scope.status = OrganizationScopeStatus.CONFIRMED.value
    scope.confirmed_by_user_id = confirmed_by_user_id
    scope.confirmed_at = utcnow()
    db.add(scope)
    return scope


def get_confirmed_scope(db: Session, organization_id: int) -> OrganizationScope | None:
    return (
        db.query(OrganizationScope)
        .filter(
            OrganizationScope.organization_id == organization_id,
            OrganizationScope.status == OrganizationScopeStatus.CONFIRMED.value,
        )
        .order_by(OrganizationScope.confirmed_at.desc())
        .first()
    )


def add_domain(
    db: Session,
    *,
    organization_id: int,
    domain: str,
    domain_type: OrganizationDomainType,
) -> OrganizationDomain:
    if not domain.strip():
        raise OrganizationIdentityValidationError("A domain is required.")
    record = OrganizationDomain(
        organization_id=organization_id,
        domain=domain.strip().lower(),
        domain_type=domain_type.value,
        verification_status="unverified",
    )
    db.add(record)
    db.flush()
    return record


def verify_domain(
    db: Session, domain: OrganizationDomain, *, verified_by_user_id: int, verification_method: str
) -> OrganizationDomain:
    domain.verification_status = "verified"
    domain.verified_by_user_id = verified_by_user_id
    domain.verified_at = utcnow()
    domain.verification_method = verification_method
    db.add(domain)
    return domain

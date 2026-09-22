"""#280 (TZ-2) — a person sees and sets their own location and timezone.

A route module of its own rather than three more fields on the profile or auth
endpoints: adding a capability should not require editing a working one, and
this one has its own validation, its own audit event and its own reason to
change.

**It belongs to the person, not the tenant.** The zone is read from the
authenticated caller and written to the same row — an organisation-wide setting
was considered and ruled out (Søren, 2026-08-19), because a compliance record
should read in the clock of whoever is reading it.
"""

from __future__ import annotations

from datetime import datetime
from zoneinfo import ZoneInfo

import structlog
from fastapi import APIRouter, Depends
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from src.api.middleware.tenant_context import TenantContext, get_tenant_context
from src.core.constants.user_locale import (
    CITY_MAX_LENGTH,
    USER_LOCALE_AUDIT_UPDATED,
    USER_LOCALE_NOTE_NOTHING_IS_REWRITTEN,
)
from src.core.database import get_db
from src.core.exceptions import ResourceNotFoundError, ValidationError
from src.core.models import User
from src.core.repository import TenantRepository
from src.core.services.audit_service import append_audit_event
from src.core.services.user_locale_service import (
    UserLocaleValidationError,
    is_fallback_timezone,
    propose_timezone_for_country,
    resolve_reader_timezone,
    validate_city,
    validate_country,
    validate_timezone,
)
from src.api.schemas.timestamps import UtcTimestamp

logger = structlog.get_logger(__name__)

router = APIRouter(prefix="/api/v1/users/me/locale", tags=["User locale"])

USER_LOCALE_ERROR_NOT_FOUND = "This account could not be read"


class UserLocaleUpdateRequest(BaseModel):
    #: Absent means "leave it alone". Explicit ``null`` on a location field
    #: means "clear it" — a person who moves somewhere they would rather not
    #: state must be able to remove it, not only replace it.
    timezone: str | None = None
    location_country: str | None = None
    location_city: str | None = Field(default=None, max_length=CITY_MAX_LENGTH)
    clear_location: bool = False


class UserLocaleResponse(BaseModel):
    #: What the person set, or ``None`` when they have not chosen yet. Kept
    #: apart from ``effective_timezone`` so a screen can tell the difference.
    timezone: str | None = None
    #: What their timestamps are actually rendered in — their own choice, or the
    #: platform default when they have not made one.
    effective_timezone: str
    #: True when ``effective_timezone`` is a fallback. The screen has to say so:
    #: a default presented as a setting is how somebody ends up reading an audit
    #: trail in a clock they never picked.
    is_default: bool
    location_country: str | None = None
    location_city: str | None = None
    #: The current time where they are, for the screen to show beside the field.
    #: Computed here because the answer must match what the platform will
    #: actually render, and a browser asked separately can disagree.
    local_time: UtcTimestamp
    local_time_zone_abbreviation: str
    #: Said on the screen, not only in a docstring.
    note: str = USER_LOCALE_NOTE_NOTHING_IS_REWRITTEN


class TimezoneProposalResponse(BaseModel):
    """A zone to *offer* for a country, or nothing when it cannot settle it."""

    country: str
    proposed_timezone: str | None = None


def _require_self(db: Session, ctx: TenantContext) -> User:
    user = TenantRepository(db, User, ctx.organization_id).get_by_id(ctx.user_id)
    if user is None or not user.is_active:
        raise ResourceNotFoundError(USER_LOCALE_ERROR_NOT_FOUND)
    return user


def _response(user: User) -> UserLocaleResponse:
    zone_name = resolve_reader_timezone(user)
    zone = ZoneInfo(zone_name)
    now = datetime.now(zone)
    return UserLocaleResponse(
        timezone=user.timezone,
        effective_timezone=zone_name,
        is_default=is_fallback_timezone(user),
        location_country=user.location_country,
        location_city=user.location_city,
        local_time=now,
        # "CEST" rather than "+02:00": the abbreviation is what a person reads
        # on a clock, and it is the half that changes at the DST boundary.
        local_time_zone_abbreviation=now.strftime("%Z"),
    )


@router.get("", response_model=UserLocaleResponse)
def read_own_locale(
    ctx: TenantContext = Depends(get_tenant_context),
    db: Session = Depends(get_db),
) -> UserLocaleResponse:
    return _response(_require_self(db, ctx))


@router.get("/proposal", response_model=TimezoneProposalResponse)
def propose_for_country(
    country: str,
    ctx: TenantContext = Depends(get_tenant_context),
) -> TimezoneProposalResponse:
    """What to *offer* for a country — never what to apply.

    Returns nothing for any country with more than one zone. The caller shows
    the proposal and the person confirms it; nothing here writes.
    """
    return TimezoneProposalResponse(
        country=country.strip().upper(),
        proposed_timezone=propose_timezone_for_country(country),
    )


@router.patch("", response_model=UserLocaleResponse)
def update_own_locale(
    body: UserLocaleUpdateRequest,
    ctx: TenantContext = Depends(get_tenant_context),
    db: Session = Depends(get_db),
) -> UserLocaleResponse:
    """Set the zone, the location, or both.

    Never rewrites a stored instant. Every timestamp in the platform is a UTC
    instant and stays one; this changes how they are read.
    """
    user = _require_self(db, ctx)
    before = {
        "timezone": user.timezone,
        "location_country": user.location_country,
        "location_city": user.location_city,
    }

    try:
        if body.timezone is not None:
            user.timezone = validate_timezone(body.timezone)
        if body.clear_location:
            user.location_country = None
            user.location_city = None
        else:
            if body.location_country is not None:
                user.location_country = validate_country(body.location_country)
            if body.location_city is not None:
                user.location_city = validate_city(body.location_city)
    except UserLocaleValidationError as exc:
        raise ValidationError(str(exc)) from exc

    after = {
        "timezone": user.timezone,
        "location_country": user.location_country,
        "location_city": user.location_city,
    }

    # Written only when something actually moved. An audit trail that records
    # every save whether or not it changed anything is one nobody reads.
    if after != before:
        append_audit_event(
            db,
            organization_id=ctx.organization_id,
            event_type=USER_LOCALE_AUDIT_UPDATED,
            actor_user_id=ctx.user_id,
            metadata={"before": before, "after": after},
        )
    db.commit()
    db.refresh(user)
    return _response(user)


__all__ = ["router"]

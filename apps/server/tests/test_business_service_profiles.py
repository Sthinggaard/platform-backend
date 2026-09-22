"""BSP-01: Business Service Profile layer — constants integrity + seeding."""

from __future__ import annotations

import pytest
from sqlalchemy import create_engine
from sqlalchemy.dialects.postgresql import ARRAY as PgArray, JSONB
from sqlalchemy.dialects.sqlite import JSON as SqliteJSON
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool
from sqlalchemy.sql.sqltypes import ARRAY as SqlArray

from src.core.constants.business_service_profiles import (
    BUSINESS_SERVICE_PROFILES,
    get_business_service_profile,
)
from src.core.constants.dependency_templates import (
    ARCHETYPE_PATTERN_EXPECTATIONS,
    CANONICAL_PATTERN_NAMES,
)
from src.core.constants.service_key_archetypes import SERVICE_KEY_ARCHETYPES
from src.core.database import Base
from src.core.services.template_library_service import ensure_template_library_seeded
from src.core.template_models import ProcessTemplate, ServiceTemplate, SlotTemplate


@pytest.fixture()
def db() -> Session:
    engine = create_engine(
        "sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool
    )
    for table in Base.metadata.tables.values():
        for column in table.columns:
            if isinstance(column.type, (SqlArray, PgArray, JSONB)):
                column.type = SqliteJSON()
    Base.metadata.create_all(
        engine,
        tables=[
            ProcessTemplate.__table__,
            ServiceTemplate.__table__,
            SlotTemplate.__table__,
        ],
    )
    session = sessionmaker(bind=engine)()
    yield session
    session.close()


class TestProfileConstantsIntegrity:
    def test_every_profile_maps_to_a_canonical_service_key(self):
        for service_key in BUSINESS_SERVICE_PROFILES:
            assert service_key in SERVICE_KEY_ARCHETYPES, service_key

    def test_every_enrichment_targets_a_canonical_pattern(self):
        for profile in BUSINESS_SERVICE_PROFILES.values():
            for enrichment in profile.slot_enrichments:
                assert enrichment.pattern_key in CANONICAL_PATTERN_NAMES, (
                    profile.service_key,
                    enrichment.pattern_key,
                )

    def test_enrichments_stay_within_the_archetype_pattern_set(self):
        # A profile can only enrich patterns its archetype actually seeds —
        # otherwise the enrichment would silently never apply.
        for profile in BUSINESS_SERVICE_PROFILES.values():
            archetype = SERVICE_KEY_ARCHETYPES[profile.service_key]
            expectations = ARCHETYPE_PATTERN_EXPECTATIONS[archetype]
            allowed = set(expectations["required"]) | set(expectations["optional"])
            for enrichment in profile.slot_enrichments:
                assert enrichment.pattern_key in allowed, (
                    profile.service_key,
                    enrichment.pattern_key,
                )

    def test_profiles_carry_the_mandatory_business_semantics(self):
        for profile in BUSINESS_SERVICE_PROFILES.values():
            assert profile.capability_statement.strip()
            assert profile.default_impact_model.get("business_criticality")
            assert profile.common_risk_patterns
            assert profile.override_policy

    def test_lookup_helper(self):
        assert get_business_service_profile("payment_processing") is not None
        assert get_business_service_profile("nonexistent") is None


class TestProfileSeeding:
    def test_seed_applies_profile_to_service_template(self, db: Session):
        ensure_template_library_seeded(db)
        row = (
            db.query(ServiceTemplate)
            .filter(ServiceTemplate.service_key == "payment_processing")
            .one()
        )
        assert row.capability_statement.startswith("Payment Processing enables")
        assert row.default_impact_model["business_criticality"] == "Mission Critical"
        assert "payment gateway outage" in row.common_risk_patterns
        assert row.override_policy["impact_model"] == "structured_reason_required"

    def test_seed_enriches_slots_with_hints_and_overrides(self, db: Session):
        ensure_template_library_seeded(db)
        service = (
            db.query(ServiceTemplate)
            .filter(ServiceTemplate.service_key == "payment_processing")
            .one()
        )
        slots = {
            slot.slot_id: slot
            for slot in db.query(SlotTemplate).filter(
                SlotTemplate.service_template_id == service.id
            )
        }
        gateway = slots["external_provider"]
        assert gateway.label == "Payment Gateway"
        assert "stripe" in gateway.matching_hints
        assert "integration" in gateway.expected_evidence_types
        # required_override flips the archetype's optional monitoring slot.
        assert slots["monitoring_service"].required is True

    def test_services_without_profiles_keep_archetype_defaults(self, db: Session):
        ensure_template_library_seeded(db)
        row = (
            db.query(ServiceTemplate)
            .filter(ServiceTemplate.service_key == "order_management")
            .one()
        )
        assert row.capability_statement is None
        slots = db.query(SlotTemplate).filter(SlotTemplate.service_template_id == row.id).all()
        assert all(not (slot.matching_hints or []) for slot in slots)

    def test_backfill_enriches_pre_profile_rows(self, db: Session):
        ensure_template_library_seeded(db)
        service = (
            db.query(ServiceTemplate)
            .filter(ServiceTemplate.service_key == "payment_processing")
            .one()
        )
        # Simulate a row created before the profile layer existed.
        service.capability_statement = None
        service.default_impact_model = None
        for slot in db.query(SlotTemplate).filter(
            SlotTemplate.service_template_id == service.id
        ):
            slot.matching_hints = []
            slot.label = "External Service Provider"
        db.commit()

        ensure_template_library_seeded(db)
        refreshed = (
            db.query(ServiceTemplate)
            .filter(ServiceTemplate.service_key == "payment_processing")
            .one()
        )
        assert refreshed.capability_statement
        gateway = (
            db.query(SlotTemplate)
            .filter(
                SlotTemplate.service_template_id == refreshed.id,
                SlotTemplate.slot_id == "external_provider",
            )
            .one()
        )
        assert gateway.label == "Payment Gateway"
        assert "stripe" in gateway.matching_hints

    def test_seeding_is_idempotent(self, db: Session):
        ensure_template_library_seeded(db)
        first_count = db.query(SlotTemplate).count()
        ensure_template_library_seeded(db)
        assert db.query(SlotTemplate).count() == first_count

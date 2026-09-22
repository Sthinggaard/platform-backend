from sqlalchemy import create_engine, select
from sqlalchemy.orm import Session, sessionmaker

from src.core.model_defs.business_process_recommendation import BusinessProcessRecommendationSet
from src.core.models import (
    Base,
    BusinessProcessDecisionAction,
    BusinessProcessDecisionLog,
    BusinessProcessRecommendation,
    BusinessProcessRecommendationStatus,
)
from src.core.services.business_process_repository import BusinessProcessRepository
from src.core.services.business_process_recommendation_engine import BusinessProcessRecommendationEngine
from src.pretenant.risk_intelligence import OrganisationProfile


def _profile() -> OrganisationProfile:
    return OrganisationProfile(
        cvr="12345678",
        legal_name="Example ApS",
        industry_code="62010",
        size_bracket="enterprise",
        geography="DK",
        locations=2,
        it_dependency="critical",
        risk_appetite="balanced",
        selected_asset_categories=["identity", "cloud", "email"],
        regulatory_flags=["GDPR", "NIS2"],
        business_model_tags=["subscription", "b2b"],
    )


def _session() -> Session:
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(
        engine,
        tables=[
            BusinessProcessRecommendation.__table__,
            BusinessProcessDecisionLog.__table__,
        ],
    )
    return sessionmaker(bind=engine)()


def test_persist_recommendations_and_status_transitions_are_auditable():
    session = _session()
    try:
        repo = BusinessProcessRepository(session, organization_id=42, user_id=7)
        recommendations = BusinessProcessRecommendationEngine().recommend(_profile())
        assert isinstance(recommendations, BusinessProcessRecommendationSet)

        rows = repo.persist_recommendations(recommendations)
        session.commit()

        assert len(rows) == 5
        stored = session.execute(
            select(BusinessProcessRecommendation).where(BusinessProcessRecommendation.organization_id == 42)
        ).scalars().all()
        assert len(stored) == 5
        assert all(row.status == BusinessProcessRecommendationStatus.SUGGESTED.value for row in stored)

        accepted = repo.accept_recommendation(stored[0].id, reason={"summary": "Approved for rollout"})
        removed = repo.remove_recommendation(stored[1].id, reason={"summary": "Not needed now", "source": "review"})
        added = repo.add_from_library("compliance-governance", reason={"summary": "Added manually"})
        session.commit()

        assert accepted.status == BusinessProcessRecommendationStatus.ACCEPTED.value
        assert removed.status == BusinessProcessRecommendationStatus.REMOVED.value
        assert added.status == BusinessProcessRecommendationStatus.ADDED.value

        refreshed_removed = session.get(BusinessProcessRecommendation, stored[1].id)
        assert refreshed_removed is not None
        assert refreshed_removed.status == BusinessProcessRecommendationStatus.REMOVED.value

        logs = session.execute(
            select(BusinessProcessDecisionLog).where(BusinessProcessDecisionLog.organization_id == 42)
        ).scalars().all()
        assert [log.action for log in logs] == [
            BusinessProcessDecisionAction.ACCEPT.value,
            BusinessProcessDecisionAction.REMOVE.value,
            BusinessProcessDecisionAction.ADD.value,
        ]
        assert logs[1].reason["source"] == "review"
        assert logs[0].user_id == 7
        assert logs[2].model_version
    finally:
        session.close()


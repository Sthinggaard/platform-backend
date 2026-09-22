from __future__ import annotations

from collections.abc import Generator

from sqlalchemy import create_engine
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.dialects.sqlite import JSON as SqliteJSON
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool
from sqlalchemy.sql.sqltypes import ARRAY as SqlArray

from src.core.model_defs.business_process_learning import BusinessProcessLearningDataset
from src.core.models import (
    Base,
    BusinessProcessDecisionAction,
    BusinessProcessDecisionLog,
    BusinessProcessRecommendation,
    BusinessProcessRecommendationStatus,
    Organization,
)
from src.core.services.business_process_learning_dataset import build_business_process_learning_dataset


def _make_session() -> Session:
    engine = create_engine("sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    for table in Base.metadata.tables.values():
        for column in table.columns:
            if isinstance(column.type, (SqlArray, JSONB)):
                column.type = SqliteJSON()
    Base.metadata.create_all(
        engine,
        tables=[
            Organization.__table__,
            BusinessProcessRecommendation.__table__,
            BusinessProcessDecisionLog.__table__,
        ],
    )
    return sessionmaker(bind=engine)()


def _seed_organization(session: Session) -> Organization:
    org = Organization(
        id=7,
        name="Example ApS",
        slug="example",
        industry="62010",
        company_size="enterprise",
        country="DK",
        cvr_number="12345678",
        nace_code="62010",
        onboarding_data={
            "business_model_tags": ["subscription", "b2b"],
            "regulatory_flags": ["gdpr", "nis2"],
            "selected_asset_categories": ["identity", "cloud"],
            "risk_appetite": "balanced",
            "workspace": {
                "businessServices": [{"id": "svc-1"}, {"id": "svc-2"}],
                "assets": [
                    {"id": "asset-1", "assetType": "identity"},
                    {"id": "asset-2", "assetType": "cloud"},
                    {"id": "asset-3", "assetType": "email"},
                ],
                "criticalityProfiles": [
                    {"criticality": "high"},
                    {"criticality": "medium"},
                    {"criticality": "high"},
                ],
                "riskAppetiteProfile": {"profile": "balanced"},
            },
        },
    )
    session.add(org)
    session.commit()
    return org


def _seed_recommendation(
    session: Session,
    *,
    organization_id: int,
    template_id: str,
    name: str,
    category: str,
    source_rule: str,
    status: BusinessProcessRecommendationStatus,
) -> BusinessProcessRecommendation:
    row = BusinessProcessRecommendation(
        organization_id=organization_id,
        user_id=11,
        process_template_id=template_id,
        name=name,
        category=category,
        confidence=0.61,
        recommendation_reason=f"{name} is relevant",
        source_rule=source_rule,
        status=status.value,
        model_version="business-process-recommendation.v1",
    )
    session.add(row)
    session.flush()
    return row


def _seed_log(
    session: Session,
    *,
    organization_id: int,
    recommendation_id: str | None,
    action: BusinessProcessDecisionAction,
    summary: str,
) -> BusinessProcessDecisionLog:
    log = BusinessProcessDecisionLog(
        organization_id=organization_id,
        recommendation_id=recommendation_id,
        user_id=11,
        action=action.value,
        reason={"summary": summary, "details": {"source": "test"}},
        model_version="business-process-recommendation.v1",
    )
    session.add(log)
    session.flush()
    return log


def test_business_process_learning_dataset_exports_company_vector_and_labels() -> None:
    session = _make_session()
    org = _seed_organization(session)

    accepted = _seed_recommendation(
        session,
        organization_id=org.id,
        template_id="customer-lifecycle",
        name="Customers, Sales & Retention",
        category="customer",
        source_rule="RULE_CUSTOMER_SUCCESS_MODEL",
        status=BusinessProcessRecommendationStatus.ACCEPTED,
    )
    removed = _seed_recommendation(
        session,
        organization_id=org.id,
        template_id="security-operations",
        name="Keeping the Business Safe",
        category="security",
        source_rule="RULE_SECURITY_DEPENDENCY",
        status=BusinessProcessRecommendationStatus.REMOVED,
    )
    added = _seed_recommendation(
        session,
        organization_id=org.id,
        template_id="billing-subscription",
        name="Getting Paid",
        category="finance",
        source_rule="MANUAL_LIBRARY_ADD",
        status=BusinessProcessRecommendationStatus.ADDED,
    )
    _seed_log(
        session,
        organization_id=org.id,
        recommendation_id=accepted.id,
        action=BusinessProcessDecisionAction.ACCEPT,
        summary="Keep customer flow in scope",
    )
    _seed_log(
        session,
        organization_id=org.id,
        recommendation_id=removed.id,
        action=BusinessProcessDecisionAction.REMOVE,
        summary="Not relevant to this setup",
    )
    _seed_log(
        session,
        organization_id=org.id,
        recommendation_id=added.id,
        action=BusinessProcessDecisionAction.ADD,
        summary="Billing is needed",
    )
    _seed_log(
        session,
        organization_id=org.id,
        recommendation_id=None,
        action=BusinessProcessDecisionAction.CONFIRM,
        summary="Confirm business model",
    )
    session.commit()

    dataset = build_business_process_learning_dataset(session)
    assert isinstance(dataset, BusinessProcessLearningDataset)
    assert len(dataset.examples) == 1

    example = dataset.examples[0]
    vector = example.company_profile_vector
    assert example.organization_id == org.id
    assert example.organization_name == "Example ApS"
    assert vector.industry == "62010"
    assert vector.size == "enterprise"
    assert vector.geography == "DK"
    assert vector.business_model_tags == ["subscription", "b2b"]
    assert vector.regulatory_flags == ["gdpr", "nis2"]
    assert vector.asset_categories == ["identity", "cloud", "email"]
    assert vector.risk_appetite == "balanced"
    assert vector.service_count == 2
    assert vector.asset_count == 3
    assert vector.criticality_distribution == {"high": 2, "medium": 1}

    labels = example.labels
    assert [item.template_id for item in labels.accepted_process_templates] == ["customer-lifecycle"]
    assert [item.template_id for item in labels.removed_process_templates] == ["security-operations"]
    assert [item.template_id for item in labels.added_process_templates] == ["billing-subscription"]
    assert [item.summary for item in labels.decision_reasons] == [
        "Keep customer flow in scope",
        "Not relevant to this setup",
        "Billing is needed",
        "Confirm business model",
    ]

    exported = dataset.model_dump(by_alias=True)
    assert exported["examples"][0]["companyProfileVector"]["serviceCount"] == 2
    assert exported["examples"][0]["labels"]["acceptedProcessTemplates"][0]["templateId"] == "customer-lifecycle"


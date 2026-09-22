from __future__ import annotations

from collections import Counter
from collections.abc import Sequence
from datetime import datetime, timezone
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from src.core.model_defs.business_process_learning import (
    BusinessProcessLearningCompanyProfileVector,
    BusinessProcessLearningDataset,
    BusinessProcessLearningDecisionReason,
    BusinessProcessLearningExample,
    BusinessProcessLearningLabels,
    BusinessProcessLearningTemplateLabel,
)
from src.core.models import BusinessProcessDecisionLog, BusinessProcessRecommendation, Organization

_ACTION_ORDER = {
    "accept": 0,
    "remove": 1,
    "add": 2,
    "confirm": 3,
}


def build_business_process_learning_dataset(db: Session) -> BusinessProcessLearningDataset:
    organization_ids = sorted(
        {
            organization_id
            for organization_id in (
                [row[0] for row in db.execute(select(BusinessProcessRecommendation.organization_id).distinct()).all()]
                + [row[0] for row in db.execute(select(BusinessProcessDecisionLog.organization_id).distinct()).all()]
            )
            if isinstance(organization_id, int)
        }
    )
    examples: list[BusinessProcessLearningExample] = []
    for organization_id in organization_ids:
        org = db.get(Organization, organization_id)
        if org is None:
            continue
        recommendations = db.execute(
            select(BusinessProcessRecommendation)
            .where(BusinessProcessRecommendation.organization_id == organization_id)
            .order_by(BusinessProcessRecommendation.created_at.asc(), BusinessProcessRecommendation.id.asc())
        ).scalars().all()
        decision_logs = db.execute(
            select(BusinessProcessDecisionLog)
            .where(BusinessProcessDecisionLog.organization_id == organization_id)
            .order_by(BusinessProcessDecisionLog.created_at.asc(), BusinessProcessDecisionLog.id.asc())
        ).scalars().all()
        recommendation_lookup = {row.id: row for row in recommendations}
        examples.append(
            BusinessProcessLearningExample(
                organization_id=organization_id,
                organization_name=_organization_name(org),
                company_profile_vector=_build_company_profile_vector(org),
                labels=BusinessProcessLearningLabels(
                    accepted_process_templates=_build_template_labels(
                        recommendations,
                        "accepted",
                    ),
                    removed_process_templates=_build_template_labels(
                        recommendations,
                        "removed",
                    ),
                    added_process_templates=_build_template_labels(
                        recommendations,
                        "added",
                    ),
                    decision_reasons=[
                        _build_decision_reason(log, recommendation_lookup.get(log.recommendation_id))
                        for log in decision_logs
                    ],
                ),
            )
        )
        examples[-1].labels.decision_reasons.sort(
            key=lambda item: (
                item.created_at,
                _ACTION_ORDER.get(item.action, 99),
                item.template_id or "",
                item.decision_log_id,
            )
        )
    return BusinessProcessLearningDataset(generated_at=datetime.now(timezone.utc), examples=examples)


def _build_company_profile_vector(org: Organization) -> BusinessProcessLearningCompanyProfileVector:
    onboarding_data = org.onboarding_data if isinstance(org.onboarding_data, dict) else {}
    workspace = _as_dict(onboarding_data.get("workspace"))
    workspace_org = _as_dict(workspace.get("organization"))
    asset_items = _as_sequence(workspace.get("assets"))
    service_items = _as_sequence(workspace.get("businessServices") or workspace.get("business_services"))
    criticality_items = _as_sequence(workspace.get("criticalityProfiles") or workspace.get("criticality_profiles"))
    return BusinessProcessLearningCompanyProfileVector(
        industry=_first_text(
            onboarding_data.get("industry"),
            onboarding_data.get("industry_code"),
            onboarding_data.get("industryCode"),
            workspace_org.get("industryCode"),
            org.industry,
            org.nace_code,
        ),
        size=_first_text(
            onboarding_data.get("size"),
            onboarding_data.get("size_bracket"),
            onboarding_data.get("sizeBracket"),
            workspace_org.get("sizeBracket"),
            org.company_size,
        ),
        geography=_first_text(
            onboarding_data.get("geography"),
            onboarding_data.get("country"),
            workspace_org.get("geography"),
            workspace_org.get("country"),
            org.country,
        ),
        business_model_tags=_merge_tags(
            onboarding_data.get("business_model_tags"),
            onboarding_data.get("businessModelTags"),
            workspace.get("businessModelTags"),
            workspace.get("business_model_tags"),
        ),
        regulatory_flags=_merge_tags(
            onboarding_data.get("regulatory_flags"),
            onboarding_data.get("regulatoryFlags"),
            workspace.get("regulatoryFlags"),
            workspace.get("regulatory_flags"),
        ),
        asset_categories=_merge_tags(
            onboarding_data.get("selected_asset_categories"),
            onboarding_data.get("selectedAssetCategories"),
            workspace.get("selectedAssetCategories"),
            workspace.get("assetCategories"),
            _asset_categories_from_assets(asset_items),
        ),
        risk_appetite=_first_text(
            onboarding_data.get("risk_appetite"),
            onboarding_data.get("riskAppetite"),
            _risk_appetite_from_workspace(workspace),
        ),
        service_count=len(service_items),
        asset_count=len(asset_items),
        criticality_distribution=_criticality_distribution(criticality_items),
    )


def _build_template_labels(
    recommendations: Sequence[BusinessProcessRecommendation],
    target_status: str,
) -> list[BusinessProcessLearningTemplateLabel]:
    seen: set[str] = set()
    labels: list[BusinessProcessLearningTemplateLabel] = []
    for row in recommendations:
        if row.status != target_status:
            continue
        template_id = row.process_template_id
        if template_id in seen:
            continue
        seen.add(template_id)
        labels.append(
            BusinessProcessLearningTemplateLabel(
                templateId=template_id,
                name=row.name,
                category=row.category,
                sourceRule=row.source_rule,
                status=row.status,
            )
        )
    return sorted(labels, key=lambda item: item.template_id)


def _build_decision_reason(
    log: BusinessProcessDecisionLog,
    recommendation: BusinessProcessRecommendation | None,
) -> BusinessProcessLearningDecisionReason:
    reason_payload = log.reason if isinstance(log.reason, dict) else {}
    summary = _reason_summary(reason_payload)
    details = {key: value for key, value in reason_payload.items() if key != "summary"} if reason_payload else {}
    return BusinessProcessLearningDecisionReason(
        decisionLogId=log.id,
        recommendationId=log.recommendation_id,
        templateId=recommendation.process_template_id if recommendation is not None else None,
        templateName=recommendation.name if recommendation is not None else None,
        action=log.action,
        summary=summary,
        details=details,
        modelVersion=log.model_version,
        createdAt=log.created_at,
    )


def _reason_summary(reason: dict[str, Any]) -> str:
    for key in ("summary", "message", "reason"):
        value = reason.get(key)
        if isinstance(value, str) and value.strip():
            return value.strip()
    if reason:
        return " / ".join(
            f"{key}: {value}"
            for key, value in reason.items()
            if isinstance(value, (str, int, float, bool))
        )
    return ""


def _organization_name(org: Organization) -> str:
    if isinstance(org.name, str) and org.name.strip():
        return org.name.strip()
    if isinstance(org.slug, str) and org.slug.strip():
        return org.slug.strip()
    return f"Organization {org.id}"


def _first_text(*values: Any) -> str:
    for value in values:
        if isinstance(value, str):
            candidate = value.strip()
            if candidate:
                return candidate
    return ""


def _merge_tags(*values: Any) -> list[str]:
    tags: list[str] = []
    seen: set[str] = set()
    for value in values:
        for item in _as_sequence(value):
            if not isinstance(item, str):
                continue
            token = item.strip().lower()
            if not token or token in seen:
                continue
            seen.add(token)
            tags.append(token)
    return tags


def _asset_categories_from_assets(assets: Sequence[Any]) -> list[str]:
    categories: list[str] = []
    seen: set[str] = set()
    for asset in assets:
        if not isinstance(asset, dict):
            continue
        candidate = asset.get("assetType") or asset.get("asset_type") or asset.get("type") or asset.get("name")
        if not isinstance(candidate, str):
            continue
        token = candidate.strip().lower()
        if not token or token in seen:
            continue
        seen.add(token)
        categories.append(token)
    return categories


def _risk_appetite_from_workspace(workspace: dict[str, Any]) -> str:
    profile = workspace.get("riskAppetiteProfile")
    if isinstance(profile, dict):
        return _first_text(profile.get("profile"), profile.get("riskAppetite"), profile.get("risk_appetite"))
    return ""


def _criticality_distribution(items: Sequence[Any]) -> dict[str, int]:
    counts: Counter[str] = Counter()
    for item in items:
        if isinstance(item, dict):
            for key in ("criticality", "criticalityLevel", "criticality_level", "level", "severity", "status"):
                value = item.get(key)
                if isinstance(value, str):
                    token = value.strip().lower()
                    if token:
                        counts[token] += 1
                        break
    return dict(counts)


def _as_dict(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _as_sequence(value: Any) -> list[Any]:
    if isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
        return list(value)
    if value is None:
        return []
    return [value]

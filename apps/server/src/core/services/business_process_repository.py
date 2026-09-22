from __future__ import annotations

from collections import defaultdict
from collections.abc import Sequence
from datetime import datetime, timezone
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from src.core.constants.business_process_templates import get_business_process_template
from src.core.model_defs.business_process_recommendation import (
    BUSINESS_PROCESS_RECOMMENDATION_MODEL_VERSION,
    BusinessProcessRecommendation as RecommendationPayload,
    BusinessProcessRecommendationSet,
)
from src.core.models import (
    BusinessProcessDecisionAction,
    BusinessProcessDecisionLog,
    BusinessProcessRecommendation,
    BusinessProcessRecommendationStatus,
    Organization,
)


class BusinessProcessRepository:
    def __init__(self, db: Session, organization_id: int, user_id: int | None = None):
        self.db = db
        self.organization_id = organization_id
        self.user_id = user_id

    def persist_recommendations(
        self,
        recommendations: BusinessProcessRecommendationSet | Sequence[RecommendationPayload],
    ) -> list[BusinessProcessRecommendation]:
        payloads = recommendations.recommendations if isinstance(recommendations, BusinessProcessRecommendationSet) else recommendations
        rows: list[BusinessProcessRecommendation] = []
        for payload in payloads:
            row = self._build_recommendation_row(payload)
            self.db.add(row)
            rows.append(row)
        self.db.flush()
        return rows

    def merge_recommendations(
        self,
        recommendations: BusinessProcessRecommendationSet | Sequence[RecommendationPayload],
    ) -> list[BusinessProcessRecommendation]:
        payloads = recommendations.recommendations if isinstance(recommendations, BusinessProcessRecommendationSet) else recommendations
        existing_rows = self.db.execute(
            select(BusinessProcessRecommendation)
            .where(BusinessProcessRecommendation.organization_id == self.organization_id)
            .order_by(BusinessProcessRecommendation.created_at.asc(), BusinessProcessRecommendation.id.asc())
        ).scalars().all()

        rows_by_template: dict[str, list[BusinessProcessRecommendation]] = defaultdict(list)
        for row in existing_rows:
            rows_by_template[row.process_template_id].append(row)

        payloads_by_template = {payload.process_template_id: payload for payload in payloads}
        touched_rows: list[BusinessProcessRecommendation] = []

        for template_id, template_rows in rows_by_template.items():
            canonical = self._select_canonical_recommendation(template_rows)
            if canonical is None:
                continue
            for row in template_rows:
                if row is canonical:
                    continue
                if row.status == BusinessProcessRecommendationStatus.SUGGESTED.value:
                    self._retire_suggestion(row)

            payload = payloads_by_template.get(template_id)
            if payload is None:
                if canonical.status == BusinessProcessRecommendationStatus.SUGGESTED.value:
                    self._retire_suggestion(canonical)
                continue

            if canonical.status == BusinessProcessRecommendationStatus.SUGGESTED.value:
                self._update_suggestion(canonical, payload)
                touched_rows.append(canonical)

        for payload in payloads:
            if payload.process_template_id in rows_by_template:
                continue
            row = self._build_recommendation_row(payload)
            self.db.add(row)
            touched_rows.append(row)

        self.db.flush()
        return touched_rows

    def accept_recommendation(
        self,
        recommendation_id: str,
        *,
        reason: dict[str, Any] | str | None = None,
    ) -> BusinessProcessRecommendation:
        return self._transition_recommendation(
            recommendation_id,
            BusinessProcessRecommendationStatus.ACCEPTED,
            BusinessProcessDecisionAction.ACCEPT,
            reason=reason,
        )

    def remove_recommendation(
        self,
        recommendation_id: str,
        *,
        reason: dict[str, Any] | str,
    ) -> BusinessProcessRecommendation:
        return self._transition_recommendation(
            recommendation_id,
            BusinessProcessRecommendationStatus.REMOVED,
            BusinessProcessDecisionAction.REMOVE,
            reason=reason,
        )

    def add_from_library(
        self,
        template_id: str,
        *,
        confidence: float = 0.5,
        reason: dict[str, Any] | str | None = None,
        model_version: str = BUSINESS_PROCESS_RECOMMENDATION_MODEL_VERSION,
    ) -> BusinessProcessRecommendation:
        template = get_business_process_template(template_id)
        row = BusinessProcessRecommendation(
            organization_id=self.organization_id,
            user_id=self.user_id,
            process_template_id=template.id,
            name=template.name,
            category=template.category,
            confidence=confidence,
            recommendation_reason=template.explanation,
            source_rule="MANUAL_LIBRARY_ADD",
            status=BusinessProcessRecommendationStatus.ADDED.value,
            model_version=model_version,
        )
        self.db.add(row)
        self.db.flush()
        self._log_decision(row.id, BusinessProcessDecisionAction.ADD, reason, model_version)
        self.db.flush()
        return row

    def confirm_model(
        self,
        *,
        reason: dict[str, Any] | str | None = None,
    ) -> dict[str, Any]:
        candidate_rows = self.db.execute(
            select(BusinessProcessRecommendation)
            .where(
                BusinessProcessRecommendation.organization_id == self.organization_id,
                BusinessProcessRecommendation.status.in_(
                    [
                        BusinessProcessRecommendationStatus.SUGGESTED.value,
                        BusinessProcessRecommendationStatus.ACCEPTED.value,
                        BusinessProcessRecommendationStatus.ADDED.value,
                    ]
                ),
            )
            .order_by(BusinessProcessRecommendation.created_at.asc(), BusinessProcessRecommendation.id.asc())
        ).scalars().all()
        if not candidate_rows:
            raise ValueError("No business process recommendations available to confirm")

        for row in candidate_rows:
            if row.status == BusinessProcessRecommendationStatus.SUGGESTED.value:
                row.status = BusinessProcessRecommendationStatus.ACCEPTED.value
                self._log_decision(row.id, BusinessProcessDecisionAction.ACCEPT, reason, row.model_version)

        active_rows = self.db.execute(
            select(BusinessProcessRecommendation)
            .where(
                BusinessProcessRecommendation.organization_id == self.organization_id,
                BusinessProcessRecommendation.status.in_(
                    [
                        BusinessProcessRecommendationStatus.ACCEPTED.value,
                        BusinessProcessRecommendationStatus.ADDED.value,
                    ]
                ),
            )
            .order_by(BusinessProcessRecommendation.created_at.asc(), BusinessProcessRecommendation.id.asc())
        ).scalars().all()

        snapshot = {
            "version": BUSINESS_PROCESS_RECOMMENDATION_MODEL_VERSION,
            "confirmedAt": datetime.now(timezone.utc).isoformat(),
            "activeRecommendationIds": [row.id for row in active_rows],
            "activeProcesses": [
                {
                    "recommendationId": row.id,
                    "templateId": row.process_template_id,
                    "name": row.name,
                    "category": row.category,
                    "status": row.status,
                    "sourceRule": row.source_rule,
                    "confidence": row.confidence,
                    "recommendationReason": row.recommendation_reason,
                }
                for row in active_rows
            ],
        }
        org = self.db.get(Organization, self.organization_id)
        if org is None:
            raise LookupError("Organisation not found")
        onboarding_data = org.onboarding_data if isinstance(org.onboarding_data, dict) else {}
        next_onboarding_data = dict(onboarding_data)
        next_onboarding_data["business_process_model"] = snapshot
        org.onboarding_data = next_onboarding_data
        self.db.add(org)
        self._log_decision(
            None,
            BusinessProcessDecisionAction.CONFIRM,
            reason,
            BUSINESS_PROCESS_RECOMMENDATION_MODEL_VERSION,
        )
        self.db.flush()
        return snapshot

    def _transition_recommendation(
        self,
        recommendation_id: str,
        target_status: BusinessProcessRecommendationStatus,
        action: BusinessProcessDecisionAction,
        *,
        reason: dict[str, Any] | str | None,
    ) -> BusinessProcessRecommendation:
        row = self._get_recommendation(recommendation_id)
        if row.status == BusinessProcessRecommendationStatus.REMOVED.value and target_status is not BusinessProcessRecommendationStatus.REMOVED:
            raise ValueError("Removed recommendations cannot be reactivated")
        if row.status == target_status.value:
            return row
        row.status = target_status.value
        self._log_decision(row.id, action, reason, row.model_version)
        self.db.flush()
        return row

    def _build_recommendation_row(self, payload: RecommendationPayload) -> BusinessProcessRecommendation:
        return BusinessProcessRecommendation(
            organization_id=self.organization_id,
            user_id=self.user_id,
            process_template_id=payload.process_template_id,
            name=payload.name,
            category=payload.category,
            confidence=payload.confidence,
            recommendation_reason=payload.recommendation_reason,
            source_rule=payload.source_rule,
            status=payload.status,
            model_version=payload.model_version,
        )

    def _update_suggestion(self, row: BusinessProcessRecommendation, payload: RecommendationPayload) -> None:
        row.user_id = self.user_id
        row.name = payload.name
        row.category = payload.category
        row.confidence = payload.confidence
        row.recommendation_reason = payload.recommendation_reason
        row.source_rule = payload.source_rule
        row.status = payload.status
        row.model_version = payload.model_version

    def _select_canonical_recommendation(
        self,
        rows: Sequence[BusinessProcessRecommendation],
    ) -> BusinessProcessRecommendation | None:
        if not rows:
            return None
        non_suggested_rows = [row for row in rows if row.status != BusinessProcessRecommendationStatus.SUGGESTED.value]
        candidates = non_suggested_rows or list(rows)
        return max(candidates, key=lambda row: (row.created_at, row.id))

    def _retire_suggestion(self, row: BusinessProcessRecommendation) -> None:
        if row.status != BusinessProcessRecommendationStatus.SUGGESTED.value:
            return
        row.status = BusinessProcessRecommendationStatus.REMOVED.value
        self._log_decision(
            row.id,
            BusinessProcessDecisionAction.REMOVE,
            {"summary": "Superseded by regenerated recommendations", "details": {"superseded": True}},
            row.model_version,
        )

    def _get_recommendation(self, recommendation_id: str) -> BusinessProcessRecommendation:
        row = self.db.get(BusinessProcessRecommendation, recommendation_id)
        if row is None or row.organization_id != self.organization_id:
            raise LookupError("Business process recommendation not found")
        return row

    def _log_decision(
        self,
        recommendation_id: str | None,
        action: BusinessProcessDecisionAction,
        reason: dict[str, Any] | str | None,
        model_version: str,
    ) -> BusinessProcessDecisionLog:
        log = BusinessProcessDecisionLog(
            organization_id=self.organization_id,
            recommendation_id=recommendation_id,
            user_id=self.user_id,
            action=action.value,
            reason=self._normalize_reason(reason, action),
            model_version=model_version,
        )
        self.db.add(log)
        return log

    def _normalize_reason(
        self,
        reason: dict[str, Any] | str | None,
        action: BusinessProcessDecisionAction,
    ) -> dict[str, Any]:
        if isinstance(reason, dict):
            return reason
        if isinstance(reason, str) and reason.strip():
            return {"summary": reason.strip()}
        fallback_summaries = {
            BusinessProcessDecisionAction.ACCEPT: "Business process recommendation accepted",
            BusinessProcessDecisionAction.REMOVE: "Business process recommendation removed",
            BusinessProcessDecisionAction.ADD: "Business process recommendation added",
            BusinessProcessDecisionAction.CONFIRM: "Business process model confirmed",
        }
        return {"summary": fallback_summaries[action]}

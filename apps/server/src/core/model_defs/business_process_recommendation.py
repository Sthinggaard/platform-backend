from __future__ import annotations

from dataclasses import dataclass


BUSINESS_PROCESS_RECOMMENDATION_MODEL_VERSION = "business-process-recommendation-v1"
BUSINESS_PROCESS_RECOMMENDATION_STATUS_SUGGESTED = "suggested"


@dataclass(frozen=True, slots=True)
class BusinessProcessUserReasoning:
    business_function: str
    why_suggested: str
    impact_if_missing: str
    suggested_next_step: str
    relevance_label: str
    evidence_summary: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class BusinessProcessRecommendationExplanation:
    score: float
    matched_inputs: tuple[str, ...]
    user_reasoning: BusinessProcessUserReasoning


@dataclass(frozen=True, slots=True)
class BusinessProcessRecommendation:
    process_template_id: str
    name: str
    category: str
    confidence: float
    recommendation_reason: str
    source_rule: str
    score: float = 0.0
    matched_inputs: tuple[str, ...] = ()
    user_reasoning: BusinessProcessUserReasoning | None = None
    status: str = BUSINESS_PROCESS_RECOMMENDATION_STATUS_SUGGESTED
    model_version: str = BUSINESS_PROCESS_RECOMMENDATION_MODEL_VERSION


@dataclass(frozen=True, slots=True)
class BusinessProcessRecommendationSet:
    model_version: str
    recommendations: tuple[BusinessProcessRecommendation, ...]

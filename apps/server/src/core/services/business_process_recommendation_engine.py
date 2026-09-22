from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable

from src.core.constants.business_process_templates import (
    BUSINESS_PROCESS_TEMPLATES,
    BusinessProcessTemplate,
    get_business_process_reasoning_template,
    get_business_process_template,
)
from src.core.model_defs.business_process_recommendation import (
    BUSINESS_PROCESS_RECOMMENDATION_MODEL_VERSION,
    BusinessProcessRecommendation,
    BusinessProcessRecommendationExplanation,
    BusinessProcessRecommendationSet,
    BusinessProcessUserReasoning,
)
from src.pretenant.risk_intelligence import OrganisationProfile


@dataclass(frozen=True, slots=True)
class _RuleMatch:
    rule_id: str
    description: str
    weight: float


def relevance_label(confidence: float) -> str:
    if confidence >= 0.75:
        return "High"
    if confidence >= 0.50:
        return "Medium"
    return "Low"


class BusinessProcessRecommendationEngine:
    def __init__(self, model_version: str = BUSINESS_PROCESS_RECOMMENDATION_MODEL_VERSION):
        self.model_version = model_version

    def recommend(self, profile: OrganisationProfile) -> BusinessProcessRecommendationSet:
        scored_recommendations = [
            self._recommend_for_template(template, profile)
            for template in BUSINESS_PROCESS_TEMPLATES
        ]
        scored_recommendations.sort(
            key=lambda item: (-item[0], -item[1].confidence, item[1].process_template_id)
        )
        return BusinessProcessRecommendationSet(
            model_version=self.model_version,
            recommendations=tuple(recommendation for _, recommendation in scored_recommendations),
        )

    def _recommend_for_template(
        self,
        template: BusinessProcessTemplate,
        profile: OrganisationProfile,
    ) -> tuple[float, BusinessProcessRecommendation]:
        matches = self._match_rules(template, profile)
        raw_score, confidence = self._score(template, matches)
        source_rule = matches[0].rule_id if matches else "RULE_DEFAULT_BASELINE"
        matched_inputs = self._matched_inputs(template.id, profile, matches)
        user_reasoning = self.build_user_reasoning(
            template.id,
            source_rule,
            profile,
            matched_inputs,
            confidence,
        )
        reason = self._compose_reason(template, profile, matches)
        return raw_score, BusinessProcessRecommendation(
            process_template_id=template.id,
            name=template.name,
            category=template.category,
            confidence=confidence,
            recommendation_reason=reason,
            source_rule=source_rule,
            score=raw_score,
            matched_inputs=matched_inputs,
            user_reasoning=user_reasoning,
            model_version=self.model_version,
        )

    def explain_recommendation(
        self,
        template_id: str,
        profile: OrganisationProfile,
        source_rule: str,
        confidence: float,
    ) -> BusinessProcessRecommendationExplanation:
        template = get_business_process_template(template_id)
        matches = self._match_rules(template, profile)
        raw_score, _ = self._score(template, matches)
        matched_inputs = self._matched_inputs(template.id, profile, matches)
        user_reasoning = self.build_user_reasoning(
            template_id,
            source_rule,
            profile,
            matched_inputs,
            confidence,
        )
        return BusinessProcessRecommendationExplanation(
            score=raw_score,
            matched_inputs=matched_inputs,
            user_reasoning=user_reasoning,
        )

    def build_user_reasoning(
        self,
        template_id: str,
        source_rule: str,
        profile: OrganisationProfile,
        matched_inputs: tuple[str, ...],
        confidence: float,
    ) -> BusinessProcessUserReasoning:
        template = get_business_process_reasoning_template(template_id)
        evidence_summary = self._build_evidence_summary(template_id, source_rule, profile, matched_inputs)
        return BusinessProcessUserReasoning(
            business_function=template.plain_name,
            why_suggested=template.business_owner_summary,
            impact_if_missing=template.what_can_go_wrong,
            suggested_next_step=template.when_to_accept,
            relevance_label=relevance_label(confidence),
            evidence_summary=evidence_summary,
        )

    def _match_rules(self, template: BusinessProcessTemplate, profile: OrganisationProfile) -> list[_RuleMatch]:
        matches: list[_RuleMatch] = []
        industry_code = (profile.industry_code or "").strip()
        size_bracket = (profile.size_bracket or "").strip().lower()
        geography = (profile.geography or "").strip().upper()
        it_dependency = (profile.it_dependency or "").strip().lower()
        risk_appetite = (profile.risk_appetite or "").strip().lower()
        asset_categories = {value.strip().lower() for value in (profile.selected_asset_categories or []) if value.strip()}
        regulatory_flags = {value.strip().upper() for value in (profile.regulatory_flags or []) if value.strip()}
        business_model_tags = {value.strip().lower() for value in (profile.business_model_tags or []) if value.strip()}

        if industry_code.startswith("62") or industry_code.startswith("63"):
            matches.append(
                _RuleMatch(
                    rule_id="RULE_INDUSTRY_SOFTWARE",
                    description="Software or digital service industry signal supports a SaaS operating model.",
                    weight=0.14,
                )
            )

        if template.id == "saas-core-platform":
            matches.extend(
                self._collect_specific_matches(
                    [
                        ("RULE_IT_DEPENDENCY_CRITICAL", it_dependency in {"high", "critical"}, "Operational dependency on IT makes the core platform more critical.", 0.12),
                        ("RULE_SUBSCRIPTION_MODEL_CORE", "subscription" in business_model_tags, "Subscription revenue reinforces the core platform as a business-critical process.", 0.10),
                        (
                            "RULE_MULTI_SITE_CORE",
                            profile.locations > 1,
                            "Multiple locations increase the coordination burden around the shared platform.",
                            0.04,
                        ),
                        (
                            "RULE_CORE_ASSET_SURFACE",
                            bool(asset_categories & {"identity", "cloud", "application", "data", "network"}),
                            "Identity, cloud, application, data, and network assets indicate a broad platform surface.",
                            0.06,
                        ),
                    ]
                )
            )
        elif template.id == "customer-lifecycle":
            matches.extend(
                self._collect_specific_matches(
                    [
                        (
                            "RULE_CUSTOMER_SUCCESS_MODEL",
                            bool(business_model_tags & {"subscription", "customer_success"}),
                            "Recurring customer success activity is a strong signal for lifecycle management.",
                            0.18,
                        ),
                        (
                            "RULE_CUSTOMER_COMMUNICATIONS",
                            bool(asset_categories & {"email", "application", "data"}),
                            "Customer-facing communications and application workflows support lifecycle activity.",
                            0.08,
                        ),
                        (
                            "RULE_GROWTH_FOCUS",
                            size_bracket in {"startup", "smb", "mid", "mid_market"},
                            "Smaller operating models usually need tighter customer onboarding and retention loops.",
                            0.06,
                        ),
                        (
                            "RULE_BALANCED_RISK",
                            risk_appetite in {"balanced", "aggressive"},
                            "Growth-oriented risk appetite increases the need for clear customer lifecycle controls.",
                            0.05,
                        ),
                    ]
                )
            )
        elif template.id == "billing-subscription":
            matches.extend(
                self._collect_specific_matches(
                    [
                        (
                            "RULE_RECURRING_REVENUE",
                            bool(business_model_tags & {"subscription", "usage_based", "recurring_revenue"}),
                            "Recurring revenue signals make billing and subscription management material.",
                            0.22,
                        ),
                        (
                            "RULE_PCI_PAYMENT_EXPOSURE",
                            "PCI" in regulatory_flags,
                            "PCI exposure increases the significance of billing operations.",
                            0.18,
                        ),
                        (
                            "RULE_FINANCE_SYSTEM_SURFACE",
                            bool(asset_categories & {"data", "application", "cloud"}),
                            "Billing depends on transactional data, application, and cloud systems.",
                            0.08,
                        ),
                        (
                            "RULE_SCALE_REVENUE",
                            size_bracket in {"mid_market", "enterprise"},
                            "Larger organisations usually need stronger billing and entitlement controls.",
                            0.06,
                        ),
                    ]
                )
            )
        elif template.id == "security-operations":
            matches.extend(
                self._collect_specific_matches(
                    [
                        (
                            "RULE_SECURITY_REGULATORY_PRESSURE",
                            bool(regulatory_flags & {"GDPR", "NIS2", "ISO27001", "DORA"}),
                            "Security and compliance regulation makes security operations a direct control requirement.",
                            0.18,
                        ),
                        (
                            "RULE_SECURITY_DEPENDENCY",
                            it_dependency in {"high", "critical"},
                            "High dependency on technology increases the need for active security operations.",
                            0.18,
                        ),
                        (
                            "RULE_SECURITY_ASSET_SURFACE",
                            bool(asset_categories & {"endpoint", "network", "email", "backup", "vendor", "identity", "cloud"}),
                            "Operational assets expose a meaningful security operations surface.",
                            0.12,
                        ),
                        (
                            "RULE_DISTRIBUTED_OPERATIONS",
                            profile.locations > 1,
                            "Distributed operations increase monitoring and response complexity.",
                            0.06,
                        ),
                    ]
                )
            )
        elif template.id == "compliance-governance":
            matches.extend(
                self._collect_specific_matches(
                    [
                        (
                            "RULE_COMPLIANCE_REGULATORY_PRESSURE",
                            bool(regulatory_flags),
                            "Regulatory obligations are a direct compliance and governance signal.",
                            0.22,
                        ),
                        (
                            "RULE_NORDIC_GOVERNANCE_CONTEXT",
                            geography in {"DK", "SE", "NO", "FI", "IS", "EMEA", "NORDICS"},
                            "Nordic or EMEA operating context tends to require stronger governance evidence.",
                            0.10,
                        ),
                        (
                            "RULE_COMPLIANCE_SCALE",
                            size_bracket in {"mid_market", "enterprise"},
                            "Larger organisations usually need more formal governance processes.",
                            0.08,
                        ),
                        (
                            "RULE_CONSERVATIVE_RISK_PROFILE",
                            risk_appetite in {"conservative", "balanced"},
                            "Lower risk appetite increases the importance of compliance controls and evidence.",
                            0.05,
                        ),
                    ]
                )
            )

        if not matches:
            matches.append(
                _RuleMatch(
                    rule_id="RULE_DEFAULT_BASELINE",
                    description="Fallback baseline keeps the engine deterministic when no stronger rule matches.",
                    weight=0.04,
                )
            )
        matches.sort(key=lambda item: (-item.weight, item.rule_id))
        return matches

    def _collect_specific_matches(
        self,
        candidates: Iterable[tuple[str, bool, str, float]],
    ) -> list[_RuleMatch]:
        return [
            _RuleMatch(rule_id=rule_id, description=description, weight=weight)
            for rule_id, condition, description, weight in candidates
            if condition
        ]

    def _matched_inputs(
        self,
        template_id: str,
        profile: OrganisationProfile,
        matches: list[_RuleMatch],
    ) -> tuple[str, ...]:
        template = get_business_process_reasoning_template(template_id)
        matched_inputs: list[str] = []
        for match in matches:
            phrase = template.matched_input_phrases.get(match.rule_id)
            if phrase:
                matched_inputs.append(phrase)
        if not matched_inputs:
            matched_inputs.append("default baseline applied")
        return tuple(dict.fromkeys(matched_inputs))

    def _build_evidence_summary(
        self,
        template_id: str,
        source_rule: str,
        profile: OrganisationProfile,
        matched_inputs: tuple[str, ...],
    ) -> tuple[str, ...]:
        template = get_business_process_reasoning_template(template_id)
        matches = self._match_rules(get_business_process_template(template_id), profile)
        evidence: list[str] = []
        for match in matches:
            phrase = template.evidence_phrases.get(match.rule_id)
            if phrase:
                evidence.append(phrase)
        if not evidence:
            fallback = template.evidence_phrases.get(source_rule)
            if fallback:
                evidence.append(fallback)
        if not evidence and matched_inputs:
            evidence.append(matched_inputs[0])
        if not evidence:
            evidence.append("Default baseline applied")
        return tuple(dict.fromkeys(evidence))

    def _score(self, template: BusinessProcessTemplate, matches: list[_RuleMatch]) -> tuple[float, float]:
        base = 0.46 if template.default_criticality == "high" else 0.38
        raw_score = base + sum(match.weight for match in matches)
        confidence = round(min(0.97, raw_score), 2)
        return round(raw_score, 4), confidence

    def _compose_reason(
        self,
        template: BusinessProcessTemplate,
        profile: OrganisationProfile,
        matches: list[_RuleMatch],
    ) -> str:
        if matches:
            lead = matches[0].description
            if len(matches) > 1:
                trail = matches[1].description
                return f"{lead} {trail}"
            return lead
        return f"Default coverage for {template.name} when limited profile signals are available."

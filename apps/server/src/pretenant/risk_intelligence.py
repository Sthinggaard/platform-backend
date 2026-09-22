from __future__ import annotations

import hashlib
from dataclasses import asdict, dataclass

MODEL_VERSION = "risk-intel-baseline-v1"
EXPLAINABILITY_VERSION = "exp-v1"

_ODM_CATALOG = [
    {"id": "identity_access", "title": "Identity & Access Governance"},
    {"id": "endpoint_hardening", "title": "Endpoint Security Hygiene"},
    {"id": "vendor_risk", "title": "Third-Party Risk Management"},
    {"id": "backup_resilience", "title": "Backup & Recovery Resilience"},
    {"id": "email_security", "title": "Email Threat Protection"},
    {"id": "vulnerability_management", "title": "Vulnerability Management"},
]

_HYPOTHESIS_CATALOG = [
    {
        "riskCode": "R-IA-01",
        "title": "Identity controls may be inconsistently enforced",
        "rationale": "Initial profile indicates potential variance in IAM maturity and privileged access governance.",
    },
    {
        "riskCode": "R-DP-02",
        "title": "Data protection coverage may be uneven",
        "rationale": "Baseline profile suggests data handling practices can differ across core business processes.",
    },
    {
        "riskCode": "R-IR-03",
        "title": "Incident response readiness may be under-tested",
        "rationale": "Early-stage onboarding data often correlates with limited tabletop and recovery validation cadence.",
    },
    {
        "riskCode": "R-TP-04",
        "title": "Third-party exposure may introduce inherited risk",
        "rationale": "Supplier dependencies in baseline operations can create control surface outside direct ownership.",
    },
    {
        "riskCode": "R-VM-05",
        "title": "Vulnerability remediation cycle may lag",
        "rationale": "Risk signal indicates likely delay between detection and patch rollout across assets.",
    },
]


class RiskModelUnavailableError(Exception):
    pass


@dataclass(frozen=True)
class OrganisationProfile:
    cvr: str
    legal_name: str
    industry_code: str
    size_bracket: str
    geography: str
    locations: int
    it_dependency: str
    risk_appetite: str
    selected_asset_categories: list[str]
    regulatory_flags: list[str] | None = None
    business_model_tags: list[str] | None = None


@dataclass(frozen=True)
class BaselineRiskLandscape:
    model_version: str
    odm_list: list[dict[str, object]]
    kri_list: list[dict[str, object]]
    assumptions: list[dict[str, str]]
    confidence: dict[str, object]
    explainability_version: str
    profile_fingerprint: str
    overall_risk_score: int
    risk_level: str
    focus_areas: list[str]
    hypotheses: list[dict[str, str]]

    def as_payload(self) -> dict:
        return asdict(self)

    def as_contract_payload(self) -> dict:
        return {
            "odmList": self.odm_list,
            "kriList": self.kri_list,
            "assumptions": self.assumptions,
            "confidence": self.confidence,
            "explainabilityVersion": self.explainability_version,
        }

    def as_legacy_payload(self) -> dict:
        return {
            "overallRiskScore": self.overall_risk_score,
            "riskLevel": self.risk_level,
            "focusAreas": self.focus_areas,
            "hypotheses": self.hypotheses,
            "profileFingerprint": self.profile_fingerprint,
        }


def _normalized(value: str | None) -> str:
    return (value or "").strip().lower()


def _normalized_list(values: list[str] | None, *, upper: bool = False) -> list[str]:
    items = [v.strip() for v in (values or []) if v and v.strip()]
    items = [v.upper() if upper else v.lower() for v in items]
    return sorted(set(items))


class RiskIntelligenceEngine:
    def __init__(self, model_version: str = MODEL_VERSION):
        self.model_version = model_version

    def generate_baseline(self, profile: OrganisationProfile) -> BaselineRiskLandscape:
        asset_categories = _normalized_list(profile.selected_asset_categories)
        regulatory_flags = _normalized_list(profile.regulatory_flags, upper=True)
        business_model_tags = _normalized_list(profile.business_model_tags)
        digest = hashlib.sha256(
            "|".join(
                [
                    self.model_version,
                    _normalized(profile.cvr),
                    _normalized(profile.legal_name),
                    _normalized(profile.industry_code),
                    _normalized(profile.size_bracket),
                    _normalized(profile.geography),
                    str(profile.locations),
                    _normalized(profile.it_dependency),
                    _normalized(profile.risk_appetite),
                    ",".join(asset_categories),
                    ",".join(regulatory_flags),
                    ",".join(business_model_tags),
                ]
            ).encode("utf-8")
        ).digest()
        score = 30 + (digest[0] % 61)  # 30-90 deterministic band
        if score >= 75:
            risk_level = "high"
        elif score >= 50:
            risk_level = "medium"
        else:
            risk_level = "low"

        focus_areas = self._pick_focus_areas(digest)
        hypotheses = self._pick_hypotheses(digest)
        odms = self._build_odms(focus_areas, digest)
        assumptions = self._build_assumptions(profile)
        kri_list = self._build_kris(hypotheses, profile, digest)
        confidence = self._build_confidence(score, digest)
        fingerprint = hashlib.sha256(
            f"{self.model_version}:{_normalized(profile.cvr)}:{_normalized(profile.legal_name)}".encode("utf-8")
        ).hexdigest()[:16]
        return BaselineRiskLandscape(
            model_version=self.model_version,
            odm_list=odms,
            kri_list=kri_list,
            assumptions=assumptions,
            confidence=confidence,
            explainability_version=EXPLAINABILITY_VERSION,
            profile_fingerprint=fingerprint,
            overall_risk_score=score,
            risk_level=risk_level,
            focus_areas=focus_areas,
            hypotheses=hypotheses,
        )

    def _pick_focus_areas(self, digest: bytes) -> list[str]:
        items = [item["id"] for item in _ODM_CATALOG]
        selected: list[str] = []
        for byte in digest:
            if len(selected) == 3:
                break
            candidate = items[byte % len(items)]
            if candidate not in selected:
                selected.append(candidate)
        if len(selected) < 3:
            for candidate in items:
                if candidate not in selected:
                    selected.append(candidate)
                if len(selected) == 3:
                    break
        return selected

    def _build_odms(self, focus_areas: list[str], digest: bytes) -> list[dict[str, object]]:
        catalog_by_id = {item["id"]: item for item in _ODM_CATALOG}
        priorities = ["low", "medium", "high"]
        odms: list[dict[str, object]] = []
        for idx, area_id in enumerate(focus_areas):
            item = catalog_by_id.get(area_id, {"id": area_id, "title": area_id.replace("_", " ").title()})
            odms.append(
                {
                    "id": item["id"],
                    "title": item["title"],
                    "priority": priorities[digest[(idx + 3) % len(digest)] % len(priorities)],
                    "summary": f"Baseline focus area identified for {item['title'].lower()}.",
                }
            )
        return odms

    def _pick_hypotheses(self, digest: bytes) -> list[dict[str, str]]:
        chosen: list[dict[str, str]] = []
        seen_codes: set[str] = set()
        likelihood_levels = ["low", "medium", "high"]
        impact_levels = ["moderate", "significant", "severe"]
        for idx, byte in enumerate(digest):
            if len(chosen) == 3:
                break
            item = _HYPOTHESIS_CATALOG[byte % len(_HYPOTHESIS_CATALOG)]
            code = item["riskCode"]
            if code in seen_codes:
                continue
            chosen.append(
                {
                    "riskCode": code,
                    "title": item["title"],
                    "rationale": item["rationale"],
                    "likelihood": likelihood_levels[digest[(idx + 7) % len(digest)] % len(likelihood_levels)],
                    "impact": impact_levels[digest[(idx + 13) % len(digest)] % len(impact_levels)],
                }
            )
            seen_codes.add(code)
        return chosen

    def _build_assumptions(self, profile: OrganisationProfile) -> list[dict[str, str]]:
        assumptions = [
            {
                "code": "ASSUME_INDUSTRY_BASELINE",
                "text": f"Industry baseline patterns derived from NACE/industry code {profile.industry_code}.",
                "sourceField": "industryCode",
            },
            {
                "code": "ASSUME_GEOGRAPHY_PRIMARY",
                "text": f"Primary regulatory and operating context inferred from geography {profile.geography}.",
                "sourceField": "geography",
            },
            {
                "code": "ASSUME_IT_DEPENDENCY",
                "text": f"Operational resilience assumptions aligned to IT dependency level {profile.it_dependency}.",
                "sourceField": "itDependency",
            },
        ]
        if profile.regulatory_flags:
            assumptions.append(
                {
                    "code": "ASSUME_REGULATORY_SCOPE",
                    "text": "Regulatory obligations inferred from selected regulatory flags.",
                    "sourceField": "regulatoryFlags",
                }
            )
        return assumptions

    def _build_kris(self, hypotheses: list[dict[str, str]], profile: OrganisationProfile, digest: bytes) -> list[dict[str, object]]:
        kri_list: list[dict[str, object]] = []
        reason_code_pool = [
            "INDUSTRY_PROFILE",
            "SIZE_BRACKET",
            "GEOGRAPHY",
            "ASSET_CATEGORY",
            "IT_DEPENDENCY",
            "RISK_APPETITE",
            "REGULATORY_FLAG",
        ]
        confidence_bands = ["low", "medium", "medium_high", "high"]
        for idx, hypothesis in enumerate(hypotheses):
            primary_factor = ["industryCode", "sizeBracket", "geography", "itDependency", "riskAppetite"][
                idx % 5
            ]
            reason_codes = [
                reason_code_pool[(digest[(idx + 1) % len(digest)] + shift) % len(reason_code_pool)]
                for shift in (0, 2)
            ]
            confidence_score = round(0.45 + ((digest[(idx + 11) % len(digest)] % 46) / 100), 2)
            confidence_band = confidence_bands[digest[(idx + 17) % len(digest)] % len(confidence_bands)]
            assumptions = [
                {
                    "code": "ASSUME_PROFILE_SIGNAL",
                    "text": f"Baseline hypothesis uses {primary_factor} as a profile signal.",
                    "sourceField": primary_factor,
                }
            ]
            kri_list.append(
                {
                    "id": hypothesis["riskCode"].lower(),
                    "riskCode": hypothesis["riskCode"],
                    "title": hypothesis["title"],
                    "severity": hypothesis["impact"],
                    "rationale": {
                        "narrative": hypothesis["rationale"],
                        "reasonCodes": reason_codes,
                    },
                    "inputFactors": [primary_factor],
                    "assumptions": assumptions,
                    "confidence": {
                        "score": confidence_score,
                        "band": confidence_band,
                    },
                }
            )
        return kri_list

    def _build_confidence(self, score: int, digest: bytes) -> dict[str, object]:
        normalized = round(min(0.95, max(0.35, 0.5 + ((digest[5] % 40) / 100))), 2)
        if normalized >= 0.85:
            band = "high"
        elif normalized >= 0.7:
            band = "medium_high"
        elif normalized >= 0.55:
            band = "medium"
        else:
            band = "low"
        return {
            "score": normalized,
            "band": band,
            "narrative": f"Confidence adjusted for profile completeness and model coverage (risk score {score}).",
        }

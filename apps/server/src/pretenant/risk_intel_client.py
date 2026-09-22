from __future__ import annotations

from dataclasses import dataclass
from typing import Callable, Literal

from src.pretenant.risk_intelligence import (
    BaselineRiskLandscape,
    OrganisationProfile,
    RiskIntelligenceEngine,
    RiskModelUnavailableError,
)


@dataclass(frozen=True)
class RiskIntelligenceClientResult:
    baseline: BaselineRiskLandscape
    model_version: str
    contract_payload: dict[str, object]
    legacy_payload: dict[str, object]


class RiskIntelligenceClient:
    """Adapter boundary for pre-tenant -> risk-intel compute.

    The implementation is in-process today, but centralizing calls here lets us
    switch to an internal HTTP client (`POST /risk-intel/baseline`) without
    changing public onboarding route orchestration.
    """

    def __init__(
        self,
        *,
        model_version: str | None = None,
        engine_factory: Callable[[], object] | None = None,
        mode: Literal["inprocess", "internal_contract"] = "inprocess",
    ):
        self._model_version = model_version
        self._engine_factory = engine_factory
        self._mode = mode

    def compute_baseline(self, profile: OrganisationProfile) -> RiskIntelligenceClientResult:
        if self._mode not in {"inprocess", "internal_contract"}:
            raise ValueError(f"Unsupported RiskIntelligenceClient mode: {self._mode}")
        if self._mode == "internal_contract":
            return self._compute_via_internal_contract(profile)

        # `inprocess` mode: call the pure engine directly.
        if self._engine_factory is not None:
            engine = self._engine_factory()
        else:
            engine = (
                RiskIntelligenceEngine(model_version=self._model_version)
                if self._model_version
                else RiskIntelligenceEngine()
            )
        try:
            baseline = engine.generate_baseline(profile)
        except RiskModelUnavailableError:
            raise
        return RiskIntelligenceClientResult(
            baseline=baseline,
            model_version=baseline.model_version,
            contract_payload=baseline.as_contract_payload(),
            legacy_payload=baseline.as_legacy_payload(),
        )

    def _compute_via_internal_contract(self, profile: OrganisationProfile) -> RiskIntelligenceClientResult:
        # Lazy import avoids circular module loading during app startup.
        from fastapi.testclient import TestClient

        from src.api.main import app

        request_model_version = self._model_version or "current"
        payload = {
            "modelVersion": request_model_version,
            "organisationProfile": {
                "industryCode": profile.industry_code,
                "sizeBracket": profile.size_bracket,
                "geography": profile.geography,
                "locations": profile.locations,
                "itDependency": profile.it_dependency,
                "riskAppetite": profile.risk_appetite,
                "selectedAssetCategories": profile.selected_asset_categories,
                "regulatoryFlags": profile.regulatory_flags or [],
                "businessModelTags": profile.business_model_tags or [],
            },
        }

        with TestClient(app) as client:
            resp = client.post("/risk-intel/baseline", json=payload)
        if resp.status_code >= 500:
            raise RiskModelUnavailableError("Risk intelligence contract endpoint unavailable")
        if resp.status_code != 200:
            raise RiskModelUnavailableError(f"Risk intelligence contract call failed ({resp.status_code})")

        data = resp.json()
        contract_payload = data.get("baselineRiskLandscape") or {}
        model_version = data.get("modelVersion") or self._model_version or ""

        # Transitional compatibility: public onboarding still returns a legacy payload.
        # Derive it from the same pure engine so callers remain stable while the
        # legacy baselineRiskLandscape field is phased out.
        if self._engine_factory is not None:
            engine = self._engine_factory()
        else:
            engine = RiskIntelligenceEngine(model_version=model_version or self._model_version)
        baseline = engine.generate_baseline(profile)
        return RiskIntelligenceClientResult(
            baseline=baseline,
            model_version=model_version or baseline.model_version,
            contract_payload=contract_payload,
            legacy_payload=baseline.as_legacy_payload(),
        )

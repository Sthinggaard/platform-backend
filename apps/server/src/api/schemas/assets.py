from __future__ import annotations

from typing import Literal, Optional

from pydantic import BaseModel, Field, field_validator, model_validator

from src.core.models import (
    ConnectionState,
    ConnectivityStatus,
    Criticality,
    Environment,
    ScanStartMode,
    SetupConfidence,
)
from src.core.constants import AssetArchetype, LAYER_ARCHETYPES, Provider, PROVIDERS

ALLOWED_INTENT = {"SECURITY_MONITORING", "COMPLIANCE", "AUDIT_EVIDENCE", "DRIFT_DETECTION"}


class CreateAssetRequest(BaseModel):
    display_name: str = Field(..., min_length=1, max_length=200)
    type: str
    provider: str
    provider_display_name: Optional[str] = None
    environment: Environment
    criticality: Criticality
    layer: str = Field(..., pattern=r"^L[1-7]$")
    archetype: AssetArchetype
    secondary_layers: list[int] | None = None
    intent: list[str]
    setup_confidence: SetupConfidence
    scan_start_mode: ScanStartMode
    business_owner_ref: str
    technical_owner_ref: str
    setup_assignee_ref: str | None = None
    provider_account_id: str | None = None
    access_method: Literal["CROSS_ACCOUNT_ROLE", "SERVICE_PRINCIPAL", "OIDC", "API_KEY"] | None = None
    permission_preset: str | None = "SECURITY_READONLY"
    provider_resource_id: str | None = None
    advanced_override: bool = False
    override_reason: str | None = None

    @field_validator("provider")
    @classmethod
    def validate_provider(cls, v: str) -> str:
        if v not in PROVIDERS:
            raise ValueError("provider must be one of known providers or OTHER")
        return v

    @field_validator("provider_display_name")
    @classmethod
    def validate_other_name(cls, v: Optional[str], values) -> Optional[str]:
        provider = values.data.get("provider")
        if provider == Provider.OTHER.value and not v:
            raise ValueError("provider_display_name is required when provider is OTHER")
        return v

    @field_validator("layer")
    @classmethod
    def validate_layer(cls, v: str) -> str:
        if v not in LAYER_ARCHETYPES:
            raise ValueError("layer must be one of L1-L7")
        return v


    @field_validator("provider_account_id")
    @classmethod
    def validate_account(cls, v: Optional[str], values):
        archetype = values.data.get("archetype")
        provider = values.data.get("provider")
        if archetype == AssetArchetype.CLOUD_ACCOUNT_GOVERNANCE:
            if not v:
                raise ValueError("provider_account_id is required for governance archetype")
            if provider == Provider.AWS.value and (not v.isdigit() or len(v) != 12):
                raise ValueError("provider_account_id must be a 12-digit AWS account id")
        return v

    @field_validator("secondary_layers")
    @classmethod
    def validate_layers(cls, v, values):
        if not v:
            return None
        primary = values.data.get("layer")
        bad = [n for n in v if n < 1 or n > 7 or n == primary]
        if bad:
            raise ValueError("secondary_layers must be 1-7 and not include primary")
        return v

    @field_validator("intent")
    @classmethod
    def validate_intent(cls, v: list[str]) -> list[str]:
        if not v:
            raise ValueError("intent must be non-empty")
        invalid = [x for x in v if x not in ALLOWED_INTENT]
        if invalid:
            raise ValueError(f"intent contains invalid values: {invalid}")
        return v

    @field_validator("access_method")
    @classmethod
    def warn_access(cls, v):
        if v == "API_KEY":
            raise ValueError("API_KEY access not supported in MVP")
        return v

    @model_validator(mode="after")
    def validate_override_constraints(self):
        if self.advanced_override and not self.override_reason:
            raise ValueError("override_reason is required when advanced_override is enabled")
        allowed_archetypes = LAYER_ARCHETYPES.get(self.layer, [])
        if (
            self.layer
            and self.archetype
            and self.archetype not in allowed_archetypes
            and not self.advanced_override
        ):
            raise ValueError("archetype not allowed for selected layer")
        return self


class CreateAssetResponse(BaseModel):
    asset_id: int
    connectivity_status: ConnectivityStatus
    external_id: str
    complete_setup_url: str


class CompleteAccessSetupRequest(BaseModel):
    role_arn: str


class VerifyConnectionResponse(BaseModel):
    success: bool
    connectivity_status: ConnectivityStatus
    connection_state: ConnectionState
    diagnostic: str | None = None

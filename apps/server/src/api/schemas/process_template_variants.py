"""HTTP contracts for governed Business Process template variants."""

from pydantic import BaseModel, Field

from src.core.constants.process_template_variant_enums import (
    ProcessBusinessOutcomeKey,
    ProcessTemplateApplicabilityReason,
    ProcessTemplateIndustryFit,
)


class ProcessTemplateVariantResponse(BaseModel):
    template_key: str
    template_version: int
    business_outcome_key: ProcessBusinessOutcomeKey
    name: str
    description: str
    core_service_count: int
    industry_fit: ProcessTemplateIndustryFit
    applicability_reason: ProcessTemplateApplicabilityReason


class ProcessTemplateVariantsResponse(BaseModel):
    process_id: str
    current_template_key: str
    business_outcome_key: ProcessBusinessOutcomeKey
    variants: list[ProcessTemplateVariantResponse]


class ApplyProcessTemplateVariantRequest(BaseModel):
    acknowledge_rebase: bool = Field(alias="acknowledgeRebase")

    model_config = {"populate_by_name": True}

    def has_rebase_acknowledgement(self) -> bool:
        return self.acknowledge_rebase is True

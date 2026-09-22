"""Dependency bundle router facade.

This module remains the stable import surface for `src.api.main` and test code,
but the implementation is split into focused route/helper modules:

- bundle_contracts.py        : Pydantic request/response contracts
- bundle_common.py           : shared bundle lookup / serialization / logging helpers
- bundle_template_routes.py  : template load, bundle read, bundle mutation
- bundle_validation_routes.py: validate, publish, version history
- bundle_archetype_routes.py : archetype suggestion and persistence
- bundle_slot_mapping_routes.py : slot-mapping publish flow
- bundle_mapping_decide.py   : one owner decision about one slot, without publishing
- bundle_slot_suggestion_routes.py : intelligence-engine slot-mapping suggestions (BSP-05)
"""

from __future__ import annotations

from fastapi import APIRouter

from src.core.constants.dependency_templates import get_template

from . import bundle_archetype_routes, bundle_mapping_decide, bundle_slot_mapping_routes, bundle_slot_suggestion_routes, bundle_template_routes, bundle_validation_routes
from .bundle_archetype_routes import set_archetype, suggest_archetype, suggest_archetype_from_bia
from .bundle_contracts import (
    ArchetypeSuggestResponse,
    DecideSlotMappingRequest,
    DecideSlotMappingResponse,
    BundleActionRequest,
    BundleVersionResponse,
    DependencyBundleResponse,
    DependencyGroupOut,
    DependencyNodeOut,
    LoadTemplateResponse,
    PublishSlotMappingsRequest,
    PublishSlotMappingsResponse,
    SetArchetypeRequest,
    SlotMappingDecision,
    SlotPublishFinding,
    TemplatePatternOptionOut,
    ValidateBundleRequest,
    ValidateBundleResponse,
    ValidationFindingOut,
)
from .bundle_mapping_decide import decide_slot_mapping
from .bundle_slot_mapping_routes import publish_slot_mappings
from .bundle_slot_suggestion_routes import suggest_service_slot_mappings
from .bundle_template_routes import get_bundle_route as get_bundle, load_template, update_bundle
from .bundle_validation_routes import get_bundle_version, list_bundle_versions, publish_bundle, validate_bundle

router = APIRouter(prefix="/api/v1/services", tags=["Dependency Bundles"])
router.include_router(bundle_template_routes.router)
router.include_router(bundle_validation_routes.router)
router.include_router(bundle_archetype_routes.router)
router.include_router(bundle_slot_mapping_routes.router)
router.include_router(bundle_mapping_decide.router)
router.include_router(bundle_slot_suggestion_routes.router)

__all__ = [
    "ArchetypeSuggestResponse",
    "BundleActionRequest",
    "BundleVersionResponse",
    "DependencyBundleResponse",
    "DependencyGroupOut",
    "DependencyNodeOut",
    "LoadTemplateResponse",
    "DecideSlotMappingRequest",
    "DecideSlotMappingResponse",
    "PublishSlotMappingsRequest",
    "PublishSlotMappingsResponse",
    "SetArchetypeRequest",
    "SlotMappingDecision",
    "SlotPublishFinding",
    "TemplatePatternOptionOut",
    "ValidateBundleRequest",
    "ValidateBundleResponse",
    "ValidationFindingOut",
    "bundle_archetype_routes",
    "bundle_mapping_decide",
    "bundle_slot_mapping_routes",
    "bundle_slot_suggestion_routes",
    "bundle_template_routes",
    "bundle_validation_routes",
    "decide_slot_mapping",
    "get_bundle",
    "get_bundle_version",
    "get_template",
    "list_bundle_versions",
    "load_template",
    "publish_bundle",
    "publish_slot_mappings",
    "router",
    "set_archetype",
    "suggest_archetype",
    "suggest_archetype_from_bia",
    "suggest_service_slot_mappings",
    "update_bundle",
    "validate_bundle",
]

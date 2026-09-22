from __future__ import annotations

from src.core.constants.decision_runtime import (
    BUSINESS_DECISION_ACTION_REJECT,
    BUSINESS_DECISION_ACTIONS,
    DECISION_ROUTE_TO_BUSINESS_ACTION,
)

BUSINESS_DECISION_TAXONOMY_VERSION = "business-decision-taxonomy-v1"


def map_route_to_business_action(route: str) -> str:
    return DECISION_ROUTE_TO_BUSINESS_ACTION.get(route, BUSINESS_DECISION_ACTION_REJECT)


def build_business_decision_taxonomy(
    *,
    recommended_action: str,
    selected_action: str | None = None,
    decision_type: str | None = None,
) -> dict:
    payload = {
        "version": BUSINESS_DECISION_TAXONOMY_VERSION,
        "recommendedRoute": recommended_action,
        "recommendedBusinessAction": map_route_to_business_action(recommended_action),
        "allowedBusinessActions": list(BUSINESS_DECISION_ACTIONS),
        "routeToBusinessAction": dict(DECISION_ROUTE_TO_BUSINESS_ACTION),
    }
    if selected_action is not None:
        payload["selectedRoute"] = selected_action
        payload["selectedBusinessAction"] = map_route_to_business_action(selected_action)
    if decision_type is not None:
        payload["routeRelationship"] = decision_type
    return payload

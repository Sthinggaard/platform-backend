from __future__ import annotations

from datetime import datetime
from typing import Any

from src.core.constants.service_key_archetypes import get_archetype_for_service_key, get_service_key_name
from src.core.constants.value_stream_library import VALUE_STREAM_BY_KEY, infer_value_streams_from_nace
from src.pretenant.company_assumption_catalog import resolve_company_archetype


_FLAGSHIP_PROCESS_PRIORITY = "critical"
_PROCESS_MAP_OPERATIONS_LANE = "operations"
_PROCESS_MAP_PLATFORM_LANE = "platform"
_PROCESS_MAP_TASK_NAMES = {
    "ci_cd_pipeline": "Build release",
    "source_control": "Review source change",
    "deployment_service": "Deploy change",
    "monitoring_service": "Monitor service",
    "identity_service": "Manage identity access",
    "sso_service": "Authenticate workforce",
    "privileged_access": "Review privileged access",
}
_CONTEXT_TEMPLATE_BY_VALUE = {
    "digital_products": "software_delivery",
    "client_expertise": "quote_to_cash",
    "physical_products": "plan_to_produce",
    "sell_or_distribute": "order_to_cash",
    "move_goods_or_people": "shipment_to_delivery",
    "serve_customers": "customer_service",
    "fulfil_orders": "order_to_cash",
    "plan_and_make": "plan_to_produce",
    "deliver_goods": "warehouse_to_delivery",
}


def _flagship_process_key(archetype_keys: tuple[str, ...], inferred_by_key: dict[str, Any]) -> str | None:
    critical_key = next(
        (
            key
            for key in archetype_keys
            if inferred_by_key.get(key) and inferred_by_key[key].suggested_priority == _FLAGSHIP_PROCESS_PRIORITY
        ),
        None,
    )
    return critical_key or next((key for key in archetype_keys if key in VALUE_STREAM_BY_KEY), None)


def _single_answer_value(raw: str | list[str] | None) -> str:
    """Business context values are normally a single choice, but the contract
    allows a list for multi-select questions. Fields consumed here
    (criticalBusinessActivity, primaryBusinessActivity) are single-select
    today; this defensively takes the first entry if a list ever appears
    rather than failing the lookup."""
    if isinstance(raw, list):
        return raw[0] if raw else ""
    return raw or ""


def _context_flagship_process_key(business_context: dict[str, str | list[str]] | None) -> str | None:
    if not business_context:
        return None
    for field in ("criticalBusinessActivity", "primaryBusinessActivity"):
        answer_value = _single_answer_value(business_context.get(field))
        template_key = _CONTEXT_TEMPLATE_BY_VALUE.get(answer_value)
        if template_key in VALUE_STREAM_BY_KEY:
            return template_key
    return None


def _process_map_task_name(service_key: str) -> str:
    return _PROCESS_MAP_TASK_NAMES.get(service_key, f"Operate {get_service_key_name(service_key)}")


def _build_flagship_process_map(template_key: str) -> dict[str, Any]:
    value_stream = VALUE_STREAM_BY_KEY[template_key]
    task_nodes: list[dict[str, Any]] = []
    for index, service_key in enumerate(value_stream.core_service_keys, start=2):
        lane = (
            _PROCESS_MAP_PLATFORM_LANE
            if get_archetype_for_service_key(service_key) == "platform_infrastructure"
            else _PROCESS_MAP_OPERATIONS_LANE
        )
        task_nodes.append(
            {
                "id": f"template:{template_key}:service:{service_key}",
                "lane": lane,
                "col": index,
                "type": "task",
                "name": _process_map_task_name(service_key),
                "taskType": "service",
                "serviceId": f"template:{template_key}:{service_key}",
                "confidence": "assumed",
            }
        )

    start_id = f"template:{template_key}:start"
    end_id = f"template:{template_key}:end"
    node_ids = [start_id, *[node["id"] for node in task_nodes], end_id]
    return {
        "title": value_stream.name,
        "hint": "Assumption preview · owner and dependency validation required",
        "lanes": [
            {"id": _PROCESS_MAP_OPERATIONS_LANE, "label": "Operations"},
            {"id": _PROCESS_MAP_PLATFORM_LANE, "label": "Platforms & systems"},
        ],
        "nodes": [
            {
                "id": start_id,
                "lane": _PROCESS_MAP_OPERATIONS_LANE,
                "col": 1,
                "type": "event",
                "eventType": "start",
                "marker": "none",
                "label": "Process begins",
            },
            *task_nodes,
            {
                "id": end_id,
                "lane": _PROCESS_MAP_OPERATIONS_LANE,
                "col": len(task_nodes) + 2,
                "type": "event",
                "eventType": "end",
                "marker": "none",
                "label": "Process outcome",
            },
        ],
        "flows": [
            {"from": current, "to": following, "kind": "sequence"}
            for current, following in zip(node_ids, node_ids[1:])
        ],
    }


def build_company_assumption_preview(
    *,
    cvr: str | None = None,
    legal_name: str | None = None,
    retrieved_at: datetime | None = None,
    industry_code: str | None,
    industry: str | None,
    size_bracket: str | None,
    geography: str | None,
    business_context: dict[str, str | list[str]] | None = None,
) -> dict[str, Any]:
    archetype = resolve_company_archetype(industry_code)
    archetype_is_specific = archetype.key != "general_business"
    confidence_score = 0.82 if archetype_is_specific and industry_code else 0.56
    confidence_band = "high" if archetype_is_specific and industry_code else "medium"
    inferred_by_key = {
        item.key: item
        for item in infer_value_streams_from_nace(
            nace_code=industry_code or "",
            company_size=size_bracket or "",
        )
    }
    context_flagship_key = _context_flagship_process_key(business_context)
    flagship_key = context_flagship_key or _flagship_process_key(archetype.process_template_keys, inferred_by_key)
    flagship_process = None
    if flagship_key:
        inferred_flagship = inferred_by_key.get(flagship_key)
        flagship_template = VALUE_STREAM_BY_KEY[flagship_key]
        flagship_process = {
            "key": flagship_key,
            "name": flagship_template.name,
            "templateKey": flagship_key,
            "rationale": (
                "This starting point reflects the way you said your organisation delivers value."
                if context_flagship_key
                else inferred_flagship.inference_reason if inferred_flagship else flagship_template.description
            ),
            "confidence": inferred_flagship.confidence if inferred_flagship else confidence_band,
            "priority": inferred_flagship.suggested_priority if inferred_flagship else "standard",
            "source": "company_context_suggestion" if context_flagship_key else "risk_intelligence_engine",
            "selectionBasis": (
                "Your business context and registry facts mapped to the canonical value-stream library."
                if context_flagship_key
                else "CVR industry code and company context mapped to the canonical value-stream library."
            ),
            "processMap": _build_flagship_process_map(flagship_key),
        }
    headline = (
        f"The starting model maps {len(archetype.process_template_keys)} core business processes for this industry pattern. "
        f"{flagship_process['name'] if flagship_process else 'The leading process'} is shown as a business-critical assumption to review during setup."
    )
    source = {
        "type": "registry_industry",
        "cvr": cvr,
        "legalName": legal_name,
        "retrievedAt": retrieved_at.isoformat() if retrieved_at else None,
        "industryCode": industry_code,
        "industry": industry,
        "sizeBracket": size_bracket,
        "geography": geography,
    }
    registry_facts = {
        "cvr": cvr,
        "legalName": legal_name,
        "industryCode": industry_code,
        "industry": industry,
        "sizeBracket": size_bracket,
        "geography": geography,
    }
    known_facts = [key for key, value in registry_facts.items() if value]
    missing_facts = [key for key, value in registry_facts.items() if not value]
    return {
        "archetypeKey": archetype.key,
        "archetypeLabel": archetype.label,
        "summary": archetype.summary,
        "headline": headline,
        "source": source,
        "businessContext": business_context or {},
        "confidence": {"score": confidence_score, "band": confidence_band},
        "completeness": {
            "status": "partial",
            "knownFactCount": len(known_facts),
            "expectedFactCount": len(registry_facts),
            "knownFacts": known_facts,
            "missingFacts": missing_facts,
            "assumptionsRequireConfirmation": True,
        },
        "suggestedProcesses": [
            {
                "key": template_key,
                "name": VALUE_STREAM_BY_KEY[template_key].name,
                "rationale": (
                    inferred_by_key[template_key].inference_reason
                    if template_key in inferred_by_key and archetype_is_specific and industry_code
                    else VALUE_STREAM_BY_KEY[template_key].description
                ),
                "archetypeKey": archetype.key,
                "templateKey": template_key,
                "confidence": inferred_by_key[template_key].confidence if template_key in inferred_by_key and archetype_is_specific else confidence_band,
                "priority": (
                    _FLAGSHIP_PROCESS_PRIORITY
                    if template_key in archetype.critical_process_template_keys
                    else inferred_by_key[template_key].suggested_priority
                    if template_key in inferred_by_key and archetype_is_specific
                    else "standard"
                ),
                "source": "industry_archetype",
            }
            for template_key in archetype.process_template_keys
        ],
        "flagshipProcess": flagship_process,
        "focusAreas": [
            {
                "key": focus.key,
                "title": focus.title,
                "priority": focus.priority,
                "rationale": focus.rationale,
                "source": "industry_archetype",
            }
            for focus in archetype.focus_areas
        ],
        "continuityAssumption": {
            "label": archetype.continuity_assumption.label,
            "description": archetype.continuity_assumption.description,
            "benchmark": archetype.continuity_assumption.benchmark,
            "source": "industry_archetype",
            "status": "assumed",
        },
        "assumptions": [
            {
                "code": "INDUSTRY_ARCHETYPE",
                "text": "The company profile is an initial assumption derived from registry facts and must be confirmed during setup.",
                "sourceField": "industryCode",
            },
            {
                "code": "OPERATING_MODEL",
                "text": "The suggested process and focus areas represent likely starting points, not approved organisational decisions.",
                "sourceField": "industry",
            },
        ],
    }

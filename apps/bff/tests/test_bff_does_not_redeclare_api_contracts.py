"""#227 — a BFF model may not share an API model's name with a different field set.

`apps/bff/app.py` retypes shapes the API already defines. Nothing compared the two,
so they drifted silently and in three different directions:

1. `SignupVerifyTenant` lacked `populate_by_name`, so a **successful** upstream
   response could not be serialised and the BFF answered 500 for a signup the API
   had completed (fixed 2026-08-17).
2. `BusinessContextRequest` typed six fields as `str` where the API used
   `StrEnum`, so the published contract was weaker than the real one.
3. Found by this check: `BaselineRiskResponse` omitted `assumptionStatus` and
   `requiresHumanReview`, and `CvrEnrichmentResponse` omitted `sizeBracket` and
   `geography` — all four *required or meaningful on the API side* and therefore
   stripped by `response_model` before any client saw them.

The duplication itself is not the defect and this does not forbid it; the BFF has
reasons to shape its own responses. **Silent divergence** is the defect. So the rule
is narrow and mechanical: share a name, share a field set — or rename, so the
difference is visible to whoever reads it next.
"""

from __future__ import annotations

import importlib
import inspect

import pytest
from pydantic import BaseModel

import bff.app as bff_app

#: API modules whose models the BFF mirrors. Listed rather than auto-discovered:
#: importing every route module would construct services and stateful stores the
#: BFF has no business touching, and a check with side effects is one people
#: disable.
_API_SCHEMA_MODULES = (
    "src.api.routes.public_onboarding",
    "src.api.schemas.auth",
)

#: Names the BFF deliberately shapes differently. Each entry needs a reason; an
#: empty allowlist is the goal, and adding to it is a decision rather than a fix.
_DELIBERATE_DIVERGENCE: dict[str, str] = {}


def _models_declared_in(module) -> dict[str, type[BaseModel]]:
    return {
        name: obj
        for name, obj in vars(module).items()
        if inspect.isclass(obj)
        and issubclass(obj, BaseModel)
        and obj is not BaseModel
        and obj.__module__ == module.__name__
    }


def _api_models() -> dict[str, type[BaseModel]]:
    collected: dict[str, type[BaseModel]] = {}
    for module_path in _API_SCHEMA_MODULES:
        collected.update(_models_declared_in(importlib.import_module(module_path)))
    return collected


def _same_name_pairs() -> list[tuple[str, type[BaseModel], type[BaseModel]]]:
    bff_models = _models_declared_in(bff_app)
    api_models = _api_models()
    return [
        (name, bff_models[name], api_models[name])
        for name in sorted(set(bff_models) & set(api_models))
    ]


def test_the_check_has_something_to_check() -> None:
    """A guard that silently matches nothing passes forever. If the BFF stops
    mirroring these modules, this fails and someone re-points it rather than
    trusting a green tick over an empty set."""
    pairs = _same_name_pairs()
    assert len(pairs) >= 10, f"only {len(pairs)} same-name pairs found — is _API_SCHEMA_MODULES stale?"


@pytest.mark.parametrize("name", [pair[0] for pair in _same_name_pairs()])
def test_a_shared_name_means_a_shared_field_set(name: str) -> None:
    bff_model, api_model = next((b, a) for n, b, a in _same_name_pairs() if n == name)
    bff_fields = set(bff_model.model_fields)
    api_fields = set(api_model.model_fields)

    if name in _DELIBERATE_DIVERGENCE:
        pytest.skip(f"deliberate: {_DELIBERATE_DIVERGENCE[name]}")

    missing_in_bff = sorted(api_fields - bff_fields)
    extra_in_bff = sorted(bff_fields - api_fields)

    assert not missing_in_bff and not extra_in_bff, (
        f"{name} has drifted from the API's model.\n"
        f"  dropped by the BFF (stripped from responses): {missing_in_bff or 'none'}\n"
        f"  added by the BFF (never sent upstream):       {extra_in_bff or 'none'}\n"
        "Either match the API's model, or rename the BFF's so the difference is "
        "visible, or record it in _DELIBERATE_DIVERGENCE with a reason."
    )

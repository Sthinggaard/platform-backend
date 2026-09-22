"""Response models must not shadow each other.

2026-08-31: `SetupOwnershipResponse` was defined twice in
`organization_structure.py` — once for the standalone `/setup-ownership`
endpoint and once, thirty lines later, for the block nested inside the
prepared-structure response. The later definition silently rebound the name, so
both `/setup-ownership` routes built one shape while FastAPI validated the
result against the other.

Every call returned 500, the middleware's catch-all reported it as "Failed to
process authentication token", and the Organisation Structure step of onboarding
could not be completed. Nothing in the suite noticed.
"""

from __future__ import annotations

import ast
import inspect
from collections import Counter

from src.api.routes import organization_structure as mod


def test_no_response_model_name_is_defined_twice():
    """A duplicate class name is a silent rebind, not an error."""
    tree = ast.parse(inspect.getsource(mod))
    names = [n.name for n in ast.walk(tree) if isinstance(n, ast.ClassDef)]
    duplicates = {name: count for name, count in Counter(names).items() if count > 1}

    assert not duplicates, (
        f"These classes are defined more than once in organization_structure.py: "
        f"{duplicates}. The last definition silently wins, so a route can build one "
        f"shape while its response_model validates another."
    )


def test_setup_ownership_response_is_the_endpoint_shape():
    """The standalone endpoint's model, not the nested prepared-structure one."""
    fields = set(mod.SetupOwnershipResponse.model_fields)
    assert fields == {"technical_setup_owner_user_id"}, fields


def test_prepared_setup_ownership_response_is_the_nested_shape():
    fields = set(mod.PreparedSetupOwnershipResponse.model_fields)
    assert fields == {
        "organisation_administrator_ids",
        "technical_setup_owner_id",
        "technical_contact_ids",
    }, fields


def test_both_setup_ownership_routes_declare_the_endpoint_model():
    routes = [
        r for r in mod.router.routes
        if getattr(r, "path", "").endswith("/setup-ownership")
    ]
    assert routes, "the /setup-ownership routes are gone"
    for route in routes:
        assert route.response_model is mod.SetupOwnershipResponse, (
            f"{sorted(route.methods)} /setup-ownership declares "
            f"{route.response_model}, which cannot represent what the route builds"
        )

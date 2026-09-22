"""Epic A4 — tests for the tenant-isolation structural enforcement checker."""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

# Loaded by file path, not package import: this repo has a top-level
# `scripts/` directory at the monorepo root as well as this one at
# `apps/server/scripts/`, and pytest's sys.path ordering can resolve the
# bare `scripts` package name to either — a path-based load sidesteps
# that ambiguity entirely.
_CHECKER_PATH = Path(__file__).parent.parent / "scripts" / "check_tenant_isolation.py"
_spec = importlib.util.spec_from_file_location("check_tenant_isolation", _CHECKER_PATH)
_checker = importlib.util.module_from_spec(_spec)
sys.modules[_spec.name] = _checker
_spec.loader.exec_module(_checker)

ALLOWLIST = _checker.ALLOWLIST
ROUTES_DIR = _checker.ROUTES_DIR
load_tenant_scoped_models = _checker.load_tenant_scoped_models
run_checks = _checker.run_checks

FIXTURES_DIR = Path(__file__).parent / "fixtures" / "tenant_isolation"

_ALLOWLIST_KEYS = {(a.file, a.function, a.model) for a in ALLOWLIST}


def _violations_in(filename: str) -> list:
    return [v for v in run_checks(FIXTURES_DIR) if v.file == filename]


def test_load_tenant_scoped_models_matches_tenant_repositorys_own_check():
    """The checker's classification must be the exact same guard
    TenantRepository.__init__ already applies — the two must never drift."""
    scoped = load_tenant_scoped_models()
    assert "User" in scoped
    assert "Organization" not in scoped  # the tenant root itself, GlobalRepository's domain


def test_tenant_repository_usage_produces_no_violation():
    assert _violations_in("clean_tenant_repository.py") == []


def test_explicit_organization_id_filter_produces_no_violation():
    assert _violations_in("clean_explicit_filter.py") == []


def test_self_lookup_by_ctx_user_id_produces_no_violation():
    assert _violations_in("clean_self_lookup.py") == []


def test_python_side_org_filter_produces_no_violation():
    assert _violations_in("clean_python_side_filter.py") == []


def test_raw_query_with_no_org_filter_is_flagged():
    violations = _violations_in("violating_raw_query.py")
    assert len(violations) == 1
    v = violations[0]
    assert v.function == "list_all_users_by_status"
    assert v.model == "User"


def test_select_style_query_with_no_org_filter_is_flagged():
    violations = _violations_in("violating_select.py")
    assert len(violations) == 1
    v = violations[0]
    assert v.function == "list_users_by_email_domain"
    assert v.model == "User"


def test_regression_global_model_is_never_flagged_but_tenant_scoped_model_is():
    """The actual H2 mechanism: model classification must correctly
    separate a genuinely global model from a tenant-scoped one in the
    identical unfiltered-query shape."""
    violations = _violations_in("regression_global_vs_scoped.py")
    functions_flagged = {v.function for v in violations}
    assert "get_organization_unfiltered" not in functions_flagged
    assert "get_user_unfiltered" in functions_flagged


def test_allowlist_entries_are_visible_not_silent():
    """An allowlisted violation must still be found by run_checks (visible),
    just excluded from the failing set by main() — never silently absent."""
    real_violations = run_checks(ROUTES_DIR)
    found_keys = {(v.file, v.function, v.model) for v in real_violations}
    assert _ALLOWLIST_KEYS <= found_keys


def test_real_route_tree_has_no_unallowlisted_violations():
    """Pins the known state: fails immediately if any allowlisted site's
    shape changes, or a new instance of the pattern appears anywhere."""
    real_violations = run_checks(ROUTES_DIR)
    failing = [v for v in real_violations if (v.file, v.function, v.model) not in _ALLOWLIST_KEYS]
    assert failing == [], f"Unexpected, non-allowlisted tenant-isolation violations: {failing}"

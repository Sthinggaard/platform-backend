#!/usr/bin/env python3
"""Epic A4 — structural tenant-isolation enforcement gate.

``TenantRepository`` (``core/repository.py``) fails loudly when constructed
against a model with no ``organization_id`` column (Epic A1's H2 fix) — but
that only protects call sites that already chose to use it. Nothing
structurally stops a route from bypassing it entirely with a raw
``db.query(Model)``/``select(Model)`` and no ``organization_id`` filter, which
is exactly the shape that produced C1/H1 (a role-check choice, not a
repository choice). This script closes that gap at CI time.

Design: a route function violates tenant isolation if it queries a
tenant-scoped model (any mapped class with an ``organization_id`` column —
introspected at runtime from the real model registry, the same check
``TenantRepository.__init__`` already performs, so this script's notion of
"tenant-scoped" can never drift from that repository's own) via
``<session>.query(Model)``/``select(Model)``, and the enclosing function
contains no ``Model.organization_id ==`` comparison anywhere. This is a
per-function, not per-statement-chain, heuristic — deliberately simple (in
the same spirit as ``apps/tenant/scripts/enforce-architecture.mjs``'s own
regex-based checks, not a sound type-checker) and verified against every
real route file's actual query shapes before being wired into CI.

A known, disclosed, individually-justified ``ALLOWLIST`` covers 10 sites
found during Epic A4's initial audit — each a child-row lookup that relies
on an upstream object already having been tenant-validated, not a live gap.
Any *new* instance of the pattern, anywhere, fails the build immediately.
"""

from __future__ import annotations

import ast
import sys
from dataclasses import dataclass
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
ROUTES_DIR = REPO_ROOT / "src" / "api" / "routes"

_QUERY_METHOD_NAMES = {"query"}
_FILTER_METHOD_NAMES = {"filter", "filter_by", "where"}


@dataclass(frozen=True)
class Violation:
    file: str
    line: int
    function: str
    model: str


@dataclass(frozen=True)
class AllowedViolation:
    file: str
    function: str
    model: str
    reason: str
    epic_ref: str = "A4"


# Epic A4's audit (a full AST run of check_tenant_isolation.py itself against
# the real route tree, cross-checked against a manual grep-based survey of
# all 59 api/routes/*.py files) found every disclosed, individually-justified
# exception below. Two shapes:
#
# 1. "Trust the caller" (8 entries) — a child-row lookup that relies on an
#    upstream object already having been tenant-validated in the same call
#    chain (not a live gap, but no structural enforcement of its own either).
#    (assets.py's list_asset_findings/list_signals were originally found by
#    the manual survey in this same category, but are NOT listed below —
#    both guard with `if asset.organization_id != tenant.organization_id:
#    raise 404` before the child query, which the checker's own
#    _python_side_org_filter check recognizes as a real, sound tenant check;
#    no allowlist entry is needed, and the checker will correctly re-flag
#    them the moment that guard is ever removed, which a static entry could
#    not do.)
# 2. "Pre-tenant identity-bootstrap flows" and deliberate platform-wide
#    queries (18 entries) — no tenant context exists yet to check against
#    (login/signup/SSO/password-reset/invite/scanner-agent-auth), or the
#    query is intentionally cross-organisation and gated by a non-JWT
#    mechanism instead (learning.py's operator-secret gate, the H1 fix).
#
# See implementation-risk-register.md's A4 section for the full narrative.
ALLOWLIST: list[AllowedViolation] = [
    AllowedViolation(
        file="api/routes/bundle_slot_mapping_routes.py",
        function="get_dependency_group_drill",
        model="Asset",
        reason="Asset PKs are sourced from an already org-filtered SlotInstance query "
        "(SlotInstance.organization_id == ctx.organization_id) earlier in the same function.",
    ),
    AllowedViolation(
        file="api/routes/discovery_command_agent.py",
        function="next_command_route",
        model="DiscoveryRun",
        reason="collector-authenticated route (require_scanner_instance), not a browser TenantContext; "
        "the run is reached only via a command already scoped to this scanner instance.",
    ),
    AllowedViolation(
        file="api/routes/discovery_run.py",
        function="_cancel_execution_plan_if_any",
        model="DiscoveryExecutionPlan",
        reason="plan is looked up by discovery_run_id against a run already tenant-scoped by _require_run "
        "in every caller of this helper.",
    ),
    AllowedViolation(
        file="api/routes/evidence_source.py",
        function="get_scope_route",
        model="EvidenceSourceScope",
        reason="scope looked up by evidence_source_id against a source already tenant-scoped by _require_source.",
    ),
    AllowedViolation(
        file="api/routes/evidence_source.py",
        function="confirm_scope_route",
        model="EvidenceSourceScope",
        reason="same pattern as get_scope_route — source already tenant-scoped by _require_source.",
    ),
    AllowedViolation(
        file="api/routes/processes.py",
        function="_has_published_bundle",
        model="DependencyBundle",
        reason="bundle looked up by service_id against a service already resolved from a tenant-scoped query "
        "in every caller of this helper.",
    ),
    AllowedViolation(
        file="api/routes/value_streams.py",
        function="_has_published_bundle",
        model="DependencyBundle",
        reason="duplicate helper of processes.py's own _has_published_bundle — same reasoning applies.",
    ),
    AllowedViolation(
        file="api/routes/scanner_management.py",
        function="_instance_response",
        model="EvidenceSource",
        reason="source looked up by instance.evidence_source_id against a ScannerInstance already tenant-scoped "
        "by _require_instance (TenantRepository) in every caller of this helper.",
    ),
    AllowedViolation(
        file="api/routes/scanner_management.py",
        function="get_scanner_route",
        model="EvidenceSource",
        reason="same pattern as _instance_response above — source looked up by instance.evidence_source_id "
        "against a ScannerInstance already tenant-scoped by _require_instance earlier in this same function.",
    ),
    AllowedViolation(
        file="api/routes/discovery_run.py",
        function="_run_response",
        model="DiscoveryExecutionPlan",
        reason="same pattern as _cancel_execution_plan_if_any above — plan looked up by discovery_run_id "
        "against a run already tenant-scoped by _require_run in every caller of this helper.",
    ),
    AllowedViolation(
        file="api/routes/discovery_run.py",
        function="get_discovery_run_timeline_route",
        model="DiscoveryExecutionPlan",
        reason="DISC-41's own timeline route (Epic A3) — plan looked up by discovery_run_id against a run "
        "already tenant-scoped by _require_run earlier in this same function.",
    ),
    # --- Deliberate, documented platform-wide queries (not a missing filter) ---
    AllowedViolation(
        file="api/routes/learning.py",
        function="_load_signal_summary",
        model="TrainingSignal",
        reason="deliberately cross-organisation platform-wide aggregation (source code's own comment); both "
        "callers require _require_platform_operator_secret, not a tenant JWT — the A1/H1 fix restricted who "
        "can call this, not what it returns. Adding an organization_id filter would silently break the "
        "platform-operator view without closing anything.",
    ),
    AllowedViolation(
        file="api/routes/activation.py",
        function="_flush_activation_audit_outbox_best_effort",
        model="ActivationAuditOutbox",
        reason="outbox-drain worker pattern — processes every pending row across all organisations by design, "
        "the same shape as learning.py's deliberate platform-wide aggregation.",
    ),
    # --- Pre-tenant identity-bootstrap flows: no tenant context exists yet to
    # check against — these queries ARE the mechanism establishing it (login,
    # signup, SSO, password reset, invite acceptance, scanner-agent bearer-token
    # auth). Structurally different from the "trust the caller" pattern above:
    # there is no upstream tenant validation to point to, because the tenant
    # itself has not been determined yet at this point in the request. ---
    AllowedViolation(
        file="api/routes/auth.py",
        function="signup_start",
        model="User",
        reason="pre-tenant email-uniqueness check during signup; no user or tenant is authenticated yet.",
    ),
    AllowedViolation(
        file="api/routes/auth.py",
        function="signup_verify",
        model="User",
        reason="pre-tenant email-uniqueness check during signup; no user or tenant is authenticated yet.",
    ),
    AllowedViolation(
        file="api/routes/auth.py",
        function="verify_login_mfa",
        model="MfaChallenge",
        reason="challenge looked up by its own id for error-path logging during login, before a session exists.",
    ),
    AllowedViolation(
        file="api/routes/auth.py",
        function="verify_login_mfa",
        model="User",
        reason="user resolved from an already-verified MFA challenge (verify_mfa_challenge validated the code); "
        "this is the login flow establishing the session, not a post-login query.",
    ),
    AllowedViolation(
        file="api/routes/auth.py",
        function="mfa_resend_challenge",
        model="MfaChallenge",
        reason="challenge looked up by its own id while still in the pre-session login-MFA flow.",
    ),
    AllowedViolation(
        file="api/routes/auth.py",
        function="mfa_resend_challenge",
        model="User",
        reason="user resolved from the challenge just looked up above, pre-session.",
    ),
    AllowedViolation(
        file="api/routes/auth.py",
        function="request_password_reset",
        model="User",
        reason="pre-tenant lookup by email to send a reset link; no session exists yet.",
    ),
    AllowedViolation(
        file="api/routes/auth.py",
        function="confirm_password_reset",
        model="PasswordResetToken",
        reason="token looked up by its own hash; this is the password-recovery flow itself, pre-session.",
    ),
    AllowedViolation(
        file="api/routes/auth.py",
        function="confirm_password_reset",
        model="User",
        reason="user resolved from an independently-validated PasswordResetToken record, pre-session.",
    ),
    AllowedViolation(
        file="api/routes/auth.py",
        function="accept_invite",
        model="User",
        reason="user resolved from an independently-validated InviteToken record — this route IS how a new "
        "user joins a tenant, so no prior tenant session exists to check against.",
    ),
    AllowedViolation(
        file="api/routes/auth.py",
        function="sso_callback",
        model="UserIdentity",
        reason="identity resolved by provider+subject from a verified IdP claims payload, not client input; "
        "this is SSO identity resolution itself, before any session exists.",
    ),
    AllowedViolation(
        file="api/routes/auth.py",
        function="sso_callback",
        model="User",
        reason="user resolved from the identity just looked up above, pre-session.",
    ),
    AllowedViolation(
        file="api/routes/activation.py",
        function="_resolve_idempotent_redeem_response",
        model="User",
        reason="organization_id/user_id are read from a previously-recorded activation-token redemption record "
        "(not client input) during the pre-tenant activation flow itself.",
    ),
    AllowedViolation(
        file="api/routes/scanner_agent.py",
        function="require_scanner_instance",
        model="ScannerInstance",
        reason="the instance is looked up by a hashed bearer credential — this IS the collector-authentication "
        "step establishing which scanner/org the request belongs to, analogous to auth.py's JWT verification.",
    ),
    AllowedViolation(
        file="api/routes/scanner_agent.py",
        function="require_scanner_instance",
        model="ScannerCredential",
        reason="same collector-authentication step as the ScannerInstance lookup above (TENANT-83/84 named "
        "credentials) — looked up by a hashed bearer token before the org is known; the org/instance actually "
        "acted on afterward is read from the matched row itself, never client input.",
    ),
]

_ALLOWLIST_KEYS = {(a.file, a.function, a.model) for a in ALLOWLIST}


def load_tenant_scoped_models() -> set[str]:
    """The exact same classification TenantRepository.__init__ already
    performs (hasattr(model_class, "organization_id")) — introspected at
    runtime so this script's notion of "tenant-scoped" can never drift
    from that repository's own guard."""
    from src.core.models import Base  # noqa: PLC0415 — deferred so this module has no import-time DB dependency

    return {
        mapper.class_.__name__
        for mapper in Base.registry.mappers
        if hasattr(mapper.class_, "organization_id")
    }


def _local_model_aliases(tree: ast.Module, tenant_scoped: set[str]) -> dict[str, str]:
    """Map each locally-imported name to its real class name, for every
    import that resolves to a tenant-scoped model — handles `as` aliasing."""
    aliases: dict[str, str] = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom):
            for alias in node.names:
                if alias.name in tenant_scoped:
                    aliases[alias.asname or alias.name] = alias.name
    return aliases


def _iter_functions(tree: ast.Module):
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            yield node


def _queried_model(call: ast.Call, aliases: dict[str, str]) -> str | None:
    func = call.func
    is_query_call = (isinstance(func, ast.Attribute) and func.attr in _QUERY_METHOD_NAMES) or (
        isinstance(func, ast.Name) and func.id == "select"
    )
    if not is_query_call or not call.args:
        return None

    arg = call.args[0]
    name: str | None = None
    if isinstance(arg, ast.Name):
        name = arg.id
    elif isinstance(arg, ast.Attribute) and isinstance(arg.value, ast.Name):
        name = arg.value.id  # select(Model.column) — base model, not the column

    return aliases.get(name) if name else None


def _organization_id_owner(expr: ast.expr, aliases: dict[str, str]) -> str | None:
    """If `expr` is `<Model>.organization_id`, return the real model name."""
    if isinstance(expr, ast.Attribute) and expr.attr == "organization_id" and isinstance(expr.value, ast.Name):
        return aliases.get(expr.value.id)
    return None


def _trusted_ctx_vars(func: ast.FunctionDef | ast.AsyncFunctionDef) -> set[str]:
    """Names bound to a real, JWT-verified TenantContext in this function —
    either a parameter annotated `TenantContext`, or a local assigned from
    `get_tenant_context(...)`. Values read off one of these (`.user_id`,
    `.organization_id`) cannot be spoofed by a caller, unlike a client-
    supplied path/query/body parameter."""
    trusted: set[str] = set()
    for arg in (*func.args.args, *func.args.kwonlyargs):
        if isinstance(arg.annotation, ast.Name) and arg.annotation.id == "TenantContext":
            trusted.add(arg.arg)
    for node in ast.walk(func):
        if (
            isinstance(node, ast.Assign)
            and isinstance(node.value, ast.Call)
            and isinstance(node.value.func, ast.Name)
            and node.value.func.id == "get_tenant_context"
        ):
            for target in node.targets:
                if isinstance(target, ast.Name):
                    trusted.add(target.id)
    return trusted


def _model_satisfied_by_pair(a: ast.expr, b: ast.expr, aliases: dict[str, str], trusted: set[str]) -> str | None:
    """Two safe shapes for one side of a `==` comparison to satisfy the
    other's model, checked in either operand order:
      1. `<Model>.organization_id == <anything>` — a direct org filter.
      2. `<Model>.id == <trusted_ctx>.user_id` — a self-lookup by a
         server-derived, JWT-verified id (e.g. `User.id == ctx.user_id`
         in `/auth/me`) — the caller cannot spoof `ctx.user_id` to name
         another tenant's row, so this needs no separate org check."""
    model = _organization_id_owner(a, aliases) or _organization_id_owner(b, aliases)
    if model:
        return model

    for pk_side, ctx_side in ((a, b), (b, a)):
        if (
            isinstance(pk_side, ast.Attribute)
            and pk_side.attr == "id"
            and isinstance(pk_side.value, ast.Name)
            and pk_side.value.id in aliases
            and isinstance(ctx_side, ast.Attribute)
            and ctx_side.attr == "user_id"
            and isinstance(ctx_side.value, ast.Name)
            and ctx_side.value.id in trusted
        ):
            return aliases[pk_side.value.id]
    return None


def _python_side_org_filter(a: ast.expr, b: ast.expr, trusted: set[str]) -> bool:
    """`<row>.organization_id == <trusted_ctx>.organization_id` — an org
    filter applied in a Python comprehension/loop after an unfiltered
    fetch, rather than in SQL. Still a real, correctly-applied boundary
    (just an inefficient one — a full-table scan, not a security gap);
    the model can't be resolved from `<row>` alone (it's a loop variable,
    not the class), so this satisfies every tenant-scoped model queried
    in the function rather than a specific one."""
    for org_side, ctx_side in ((a, b), (b, a)):
        if (
            isinstance(org_side, ast.Attribute)
            and org_side.attr == "organization_id"
            and isinstance(ctx_side, ast.Attribute)
            and ctx_side.attr == "organization_id"
            and isinstance(ctx_side.value, ast.Name)
            and ctx_side.value.id in trusted
        ):
            return True
    return False


def _filtered_models_in(func: ast.FunctionDef | ast.AsyncFunctionDef, aliases: dict[str, str]) -> set[str]:
    trusted = _trusted_ctx_vars(func)
    filtered: set[str] = set()
    for node in ast.walk(func):
        if isinstance(node, ast.Compare):
            operands = [node.left, *node.comparators]
            for a, b in zip(operands, operands[1:]):
                model = _model_satisfied_by_pair(a, b, aliases, trusted)
                if model:
                    filtered.add(model)
                elif _python_side_org_filter(a, b, trusted):
                    filtered.add("*")
        elif isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr == "filter_by":
            for kw in node.keywords:
                if kw.arg == "organization_id":
                    # filter_by(organization_id=...) doesn't name the model explicitly —
                    # conservatively treat it as satisfying every model queried in this
                    # function, rather than trying to infer which query it belongs to.
                    filtered.add("*")
    return filtered


def run_checks(routes_dir: Path = ROUTES_DIR) -> list[Violation]:
    tenant_scoped = load_tenant_scoped_models()
    violations: list[Violation] = []

    for path in sorted(routes_dir.glob("*.py")):
        source = path.read_text(encoding="utf-8")
        try:
            tree = ast.parse(source, filename=str(path))
        except SyntaxError:
            continue

        aliases = _local_model_aliases(tree, tenant_scoped)
        if not aliases:
            continue

        # ALLOWLIST keys are written as "api/routes/<name>.py" to match this
        # script's one real caller (routes_dir=ROUTES_DIR). A different
        # routes_dir (tests, fixtures) reports the plain filename instead of
        # a fabricated "api/routes/" prefix that wouldn't mean anything there.
        rel_file = f"api/routes/{path.name}" if routes_dir == ROUTES_DIR else path.name
        for func in _iter_functions(tree):
            filtered = _filtered_models_in(func, aliases)
            if "*" in filtered:
                continue  # filter_by(organization_id=...) present somewhere in this function

            queried: dict[str, int] = {}
            for node in ast.walk(func):
                if isinstance(node, ast.Call):
                    model = _queried_model(node, aliases)
                    if model and model not in queried:
                        queried[model] = node.lineno

            for model, lineno in queried.items():
                if model not in filtered:
                    violations.append(Violation(file=rel_file, line=lineno, function=func.name, model=model))

    return violations


def main() -> int:
    violations = run_checks()

    failing = [v for v in violations if (v.file, v.function, v.model) not in _ALLOWLIST_KEYS]
    allowlisted = [v for v in violations if (v.file, v.function, v.model) in _ALLOWLIST_KEYS]

    if allowlisted:
        print("Tenant isolation check — allowlisted (disclosed, not currently exploitable):")
        for v in allowlisted:
            print(f"  ⚠ {v.file}:{v.line} {v.function}() queries {v.model} without an organization_id filter")
        print()

    if failing:
        print("Tenant isolation check failed:")
        print()
        for v in failing:
            print(f"  ✗ {v.file}:{v.line} {v.function}() queries {v.model} without an organization_id filter")
        print()
        print(
            "Every route querying a tenant-scoped model must either use TenantRepository, "
            "or filter explicitly by <Model>.organization_id. If this is a genuine, disclosed "
            "exception (a child-row lookup already guarded by an upstream tenant check), add a "
            "justified AllowedViolation entry to scripts/check_tenant_isolation.py's ALLOWLIST — "
            "never a blanket exemption."
        )
        return 1

    print(f"Tenant isolation check passed ({len(allowlisted)} disclosed, allowlisted exceptions).")
    return 0


if __name__ == "__main__":
    sys.exit(main())

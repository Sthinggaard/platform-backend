"""Step 4.2 Part 2 — DISC-21: execution plan generation.

Turns an APPROVED DiscoveryRun into its one DiscoveryExecutionPlan: which
stages will run (derived from the run's own profile_snapshot capability
flags via the shared STAGE_REQUIRES_CAPABILITY mapping — the same
derivation discovery_command_service.py already uses to validate a
*reported* stage, reused here rather than duplicated), their DAG
dependencies, and one ProviderExecution per registered provider capable of
serving each stage.

Transitions DiscoveryRun APPROVED -> RUNNING the moment a plan is
generated (DISC-24, resolved 2026-07-23) — the execution-pipeline path
skips QUEUED/COMMAND_AVAILABLE/ACKNOWLEDGED entirely, since those exist
only for the original Step 4.1 whole-run scanner-command handshake this
path doesn't use. The matching downstream transition (RUNNING -> a
terminal status once every stage is done) is
discovery_execution_scheduler_service.py's job, not this one — plan
generation only ever starts a run, never finishes it. A plan is 1:1 with
its run (enforced by the DB's own unique constraint on discovery_run_id)
— no retry chain at the plan level, since a DiscoveryRun retry (existing
Step 4.1 lifecycle) already creates a brand-new run, which gets its own
brand-new plan.
"""

from __future__ import annotations

from sqlalchemy.orm import Session

from src.core.constants.discovery_execution_enums import (
    DISCOVERY_EXECUTION_ERROR_COLLECTOR_CANNOT_RUN_ANY_STAGE,
    DISCOVERY_EXECUTION_ERROR_NO_PROVIDER_REGISTERED,
    DISCOVERY_EXECUTION_ERROR_PLAN_ALREADY_EXISTS,
    DISCOVERY_EXECUTION_ERROR_RUN_NOT_APPROVED,
    ExecutionPlanStatus,
    ExecutionStageStatus,
    ProviderExecutionStatus,
)
from src.core.constants.discovery_run_enums import STAGE_REQUIRES_CAPABILITY, DiscoveryRunStatus, DiscoveryStage
from src.core.model_defs.evidence_scanner import ScannerInstance
from src.core.services.collector_readiness_service import (
    CollectorReadiness,
    component_is_ready,
    resolve_collector_readiness,
)
from src.core.model_defs.discovery_execution import (
    DiscoveryExecutionPlan,
    ExecutionStage,
    ExecutionStageDependency,
    ProviderExecution,
)
from src.core.model_defs.discovery_run import DiscoveryRun
from src.core.services.discovery_providers import DiscoveryProvider, get_registered_providers
from src.core.services.discovery_run_service import transition_discovery_run, utcnow

# The DAG's edges: a stage cannot start until every stage it depends on has
# completed — fingerprinting needs to know which hosts/services exist
# first; vulnerability checks need to know which services were fingerprinted
# first. External/internal discovery have no prerequisites and may run in
# parallel. A real technical execution-ordering constraint (not invented
# business logic — no gateway/branching is fabricated, only what discovery
# tooling genuinely requires in sequence).
_STAGE_DEPENDENCIES: dict[str, tuple[str, ...]] = {
    DiscoveryStage.EXTERNAL_DISCOVERY.value: (),
    DiscoveryStage.INTERNAL_DISCOVERY.value: (),
    DiscoveryStage.SERVICE_FINGERPRINTING.value: (
        DiscoveryStage.EXTERNAL_DISCOVERY.value,
        DiscoveryStage.INTERNAL_DISCOVERY.value,
    ),
    DiscoveryStage.VULNERABILITY_DISCOVERY.value: (DiscoveryStage.SERVICE_FINGERPRINTING.value,),
}


class DiscoveryExecutionPlanError(ValueError):
    """Distinct from DiscoveryRunValidationError/DiscoveryCommandError —
    plan generation has its own small set of preconditions."""

    def __init__(self, message: str, *, code: str) -> None:
        super().__init__(message)
        self.code = code


def required_components(provider: DiscoveryProvider) -> set[str]:
    """Which Collector components this provider cannot work without.

    Read from the provider's own ``dependency_requirements`` rather than a
    second mapping kept alongside it — a provider is the only thing that knows
    what it needs, and a parallel table is a thing to forget to update.
    Supports both the plural key and the original singular one.
    """
    requirements = provider.capabilities().dependency_requirements or {}
    tools = requirements.get("requiresTools")
    if tools:
        return set(tools)
    single = requirements.get("requiresTool")
    return {single} if single else set()


def _stage_providers(
    stage_keys: list[str], *, readiness: CollectorReadiness | None = None
) -> dict[str, list[DiscoveryProvider]]:
    """Providers that support each stage *and* that this Collector can run.

    CA-02.3 slice 3 — capability-based gating at execution time. A Collector
    missing Subfinder should lose domain enumeration and nothing else; before
    this, the plan was built purely from the profile, so a job would be
    dispatched to a Collector that had already reported it could not run it,
    and the failure surfaced as a provider error at execution time rather than
    as a capability the Collector plainly does not have.

    **A provider is excluded only when the Collector positively reported the
    component as not working.** With no report at all there is no basis to
    exclude anything — absence of evidence is not evidence of failure, and
    silently planning less work because a Collector has been quiet would be a
    worse failure than planning work it then cannot do.
    """
    providers = get_registered_providers()

    def _runnable(provider: DiscoveryProvider) -> bool:
        if readiness is None or not readiness.has_report:
            return True
        return all(component_is_ready(readiness, key) for key in required_components(provider))

    return {
        stage_key: [
            p
            for p in providers
            if stage_key in p.capabilities().supported_discovery_stages and _runnable(p)
        ]
        for stage_key in stage_keys
    }


def _build_plan_definition(stage_providers: dict[str, list[DiscoveryProvider]]) -> dict:
    """Derives concurrency/retry/timeout policy from each stage's own
    registered providers' declared capabilities — not a fabricated global
    default, and not yet configurable per-organisation (a real, disclosed
    simplification for this pass, not a gap hidden from view)."""
    stage_policies: dict[str, dict] = {}
    for stage_key, providers in stage_providers.items():
        if not providers:
            continue
        stage_policies[stage_key] = {
            "maxParallelJobs": len(providers),
            "timeoutSeconds": max(p.capabilities().timeout_recommendation_seconds for p in providers),
            "retryPolicy": {
                "maxAttempts": max(p.capabilities().retry_recommendation.get("maxAttempts", 3) for p in providers)
            },
        }
    return {"stagePolicies": stage_policies}



def _some_provider_exists_for(stage_keys: list[str]) -> bool:
    """Whether any provider is registered for these stages at all, ignoring
    Collector readiness. Answers "is this a platform gap or a machine gap?"."""
    ungated = _stage_providers(stage_keys)
    return any(ungated[stage_key] for stage_key in stage_keys)


def generate_execution_plan(db: Session, run: DiscoveryRun) -> DiscoveryExecutionPlan:
    # Checked before the APPROVED check on purpose: generating a plan now
    # also moves the run to RUNNING (DISC-24), so a genuine second attempt
    # on an already-planned run would otherwise always hit "not approved"
    # first, masking the more specific "a plan already exists" signal.
    existing = db.query(DiscoveryExecutionPlan).filter(DiscoveryExecutionPlan.discovery_run_id == run.id).first()
    if existing is not None:
        raise DiscoveryExecutionPlanError(DISCOVERY_EXECUTION_ERROR_PLAN_ALREADY_EXISTS, code="plan_already_exists")

    if run.status != DiscoveryRunStatus.APPROVED.value:
        raise DiscoveryExecutionPlanError(DISCOVERY_EXECUTION_ERROR_RUN_NOT_APPROVED, code="run_not_approved")

    enabled_by_profile = [
        stage_key for stage_key, capability in STAGE_REQUIRES_CAPABILITY.items() if run.profile_snapshot.get(capability)
    ]
    # Resolved from the run's own Collector: what the profile allows and what
    # this machine can actually do are different questions, and the plan must
    # answer both.
    instance = (
        db.query(ScannerInstance).filter(ScannerInstance.id == run.scanner_instance_id).first()
        if run.scanner_instance_id
        else None
    )
    readiness = resolve_collector_readiness(db, instance) if instance is not None else None
    stage_providers = _stage_providers(enabled_by_profile, readiness=readiness)
    # Only include a stage if a provider is actually registered for it —
    # a stage with zero jobs would sit open forever with nothing to run.
    stage_keys = [stage_key for stage_key in enabled_by_profile if stage_providers[stage_key]]
    if not stage_keys:
        # Distinguish "nothing is registered" from "this Collector cannot run
        # what is registered" — same empty list, completely different remedy,
        # and sending an operator to look for a missing provider when the real
        # answer is a missing component on their own machine wastes the one
        # thing they have least of.
        if _some_provider_exists_for(enabled_by_profile):
            raise DiscoveryExecutionPlanError(
                DISCOVERY_EXECUTION_ERROR_COLLECTOR_CANNOT_RUN_ANY_STAGE,
                code="collector_cannot_run_any_stage",
            )
        raise DiscoveryExecutionPlanError(DISCOVERY_EXECUTION_ERROR_NO_PROVIDER_REGISTERED, code="no_provider_registered")

    plan = DiscoveryExecutionPlan(
        organization_id=run.organization_id,
        discovery_run_id=run.id,
        plan_definition=_build_plan_definition(stage_providers),
        status=ExecutionPlanStatus.EXECUTING.value,
    )
    db.add(plan)
    db.flush()  # populate plan.id before stages reference it

    stage_rows: dict[str, ExecutionStage] = {}
    for stage_key in stage_keys:
        depends_on = [s for s in _STAGE_DEPENDENCIES.get(stage_key, ()) if s in stage_keys]
        stage = ExecutionStage(
            execution_plan_id=plan.id,
            stage_key=stage_key,
            status=ExecutionStageStatus.PENDING.value if depends_on else ExecutionStageStatus.READY.value,
            # DISC-30: every stage generated today is required — no stage
            # is currently designated optional (a real product decision,
            # not made here); the field exists so that decision can be
            # wired in later without a schema change.
            required=True,
        )
        db.add(stage)
        db.flush()  # populate stage.id before dependency/job rows reference it
        stage_rows[stage_key] = stage

    for stage_key, stage in stage_rows.items():
        for dependency_key in _STAGE_DEPENDENCIES.get(stage_key, ()):
            dependency_stage = stage_rows.get(dependency_key)
            if dependency_stage is None:
                continue
            db.add(ExecutionStageDependency(execution_stage_id=stage.id, depends_on_stage_id=dependency_stage.id))

        for provider in stage_providers.get(stage_key, []):
            db.add(
                ProviderExecution(
                    execution_stage_id=stage.id,
                    provider_id=provider.provider_id,
                    provider_version=None,
                    status=ProviderExecutionStatus.PENDING.value,
                )
            )

    plan.started_at = plan.generated_at
    db.add(plan)

    transition_discovery_run(run, DiscoveryRunStatus.RUNNING.value)
    if run.started_at is None:
        run.started_at = utcnow()
    db.add(run)

    return plan

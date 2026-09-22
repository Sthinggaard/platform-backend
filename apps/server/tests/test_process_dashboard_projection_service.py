from types import SimpleNamespace

from src.api.middleware.tenant_context import TenantContext
from src.api.routes import process_dashboard
from src.core.constants.process_activation_enums import ProcessActivationState
from src.core.constants.process_dashboard_enums import (
    ProcessDashboardReasonCode,
    ProcessDashboardState,
)
from src.core.services.process_dashboard_projection_service import (
    ProcessDashboardProjectionInput,
    build_process_dashboard_projection,
)
from src.core.services.risk_appetite_resolution_service import ResolvedProcessAppetite

COMPLETE_BIA = {
    "impact1h": "high",
    "impact4h": "high",
    "impact24h": "medium",
    "mtd": "le_4h",
    "dataSensitivity": "high",
    "workaround": "partial",
    "alternativeChannel": "partial",
}


def _process(*, bia_answers=COMPLETE_BIA):
    return SimpleNamespace(
        id="process-1",
        name="Order to Cash",
        priority="critical",
        bia_answers=bia_answers,
    )


def _service(bia_answers=COMPLETE_BIA):
    return SimpleNamespace(
        id="service-1",
        value_stream_ids=["process-1"],
        bia_answers=bia_answers,
        l1=["asset-1"],
        l2=[],
        l3=[],
        archived_at=None,
    )


def _threat(status="detected"):
    return SimpleNamespace(id="threat-1", asset="Payment Gateway", status=status)


def _resolved_appetite(scope="organisation"):
    from datetime import datetime

    return ResolvedProcessAppetite(
        answers={"downtime": 2},
        source_scope=scope,
        policy_id="pol-1",
        version=1,
        approved_by="2",
        effective_from=datetime(2026, 1, 1),
        effective_to=None,
        review_at=None,
        decision_reference=None,
    )


def _input(
    *,
    processes=None,
    services=None,
    bundles=None,
    threats=None,
    decisions=None,
    verifications=None,
    resolved_process_appetites=None,
    activation_by_process_id=None,
    effective_process_bia_answers=None,
    viewer_user_id=None,
):
    return ProcessDashboardProjectionInput(
        processes=processes if processes is not None else [_process()],
        services=services if services is not None else [_service()],
        dependency_bundles=bundles
        if bundles is not None
        else [SimpleNamespace(service_id="service-1", lifecycle_state="bundle_published")],
        legacy_service_appetite_configs=[],
        assets=[SimpleNamespace(id=1, display_name="Payment Gateway")],
        threats=threats if threats is not None else [],
        decisions=decisions if decisions is not None else [],
        verifications=verifications if verifications is not None else [],
        resolved_process_appetites=(
            resolved_process_appetites
            if resolved_process_appetites is not None
            else {"process-1": _resolved_appetite()}
        ),
        latest_evaluations={},
        forecasts_by_id={},
        resolutions=[],
        overdue_reviews_by_process={},
        access_by_process_id={},
        access_model_configured=False,
        activation_by_process_id=activation_by_process_id or {},
        effective_process_bia_answers=effective_process_bia_answers or {},
        viewer_user_id=viewer_user_id,
    )


def _row(**kwargs):
    return build_process_dashboard_projection(_input(**kwargs)).processes[0]


def test_projection_returns_no_rows_when_no_process_is_configured():
    projection = build_process_dashboard_projection(_input(processes=[]))

    assert projection.processes == []


def test_projection_blocks_partial_setup_with_missing_bia():
    row = _row(
        processes=[_process(bia_answers=None)],
        services=[_service(bia_answers=None)],
    )

    assert row.state == ProcessDashboardState.BLOCKED
    assert ProcessDashboardReasonCode.MISSING_BIA in row.reasons


def test_projection_uses_effective_organisation_bia_for_coverage():
    # The loader normally supplies this map from the organisation baseline;
    # the projection must not require answers to be copied onto the process.
    row = _row(
        processes=[_process(bia_answers=None)],
        services=[_service(bia_answers=None)],
        effective_process_bia_answers={"process-1": COMPLETE_BIA},
    )

    assert row.coverage.bia_complete is True


def test_projection_uses_activation_gate_before_operational_state():
    readiness = SimpleNamespace(
        state=ProcessActivationState.OWNER_ACCEPTANCE_REQUIRED,
        next_action=ProcessActivationState.OWNER_ACCEPTANCE_REQUIRED,
        process_confirmed=True,
        owner_assigned=True,
        ownership_accepted=False,
        bia_attested=True,
        organisation_appetite_effective=True,
        impact_model_active=False,
    )
    row = _row(
        activation_by_process_id={"process-1": readiness},
        threats=[_threat()],
    )

    assert row.state is ProcessDashboardState.BLOCKED
    assert row.reasons == [ProcessDashboardReasonCode.OWNER_ACCEPTANCE_REQUIRED]
    assert row.activation_state is ProcessActivationState.OWNER_ACCEPTANCE_REQUIRED


def test_projection_shows_decision_needed_when_the_viewer_must_accept_ownership():
    readiness = SimpleNamespace(
        state=ProcessActivationState.OWNER_ACCEPTANCE_REQUIRED,
        next_action=ProcessActivationState.OWNER_ACCEPTANCE_REQUIRED,
        process_confirmed=True,
        owner_assigned=True,
        owner_user_id=42,
        ownership_accepted=False,
        bia_attested=True,
        organisation_appetite_effective=True,
        impact_model_active=False,
    )
    row = _row(activation_by_process_id={"process-1": readiness}, viewer_user_id=42)

    assert row.state is ProcessDashboardState.DECISION_NEEDED
    assert row.activation_action_for_viewer == "accept_ownership"


def test_projection_shows_decision_needed_when_the_viewer_must_confirm():
    readiness = SimpleNamespace(
        state=ProcessActivationState.CONFIRMATION_REQUIRED,
        next_action=ProcessActivationState.CONFIRMATION_REQUIRED,
        process_confirmed=False,
        owner_assigned=True,
        owner_user_id=42,
        ownership_accepted=True,
        bia_attested=False,
        organisation_appetite_effective=True,
        impact_model_active=False,
    )
    row = _row(activation_by_process_id={"process-1": readiness}, viewer_user_id=42)

    assert row.state is ProcessDashboardState.DECISION_NEEDED
    assert row.activation_action_for_viewer == "confirm"


def test_projection_stays_blocked_and_impersonal_for_a_bystander_viewer():
    # Someone other than the assigned owner sees an honest, informational
    # block — never a personal call to action that isn't theirs to take.
    readiness = SimpleNamespace(
        state=ProcessActivationState.OWNER_ACCEPTANCE_REQUIRED,
        next_action=ProcessActivationState.OWNER_ACCEPTANCE_REQUIRED,
        process_confirmed=True,
        owner_assigned=True,
        owner_user_id=42,
        ownership_accepted=False,
        bia_attested=True,
        organisation_appetite_effective=True,
        impact_model_active=False,
    )
    row = _row(activation_by_process_id={"process-1": readiness}, viewer_user_id=99)

    assert row.state is ProcessDashboardState.BLOCKED
    assert row.activation_action_for_viewer is None


def test_projection_omits_terminal_non_confirmation_outcomes():
    readiness = SimpleNamespace(
        state=ProcessActivationState.REDESIGN_REQUIRED,
        next_action=ProcessActivationState.REDESIGN_REQUIRED,
        process_confirmed=False,
        owner_assigned=False,
        ownership_accepted=False,
        bia_attested=False,
        organisation_appetite_effective=False,
        impact_model_active=False,
    )

    projection = build_process_dashboard_projection(
        _input(activation_by_process_id={"process-1": readiness})
    )

    assert projection.processes == []


def test_projection_is_not_proven_without_verified_outcome():
    row = _row()

    assert row.state == ProcessDashboardState.NOT_PROVEN
    assert row.reasons == [ProcessDashboardReasonCode.NO_VERIFIED_OUTCOME]


def test_projection_marks_mapped_undecided_risk_as_decision_needed():
    row = _row(threats=[_threat()])

    assert row.state == ProcessDashboardState.DECISION_NEEDED
    assert row.reasons == [ProcessDashboardReasonCode.DECISION_REQUIRED]


def test_projection_keeps_a_decided_active_risk_at_risk():
    row = _row(
        threats=[_threat(status="in-progress")],
        decisions=[SimpleNamespace(threat_id="threat-1")],
    )

    assert row.state == ProcessDashboardState.AT_RISK
    assert row.reasons == [ProcessDashboardReasonCode.DECISION_RECORDED_RISK_REMAINS]


def test_projection_requires_successful_verification_for_protected_state():
    row = _row(
        threats=[_threat(status="kept-safe")],
        verifications=[
            SimpleNamespace(
                threat_id="threat-1",
                verification_status="verified_successful",
                created_at=None,
            )
        ],
    )

    assert row.state == ProcessDashboardState.PROTECTED
    assert row.verified_outcome_count == 1


def test_dashboard_route_uses_authenticated_organization_scope(monkeypatch):
    captured_organization_ids = []

    def load_input(_db, organization_id, _viewer_user_id=None):
        captured_organization_ids.append(organization_id)
        return _input(processes=[])

    monkeypatch.setattr(process_dashboard, "load_process_dashboard_projection_input", load_input)
    response = process_dashboard.list_process_dashboard(
        ctx=TenantContext(
            user_id=11,
            organization_id=7,
            email="architect@risklence.test",
            roles=["admin"],
            permissions=[],
        ),
        db=object(),
    )

    assert captured_organization_ids == [7]
    assert response.processes == []


def test_projection_loader_scopes_every_runtime_model_to_the_tenant(monkeypatch):
    repository_organization_ids = []

    class CapturingTenantRepository:
        def __init__(_self, _db, _model, organization_id):
            repository_organization_ids.append(organization_id)

        def get_all(_self):
            return []

    monkeypatch.setattr(process_dashboard, "TenantRepository", CapturingTenantRepository)

    resolution_calls = []

    def _capture_resolution(_db, *, organization_id, process_ids):
        resolution_calls.append((organization_id, process_ids))
        return {}

    monkeypatch.setattr(process_dashboard, "resolve_appetite_for_processes", _capture_resolution)
    monkeypatch.setattr(
        process_dashboard, "find_outstanding_reviews", lambda _db, *, organization_id: []
    )
    monkeypatch.setattr(
        process_dashboard,
        "resolve_org_access",
        lambda _db, *, organization_id, viewer_user_id, processes, services: SimpleNamespace(
            configured=False, access_by_process_id={}
        ),
    )
    exception_reads = []

    def _capture_exceptions(_db, *, organization_id, process_ids):
        exception_reads.append((organization_id, process_ids))
        return {}

    monkeypatch.setattr(process_dashboard, "active_bia_exceptions", _capture_exceptions)

    result = process_dashboard.load_process_dashboard_projection_input(
        db=object(), organization_id=7
    )

    assert repository_organization_ids == [7] * 11
    # Appetite resolution is tenant-scoped through the same organisation id.
    assert resolution_calls == [(7, [])]
    # #463 — so is the read of services' BIA exceptions.
    assert exception_reads == [(7, [])]
    assert result.processes == []

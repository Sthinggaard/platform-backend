"""Dashboard slice 5 — mandate, visibility, and eligibility resolution."""

from types import SimpleNamespace

from src.core.services import process_access_resolution_service as svc


class _Query:
    def __init__(self, rows):
        self._rows = rows

    def filter(self, *_a, **_k):
        return self

    def first(self):
        return self._rows[0] if self._rows else None

    def all(self):
        return list(self._rows)


class _DB:
    def __init__(self, *, assignments=(), scope_bindings=(), policy=None, users=()):
        self.rows = {
            "OrgMandateRoleAssignment": list(assignments),
            "OrgMandateScopeBinding": list(scope_bindings),
            "OrgVisibilityPolicy": [policy] if policy else [],
            "User": list(users),
        }

    def query(self, model):
        return _Query(self.rows.get(model.__name__, []))


def _assignment(user_id, role, assignment_id=None):
    return SimpleNamespace(
        id=assignment_id or f"assignment-{user_id}-{role}",
        canonical_role=role,
        subject_type="user",
        user_id=user_id,
        identity_group_id=None,
    )


def _scope_binding(assignment_id, *, process_id=None, service_id=None, role):
    return SimpleNamespace(
        role_assignment_id=assignment_id,
        canonical_role=role,
        value_stream_id=process_id,
        business_service_id=service_id,
    )


def _policy(overview=(), full=()):
    return SimpleNamespace(overview_role_keys=list(overview), full_detail_role_keys=list(full))


def _user(user_id, email="user@example.com", first=None, last=None):
    return SimpleNamespace(id=user_id, email=email, first_name=first, last_name=last)


def _process(process_id="proc-1"):
    return SimpleNamespace(id=process_id)


def _service(owner_user_id, process_ids=("proc-1",), service_id="service-1"):
    return SimpleNamespace(
        id=service_id,
        owner_user_id=owner_user_id,
        value_stream_ids=list(process_ids),
        archived_at=None,
    )


def _resolve(db, viewer, processes=None, services=None):
    return svc.resolve_org_access(
        db,
        organization_id=7,
        viewer_user_id=viewer,
        processes=processes or [_process()],
        services=services or [],
    )


def test_unconfigured_org_falls_back_transparently():
    resolution = _resolve(_DB(), viewer=2)

    assert resolution.configured is False
    access = resolution.access_by_process_id["proc-1"]
    assert access.visible is True
    assert access.eligibility == "not_evaluated"
    assert access.detail == "overview"


def test_mandate_holder_is_role_plus_ownership_anchor():
    db = _DB(
        assignments=[_assignment(5, "business_process_owner")],
        users=[_user(5, first="Pia", last="Olsen")],
    )
    resolution = _resolve(db, viewer=5, services=[_service(owner_user_id=5)])

    access = resolution.access_by_process_id["proc-1"]
    assert access.mandate_holder is not None
    assert access.mandate_holder.name == "Pia Olsen"
    assert access.eligibility == "can_act"
    assert access.detail == "full"


def test_scoped_process_binding_is_authoritative_over_legacy_service_owner():
    assignment = _assignment(8, "business_process_owner", assignment_id="assignment-8")
    binding = _scope_binding(
        assignment.id,
        process_id="proc-1",
        role="business_process_owner",
    )
    db = _DB(
        assignments=[assignment],
        scope_bindings=[binding],
        users=[_user(5), _user(8, first="Ana", last="Jensen")],
    )

    resolution = _resolve(db, viewer=8, services=[_service(owner_user_id=5)])

    access = resolution.access_by_process_id["proc-1"]
    assert access.mandate_holder is not None
    assert access.mandate_holder.user_id == 8
    assert access.eligibility == "can_act"


def test_scoped_service_owner_can_view_process_context_without_process_mandate():
    assignment = _assignment(5, "business_service_owner", assignment_id="assignment-5")
    binding = _scope_binding(
        assignment.id,
        service_id="service-1",
        role="business_service_owner",
    )
    service = _service(owner_user_id=9)
    service.id = "service-1"
    db = _DB(assignments=[assignment], scope_bindings=[binding], users=[_user(5)])

    resolution = _resolve(db, viewer=5, services=[service])

    access = resolution.access_by_process_id["proc-1"]
    assert access.visible is True
    assert access.detail == "full"
    assert access.eligibility == "view_only"
    assert access.mandate_holder is None


def test_owner_without_process_owner_role_cannot_act():
    # Service ownership grants visibility and detail, but mandate follows the
    # canonical role — never ownership alone, never a job title.
    db = _DB(assignments=[_assignment(9, "org_wide_visibility")], users=[_user(5)])
    resolution = _resolve(db, viewer=5, services=[_service(owner_user_id=5)])

    access = resolution.access_by_process_id["proc-1"]
    assert access.visible is True
    assert access.detail == "full"
    assert access.eligibility == "view_only"
    assert access.mandate_holder is None  # honest gap: no role-anchored holder


def test_non_owner_without_visibility_role_sees_nothing():
    db = _DB(assignments=[_assignment(5, "business_process_owner")], users=[_user(5)])
    resolution = _resolve(db, viewer=99, services=[_service(owner_user_id=5)])

    assert resolution.access_by_process_id["proc-1"].visible is False


def test_overview_role_sees_rollup_not_full_detail():
    db = _DB(
        assignments=[_assignment(7, "org_wide_visibility")],
        policy=_policy(overview=["org_wide_visibility"]),
        users=[_user(7)],
    )
    resolution = _resolve(db, viewer=7, services=[_service(owner_user_id=5)])

    access = resolution.access_by_process_id["proc-1"]
    assert access.visible is True
    assert access.detail == "overview"
    assert access.eligibility == "view_only"


def test_full_detail_is_an_independent_policy_setting():
    db = _DB(
        assignments=[_assignment(7, "org_wide_visibility")],
        policy=_policy(overview=["org_wide_visibility"], full=["org_wide_visibility"]),
        users=[_user(7)],
    )
    resolution = _resolve(db, viewer=7, services=[_service(owner_user_id=5)])

    assert resolution.access_by_process_id["proc-1"].detail == "full"
    # Full detail still grants no mandate.
    assert resolution.access_by_process_id["proc-1"].eligibility == "view_only"


def test_manager_visibility_is_oversight_not_mandate(monkeypatch):
    db = _DB(
        assignments=[_assignment(5, "business_process_owner")],
        users=[_user(5), _user(8)],
    )
    # Viewer 8 manages owner 5 (runtime reporting-line seam).
    monkeypatch.setattr(svc, "resolve_reporting_line_manager_of", lambda user_id: [5] if user_id == 8 else [])

    resolution = _resolve(db, viewer=8, services=[_service(owner_user_id=5)])

    access = resolution.access_by_process_id["proc-1"]
    assert access.visible is True
    assert access.detail == "full"
    assert access.eligibility == "view_only"  # oversight, never operational mandate

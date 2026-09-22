from src.api.middleware.tenant_context import TenantContext
from src.api.routes import template_library
from src.core.models import ProcessTemplate, ServiceTemplate, SlotTemplate


class DummyQuery:
    def __init__(self, rows):
        self._rows = rows

    def filter(self, *args, **_kwargs):
        filtered = list(self._rows)
        for arg in args:
            left = getattr(arg, "left", None)
            right = getattr(arg, "right", None)
            if left is None or right is None:
                continue
            field_name = getattr(left, "key", None)
            if field_name is None or not hasattr(right, "value"):
                continue
            value = right.value
            filtered = [row for row in filtered if getattr(row, field_name) == value]
        self._rows = filtered
        return self

    def order_by(self, *_args, **_kwargs):
        return self

    def all(self):
        return list(self._rows)

    def first(self):
        return self._rows[0] if self._rows else None


class DummyDB:
    def __init__(self, rows_by_model):
        self._rows_by_model = rows_by_model
        self.added: list[object] = []
        self.committed = False

    def query(self, model):
        return DummyQuery(self._rows_by_model.get(model, []))

    def add(self, row):
        self.added.append(row)
        self._rows_by_model.setdefault(type(row), []).append(row)

    def flush(self):
        return None

    def commit(self):
        self.committed = True


def _ctx() -> TenantContext:
    return TenantContext(
        user_id=1,
        organization_id=7,
        email="architect@risklence.test",
        roles=["admin"],
        permissions=[],
    )


def test_list_process_templates_seeds_persisted_templates():
    db = DummyDB({ProcessTemplate: [], ServiceTemplate: [], SlotTemplate: []})

    response = template_library.list_process_templates(_ctx(), db)

    assert response.groups
    assert db.committed is True
    assert any(isinstance(row, ProcessTemplate) for row in db.added)
    assert any(isinstance(row, ServiceTemplate) for row in db.added)
    assert any(isinstance(row, SlotTemplate) for row in db.added)


def test_get_service_template_returns_persisted_slot_templates():
    db = DummyDB({ProcessTemplate: [], ServiceTemplate: [], SlotTemplate: []})

    response = template_library.get_service_template("payment_processing", _ctx(), db)

    assert response.service_key == "payment_processing"
    assert response.template_version == 1
    assert response.capability_groups
    assert all(group.dependency_category is not None for group in response.capability_groups)
    assert any(slot.slot_id == "transaction_data_store" for slot in response.required_slots)
    # The payment_processing Business Service Profile promotes monitoring to required.
    assert any(slot.slot_id == "monitoring_service" for slot in response.required_slots)
    assert response.capability_statement is not None
    gateway = next(
        slot
        for slot in response.required_slots + response.optional_slots
        if slot.slot_id == "external_provider"
    )
    assert gateway.label == "Payment Gateway"
    assert "stripe" in gateway.matching_hints


def test_get_archetype_template_uses_active_persisted_service_template():
    db = DummyDB({ProcessTemplate: [], ServiceTemplate: [], SlotTemplate: []})

    response = template_library.get_archetype_template("customer_channel", _ctx(), db)

    assert response.archetype == "customer_channel"
    assert response.template_version == 1
    assert any(slot.slot_id == "application_platform" for slot in response.required_slots)
    identity_group = next(group for group in response.capability_groups if group.key == "identity_access")
    assert identity_group.dependency_category == "infrastructure"


def test_the_worklist_asks_only_what_a_slot_can_answer_even_from_a_stale_stored_template():
    """CI/CD Pipeline's stored v1 template, as the dev database holds it.

    It asked `teams`, which no slot answers — Søren's manual testing, 2026-09-13:
    "This dependency has no slot to record an answer against." And it never asked
    `infrastructure`, which its two required slots sit under. The stored list is
    never rewritten, so the route has to read it through the slots.
    """
    stale = ServiceTemplate(
        id="stale-ci-cd",
        service_key="ci_cd_pipeline",
        service_name="CI/CD Pipeline",
        archetype="platform_infrastructure",
        version=1,
        status="published",
        is_active=True,
        capability_groups=[
            {
                "key": "systems",
                "label": "Systems that deliver this capability",
                "question": "What systems deliver this infrastructure service?",
                "description": "",
                "required": True,
            },
            {
                "key": "data",
                "label": "Data and configuration storage",
                "question": "",
                "description": "",
                "required": False,
            },
            {
                "key": "teams",
                "label": "Teams responsible for this service",
                "question": "",
                "description": "",
                "required": False,
            },
        ],
    )
    db = DummyDB({ProcessTemplate: [], ServiceTemplate: [stale], SlotTemplate: []})

    response = template_library.get_archetype_template("platform_infrastructure", _ctx(), db)

    questions = {group.key: group for group in response.capability_groups}
    assert "teams" not in questions
    assert questions["infrastructure"].required is True
    assert questions["infrastructure"].label == "Infrastructure this service runs on"
    # The stored wording stays; whether it is required is the slots' to say.
    assert questions["systems"].label == "Systems that deliver this capability"
    assert questions["systems"].required is False


def test_get_service_template_rejects_unknown_service_key():
    db = DummyDB({ProcessTemplate: [], ServiceTemplate: [], SlotTemplate: []})

    try:
        template_library.get_service_template("not_a_real_service", _ctx(), db)
    except Exception as exc:
        assert getattr(exc, "status_code", None) == 404
        assert "Unknown service key" in str(exc.detail)
    else:  # pragma: no cover - defensive
        raise AssertionError("Expected 404 for unknown service key")

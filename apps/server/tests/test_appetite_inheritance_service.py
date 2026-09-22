from src.core.services.appetite_inheritance_service import (
    APPETITE_DIMENSION_KEYS,
    appetite_category_provenance,
    effective_service_appetite,
    service_appetite_status,
)


def test_service_inherits_process_appetite_when_no_reassessment():
    process_answers = {"downtime": 2, "dataLoss": 1, "regulatory": 3, "financial": 2, "reputational": 2, "security": 1}
    assert effective_service_appetite(None, process_answers) == process_answers


def test_approved_reassessment_overrides_only_its_own_category():
    process_answers = {"downtime": 2, "dataLoss": 1, "regulatory": 3, "financial": 2, "reputational": 2, "security": 1}
    reassessed = {"downtime": 0}

    effective = effective_service_appetite(reassessed, process_answers)

    assert effective["downtime"] == 0
    assert effective["dataLoss"] == 1
    assert effective["regulatory"] == 3


def test_never_fabricates_a_value_neither_level_set():
    assert effective_service_appetite(None, None) is None
    assert effective_service_appetite({}, None) is None
    assert effective_service_appetite({"downtime": 1}, None) == {"downtime": 1}


def test_provenance_labels_reassessed_categories_and_inherited_ones():
    provenance = appetite_category_provenance({"downtime": 0})
    assert provenance["downtime"] == "reassessed"
    assert provenance["dataLoss"] == "inherited"
    assert set(provenance.keys()) == APPETITE_DIMENSION_KEYS


def test_service_appetite_status_reflects_pending_reassessed_and_inherited():
    assert service_appetite_status(None, has_pending_reassessment=False) == "inherited"
    assert service_appetite_status({"downtime": 0}, has_pending_reassessment=False) == "reassessed"
    assert service_appetite_status({"downtime": 0}, has_pending_reassessment=True) == "pending_reassessment"
    assert service_appetite_status(None, has_pending_reassessment=True) == "pending_reassessment"

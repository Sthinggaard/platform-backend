"""BSP-12 — org frameworks tune slot requiredness with provenance."""

from types import SimpleNamespace

from src.core.services.org_context_profile_tuning import (
    group_requiredness_overrides,
    slot_requiredness_overrides,
)


def test_nis2_promotes_monitoring_and_audit_logging():
    overrides = slot_requiredness_overrides(["NIS2"])

    assert set(overrides) == {"monitoring_service", "audit_logging"}
    assert overrides["monitoring_service"].frameworks == ("NIS2",)
    assert "NIS2" in overrides["monitoring_service"].reason


def test_framework_matching_is_tolerant_of_case_and_separators():
    for spelling in ("pci-dss", "PCI_DSS", "Pci Dss"):
        overrides = slot_requiredness_overrides([spelling])
        assert "identity_provider" in overrides, spelling


def test_overlapping_frameworks_merge_provenance():
    overrides = slot_requiredness_overrides(["NIS2", "GDPR"])

    audit = overrides["audit_logging"]
    assert audit.frameworks == ("NIS2", "GDPR")
    assert "NIS2" in audit.reason and "GDPR" in audit.reason
    # Non-overlapping promotions keep single provenance.
    assert overrides["backup_recovery"].frameworks == ("GDPR",)


def test_no_frameworks_means_no_tuning():
    assert slot_requiredness_overrides([]) == {}
    assert slot_requiredness_overrides(None) == {}
    assert slot_requiredness_overrides(["UNKNOWN_FRAMEWORK"]) == {}


def test_group_overrides_roll_up_from_promoted_slots():
    slot_rows = [
        SimpleNamespace(slot_id="monitoring_service", capability_group_key="operations"),
        SimpleNamespace(slot_id="audit_logging", capability_group_key="operations"),
        SimpleNamespace(slot_id="transaction_data_store", capability_group_key="data"),
    ]
    slot_overrides = slot_requiredness_overrides(["NIS2"])

    groups = group_requiredness_overrides(slot_rows, slot_overrides)

    assert set(groups) == {"operations"}
    assert groups["operations"].frameworks == ("NIS2",)
    # The shared reason is not duplicated when two slots carry the same rule.
    assert groups["operations"].reason.count("NIS2 expects") == 1

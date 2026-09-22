from src.core.constants.lifecycle_enums import LifecycleFamily, LifecycleTransitionSource
from src.core.services.lifecycle_audit_service import LifecycleAuditDetails, with_lifecycle_audit_metadata


def test_lifecycle_audit_metadata_is_additive_and_omits_unset_values():
    metadata = with_lifecycle_audit_metadata(
        {"discovery_run_id": "run-1"},
        LifecycleAuditDetails(
            object_type="discovery_run",
            object_id="run-1",
            family=LifecycleFamily.APPROVAL,
            source=LifecycleTransitionSource.HUMAN_APPROVED,
            previous_state="awaiting_approval",
            current_state="approved",
        ),
    )

    assert metadata["discovery_run_id"] == "run-1"
    assert metadata["lifecycle"] == {
        "objectType": "discovery_run",
        "objectId": "run-1",
        "family": "approval",
        "transitionSource": "human_approved",
        "previousState": "awaiting_approval",
        "currentState": "approved",
    }

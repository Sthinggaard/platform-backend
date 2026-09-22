import pytest
from pydantic import ValidationError

from src.api.schemas.assets import CreateAssetRequest
from src.core.constants import AssetArchetype, Provider
from src.core.models import Criticality, Environment, ScanStartMode, SetupConfidence


def _base_payload(**overrides):
    data = {
        "display_name": "Test Asset",
        "type": "cloud",
        "provider": Provider.AWS.value,
        "environment": Environment.PROD,
        "criticality": Criticality.MEDIUM,
        "layer": "L7",
        "archetype": AssetArchetype.CLOUD_ACCOUNT_GOVERNANCE,
        "intent": ["SECURITY_MONITORING"],
        "setup_confidence": SetupConfidence.MEDIUM,
        "scan_start_mode": ScanStartMode.AFTER_SME_CONFIRM,
        "business_owner_ref": "owner@example.com",
        "technical_owner_ref": "tech@example.com",
        "provider_account_id": "123456789012",
    }
    data.update(overrides)
    return data


def test_provider_other_requires_display_name():
    data = _base_payload(provider=Provider.OTHER.value, provider_display_name=None)
    with pytest.raises(ValidationError):
        CreateAssetRequest(**data)


def test_layer_archetype_mismatch():
    data = _base_payload(layer="L2", archetype=AssetArchetype.CLOUD_ACCOUNT_GOVERNANCE)
    with pytest.raises(ValidationError):
        CreateAssetRequest(**data)


def test_aws_account_must_be_12_digits():
    data = _base_payload(provider_account_id="abc")
    with pytest.raises(ValidationError):
        CreateAssetRequest(**data)


def test_valid_request_passes():
    obj = CreateAssetRequest(**_base_payload())
    assert obj.layer == "L7"
    assert obj.archetype == AssetArchetype.CLOUD_ACCOUNT_GOVERNANCE

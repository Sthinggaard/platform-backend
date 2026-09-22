import pytest
from sqlalchemy.orm import Session

from src.api.schemas.assets import CreateAssetRequest

from src.core.models import ConnectivityStatus, PermissionPreset, ScanStartMode, SetupConfidence, Criticality, Environment, Organization
from src.core.constants import AssetArchetype
from src.core.services.assets_service import complete_access_setup, create_asset_with_connection, verify_connection


@pytest.fixture
def db(db_session: Session) -> Session:
    """The shared Postgres session from `conftest` (#228), not a module-local engine.

    This module used to build its own engine from `TEST_POSTGRES_URL` and
    `drop_all()` at teardown — the same database the session-scoped `test_engine`
    owns. That took the schema out from under every suite that ran afterwards
    (#287). `db_session` rolls its transaction back instead, so nothing this
    module writes survives and nothing it does is visible outside it.
    """
    # A tenant has to exist for the FK constraints in the asset tests.
    db_session.add(
        Organization(
            id=1,
            name="Test Org",
            slug="test-org",
            plan_tier="trial",
            subscription_status="trial",
            onboarding_completed=False,
        )
    )
    db_session.commit()
    return db_session


def _create_payload():
    return CreateAssetRequest(
        display_name="Test Asset",
        type="aws_account",
        provider="AWS",
        environment=Environment.PROD,
        criticality=Criticality.MEDIUM,
        layer="L3",
        archetype=AssetArchetype.LOAD_BALANCER_INGRESS,
        secondary_layers=[4],
        intent=["SECURITY_MONITORING"],
        setup_confidence=SetupConfidence.MEDIUM,
        scan_start_mode=ScanStartMode.AFTER_SME_CONFIRM,
        business_owner_ref="owner@example.com",
        technical_owner_ref="tech@example.com",
        setup_assignee_ref=None,
        provider_account_id="123456789012",
        access_method="CROSS_ACCOUNT_ROLE",
        permission_preset=PermissionPreset.SECURITY_READONLY,
    )


def test_create_asset_creates_connection_and_external_id(db):
    payload = _create_payload()
    asset, connection, setup_url = create_asset_with_connection(db, organization_id=1, created_by_ref="creator@example.com", payload=payload)
    assert asset.id
    assert connection.external_id
    assert connection.connection_state.value == "INSTRUCTIONS_ISSUED"
    assert asset.connectivity_status == ConnectivityStatus.PENDING_VERIFICATION
    assert setup_url.endswith(f"/assets/{asset.id}/complete-setup")


def test_complete_setup_sets_role_arn_and_pending(db):
    payload = _create_payload()
    asset, connection, _ = create_asset_with_connection(db, organization_id=1, created_by_ref=None, payload=payload)
    connection = complete_access_setup(db, asset, role_arn="arn:aws:iam::123456789012:role/TestRole")
    assert connection.role_arn == "arn:aws:iam::123456789012:role/TestRole"
    assert connection.connection_state.value == "PENDING"


def test_verify_connection_success_sets_connected(db):
    payload = _create_payload()
    asset, connection, _ = create_asset_with_connection(db, organization_id=1, created_by_ref=None, payload=payload)
    # simulate completion
    connection.role_arn = "arn:aws:iam::123456789012:role/TestRole"
    db.add(connection)
    db.commit()
    success, conn, signal, _ = verify_connection(db, asset)
    assert success
    assert conn.connection_state.value == "VERIFIED"
    assert asset.connectivity_status == ConnectivityStatus.CONNECTED
    assert signal is not None

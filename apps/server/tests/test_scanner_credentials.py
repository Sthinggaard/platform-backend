"""Named scanner credentials (TENANT-83): validity calculation, expiry,
hash-only persistence, and tenant/scanner isolation. Route-level lifecycle
tests (create/rotate/pause/revoke/delete APIs, TENANT-84) live in
test_scanner_management.py alongside the rest of that router's coverage."""

from __future__ import annotations

from datetime import datetime, timedelta

import pytest
from sqlalchemy import create_engine
from sqlalchemy.dialects.postgresql import ARRAY as PgArray
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.dialects.sqlite import JSON as SqliteJSON
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool
from sqlalchemy.sql.sqltypes import ARRAY as SqlArray

from src.core.constants.evidence_scanner_enums import (
    SCANNER_CREDENTIAL_MAX_CUSTOM_DAYS,
    ScannerInstallationMethod,
)
from src.core.database import Base
from src.core.model_defs.evidence_scanner import (
    CollectorReadinessReport,
    ScannerCredential,
    ScannerDomainTarget,
    ScannerInstance,
    ScannerNetworkTarget,
)
from src.core.model_defs.evidence_source import EvidenceSource
from src.core.models import AuditEvent, Organization, User
from src.core.model_defs.common import utcnow
from src.core.services.evidence_scanner_service import (
    EvidenceScannerValidationError,
    compute_credential_expiry,
    create_credential,
    create_scanner,
    credential_can_authenticate,
    delete_credential,
    generate_activation_command,
    list_credentials_for_instance,
    pause_credential,
    resume_credential,
    revoke_credential,
    rotate_credential,
)


@pytest.fixture()
def db() -> Session:
    engine = create_engine("sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    for table in Base.metadata.tables.values():
        for column in table.columns:
            if isinstance(column.type, (SqlArray, PgArray, JSONB)):
                column.type = SqliteJSON()
    Base.metadata.create_all(
        engine,
        tables=[
            Organization.__table__,
            User.__table__,
            EvidenceSource.__table__,
            ScannerInstance.__table__,
            CollectorReadinessReport.__table__,
            ScannerDomainTarget.__table__,
            ScannerNetworkTarget.__table__,
            ScannerCredential.__table__,
            AuditEvent.__table__,
        ],
    )
    session = sessionmaker(bind=engine)()
    session.add_all(
        [
            Organization(id=1, name="Org", slug="org", country="DK", technical_setup_owner_user_id=1),
            Organization(id=2, name="Other Org", slug="other-org", country="DK", technical_setup_owner_user_id=3),
            User(id=1, organization_id=1, email="admin@example.com", role="org_admin"),
        ]
    )
    session.commit()
    yield session
    session.close()


def _naive_now() -> datetime:
    # SQLite round-trips DateTime columns as naive, unlike the aware
    # utcnow() this service uses — so DB-read expires_at needs a naive
    # reference to compare against, matching credential_can_authenticate's
    # own _naive_utc normalisation.
    return utcnow().replace(tzinfo=None)


def _instance(db: Session, organization_id: int = 1) -> ScannerInstance:
    result = create_scanner(
        db, organization_id=organization_id, name="Checkout & Payments", installation_method=ScannerInstallationMethod.DOCKER.value
    )
    db.commit()
    return result.instance


# --- Validity calculation ----------------------------------------------------------


def test_one_month_policy_expires_in_30_days():
    now = utcnow()
    expiry = compute_credential_expiry(validity_policy="one_month", custom_days=None, now=now)
    assert expiry == now + timedelta(days=30)


def test_three_months_policy_expires_in_90_days():
    now = utcnow()
    expiry = compute_credential_expiry(validity_policy="three_months", custom_days=None, now=now)
    assert expiry == now + timedelta(days=90)


def test_six_months_policy_expires_in_180_days():
    now = utcnow()
    expiry = compute_credential_expiry(validity_policy="six_months", custom_days=None, now=now)
    assert expiry == now + timedelta(days=180)


def test_one_time_policy_has_no_calendar_expiry():
    assert compute_credential_expiry(validity_policy="one_time", custom_days=None) is None


def test_custom_policy_uses_caller_supplied_days():
    now = utcnow()
    expiry = compute_credential_expiry(validity_policy="custom", custom_days=45, now=now)
    assert expiry == now + timedelta(days=45)


def test_custom_policy_requires_days():
    with pytest.raises(EvidenceScannerValidationError):
        compute_credential_expiry(validity_policy="custom", custom_days=None)


def test_custom_policy_rejects_out_of_range_days():
    with pytest.raises(EvidenceScannerValidationError):
        compute_credential_expiry(validity_policy="custom", custom_days=0)
    with pytest.raises(EvidenceScannerValidationError):
        compute_credential_expiry(validity_policy="custom", custom_days=SCANNER_CREDENTIAL_MAX_CUSTOM_DAYS + 1)


# --- Create / hash-only persistence -------------------------------------------------


def test_create_credential_returns_raw_token_once_and_persists_only_hash(db: Session):
    instance = _instance(db)
    result = create_credential(db, instance, name="Checkout & Payments credential", validity_policy="three_months")
    db.commit()
    assert len(result.activation_token) > 20
    stored = db.query(ScannerCredential).filter(ScannerCredential.id == result.credential.id).first()
    assert stored.token_hash != result.activation_token
    assert result.activation_token not in stored.token_hash
    assert stored.status == "active"
    assert stored.expires_at is not None


def test_create_credential_requires_name(db: Session):
    instance = _instance(db)
    with pytest.raises(EvidenceScannerValidationError):
        create_credential(db, instance, name="   ", validity_policy="one_month")


def test_multiple_credentials_coexist_without_replacing_each_other(db: Session):
    instance = _instance(db)
    first = create_credential(db, instance, name="Primary key", validity_policy="one_month")
    second = create_credential(db, instance, name="Backup key", validity_policy="six_months")
    db.commit()
    credentials = list_credentials_for_instance(db, instance.id)
    ids = {c.id for c in credentials}
    assert first.credential.id in ids
    assert second.credential.id in ids
    assert len(credentials) == 2


# --- Lifecycle: rotate/pause/resume/revoke/delete ------------------------------------


def test_rotate_without_choice_keeps_same_policy_renewed_from_now(db: Session):
    instance = _instance(db)
    created = create_credential(db, instance, name="Key", validity_policy="one_month")
    db.commit()
    original_hash = created.credential.token_hash

    later = _naive_now() + timedelta(days=10)
    rotated = rotate_credential(db, created.credential)
    db.commit()

    assert rotated.credential.id == created.credential.id
    assert rotated.credential.token_hash != original_hash
    assert rotated.credential.validity_policy == "one_month"
    # Renewed from the rotation moment, not the original creation moment —
    # 10 days after creation, a "keep the same duration" rotate should
    # still leave ~30 days of runway, not ~20.
    assert rotated.credential.expires_at > later + timedelta(days=15)
    assert rotated.activation_token != created.activation_token


def test_rotate_can_switch_to_a_new_duration(db: Session):
    instance = _instance(db)
    created = create_credential(db, instance, name="Key", validity_policy="one_month")
    db.commit()

    rotated = rotate_credential(db, created.credential, validity_policy="six_months")
    db.commit()

    assert rotated.credential.validity_policy == "six_months"
    assert rotated.credential.expires_at > _naive_now() + timedelta(days=170)


def test_rotate_keeping_same_custom_duration_reuses_original_day_count(db: Session):
    instance = _instance(db)
    created = create_credential(db, instance, name="Key", validity_policy="custom", custom_days=45)
    db.commit()
    assert created.credential.validity_custom_days == 45

    rotated = rotate_credential(db, created.credential)
    db.commit()

    assert rotated.credential.validity_policy == "custom"
    assert rotated.credential.validity_custom_days == 45
    assert rotated.credential.expires_at > _naive_now() + timedelta(days=40)


def test_rotate_switching_to_custom_requires_new_day_count(db: Session):
    instance = _instance(db)
    created = create_credential(db, instance, name="Key", validity_policy="one_month")
    db.commit()

    rotated = rotate_credential(db, created.credential, validity_policy="custom", custom_days=20)
    db.commit()

    assert rotated.credential.validity_policy == "custom"
    assert rotated.credential.validity_custom_days == 20


def test_rotate_a_one_time_credential_resets_its_single_use(db: Session):
    instance = _instance(db)
    created = create_credential(db, instance, name="Bootstrap key", validity_policy="one_time")
    db.commit()
    created.credential.consumed_at = utcnow()
    assert credential_can_authenticate(created.credential) is False

    rotated = rotate_credential(db, created.credential)
    db.commit()

    assert rotated.credential.consumed_at is None
    assert credential_can_authenticate(rotated.credential) is True


def test_pause_then_resume_round_trip(db: Session):
    instance = _instance(db)
    created = create_credential(db, instance, name="Key", validity_policy="one_month")
    db.commit()

    paused = pause_credential(db, created.credential)
    assert paused.status == "paused"
    assert credential_can_authenticate(paused) is False

    resumed = resume_credential(db, created.credential)
    assert resumed.status == "active"
    assert credential_can_authenticate(resumed) is True


def test_revoke_is_permanent_and_cannot_be_resumed(db: Session):
    instance = _instance(db)
    created = create_credential(db, instance, name="Key", validity_policy="one_month")
    db.commit()

    revoked = revoke_credential(db, created.credential, revoked_by_user_id=1)
    assert revoked.status == "revoked"
    assert revoked.revoked_at is not None
    assert credential_can_authenticate(revoked) is False

    with pytest.raises(EvidenceScannerValidationError):
        revoke_credential(db, created.credential)


def test_delete_blocked_while_active(db: Session):
    instance = _instance(db)
    created = create_credential(db, instance, name="Key", validity_policy="one_month")
    db.commit()
    with pytest.raises(EvidenceScannerValidationError):
        delete_credential(db, created.credential)


def test_delete_allowed_after_revoke_and_hides_from_listing(db: Session):
    instance = _instance(db)
    created = create_credential(db, instance, name="Key", validity_policy="one_month")
    db.commit()
    revoke_credential(db, created.credential)
    deleted = delete_credential(db, created.credential)
    db.commit()
    assert deleted.deleted_at is not None
    assert created.credential.id not in {c.id for c in list_credentials_for_instance(db, instance.id)}


# --- Expiry / authentication gate ---------------------------------------------------


def test_expired_calendar_credential_cannot_authenticate(db: Session):
    instance = _instance(db)
    now = utcnow()
    created = create_credential(db, instance, name="Key", validity_policy="custom", custom_days=1)
    db.commit()
    assert credential_can_authenticate(created.credential, now=now + timedelta(days=2)) is False
    assert credential_can_authenticate(created.credential, now=now) is True


def test_one_time_credential_cannot_authenticate_after_consumption(db: Session):
    instance = _instance(db)
    created = create_credential(db, instance, name="Bootstrap key", validity_policy="one_time")
    db.commit()
    assert credential_can_authenticate(created.credential) is True
    created.credential.consumed_at = utcnow()
    assert credential_can_authenticate(created.credential) is False


# --- Tenant / scanner isolation ------------------------------------------------------


def test_credentials_are_scoped_to_their_scanner_instance(db: Session):
    instance_a = _instance(db)
    result_a = create_scanner(db, organization_id=1, name="Vendor Onboarding", installation_method=ScannerInstallationMethod.DOCKER.value)
    db.commit()
    instance_b = result_a.instance

    create_credential(db, instance_a, name="A key", validity_policy="one_month")
    create_credential(db, instance_b, name="B key", validity_policy="one_month")
    db.commit()

    a_credentials = list_credentials_for_instance(db, instance_a.id)
    b_credentials = list_credentials_for_instance(db, instance_b.id)
    assert len(a_credentials) == 1
    assert len(b_credentials) == 1
    assert a_credentials[0].name == "A key"
    assert b_credentials[0].name == "B key"


def test_credentials_carry_their_own_organization_id_for_tenant_isolation(db: Session):
    org1_instance = _instance(db, organization_id=1)
    org2_instance = _instance(db, organization_id=2)

    created_1 = create_credential(db, org1_instance, name="Org 1 key", validity_policy="one_month")
    created_2 = create_credential(db, org2_instance, name="Org 2 key", validity_policy="one_month")
    db.commit()

    assert created_1.credential.organization_id == 1
    assert created_2.credential.organization_id == 2


# --- Terminal activation command -----------------------------------------------------


def test_activation_command_matches_the_real_scanner_cli_signature():
    # apps/scanner/scanner_agent/cli.py's `activate` command takes exactly
    # --base-url and --token — no --tenant flag exists on the real CLI.
    command = generate_activation_command(activation_token="abc123")
    assert command == "risklence-scanner activate --base-url https://api.risklence.com --token abc123"

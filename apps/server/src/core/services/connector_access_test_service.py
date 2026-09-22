"""CA-07.4 — proving access works, and saying something an operator can act on.

**A connection test is not verification.** CA-07's headline rule is that access
never starts verification, and this is where the line is drawn: a test proves the
pipe is open and the approved permissions are sufficient. It reads nothing about
the estate, produces no evidence, and reaches no conclusion about risk. That is
CA-08, separately, behind its own human approval.

**The platform mostly does not perform the test.** Credentials are local to the
Collector (CA-07.2), so the platform records a *request* and the Collector reports
the outcome — the shape ``record_test_scan_result`` already uses.

The exception is deliberate: two failures can be answered without any credential
at all — the Connector is withdrawn, or no permission profile was ever approved.
Those are **ours, not theirs**, and asking a Collector to discover them would be
theatre. They are recorded as completed failures rather than raised as errors, so
they land in the same history as every other result: *"when did this stop
working, and what did it say at the time?"* deserves one answer, not two places
to look.

**Reachability and permission adequacy are two answers, not one verdict.** A
Connector can be perfectly reachable and still unable to do what its profile
grants. Collapsing them would send an operator to the network when the problem is
an account's rights.

The caller owns the transaction (commit).
"""

from __future__ import annotations

from datetime import timedelta

from sqlalchemy.orm import Session

from src.core.constants.connector_access_test_enums import (
    ACCESS_TEST_TIMEOUT_MINUTES,
    CONNECTOR_ACCESS_TEST_REMEDIES,
    TEST_AUDIT_EXPIRED,
    TEST_AUDIT_REQUESTED,
    TEST_AUDIT_RESULT_RECORDED,
    TEST_ERROR_ALREADY_COMPLETE,
    TEST_ERROR_ALREADY_PENDING,
    TEST_ERROR_CAPABILITY_NOT_IN_PROFILE,
    TEST_ERROR_FAILURE_CODE_REQUIRED,
    TEST_ERROR_UNKNOWN_FAILURE_CODE,
    ConnectorAccessTestFailure,
    ConnectorAccessTestStatus,
)
from src.core.model_defs.access_connector import AccessConnector
from src.core.model_defs.common import utcnow
from src.core.model_defs.connector_access_test import ConnectorAccessTest
from src.core.model_defs.permission_profile import PermissionProfile
from src.core.services.audit_service import append_audit_event
from src.core.services.permission_profile_service import get_active_profile


class ConnectorAccessTestValidationError(ValueError):
    """Raised when an access test request or result is invalid."""


def remedy_for(failure_code: str | None) -> str | None:
    """The one place a failure code becomes advice.

    Kept as a lookup rather than a branch so a surface never invents its own
    wording, and so "every failure names something a person can go and change"
    stays checkable instead of aspirational.
    """
    if failure_code is None:
        return None
    return CONNECTOR_ACCESS_TEST_REMEDIES.get(failure_code)


def request_access_test(
    db: Session, connector: AccessConnector, *, requested_by_user_id: int | None = None
) -> ConnectorAccessTest:
    """Ask the Collector to prove this Connector works, or say why we cannot ask.

    Returns a test in ``requested`` when the Collector has been asked, and a test
    already in ``failed`` when the answer needed no Collector at all.
    """
    expire_stale_access_tests(db, organization_id=connector.organization_id)

    pending = _pending_test(db, connector)
    if pending is not None:
        raise ConnectorAccessTestValidationError(TEST_ERROR_ALREADY_PENDING)

    # Answerable here, without a credential and without the Collector.
    inactive_reason = connector.permission_subject_inactive_reason
    if inactive_reason is not None:
        return _record_immediate_failure(
            db,
            connector,
            failure_code=ConnectorAccessTestFailure.CONNECTOR_NOT_ACTIVE.value,
            failure_detail=inactive_reason,
            requested_by_user_id=requested_by_user_id,
        )

    profile = get_active_profile(
        db,
        organization_id=connector.organization_id,
        subject_id=connector.permission_subject_id,
    )
    if profile is None:
        # There is nothing to measure adequacy against. Testing anyway would
        # return "reachable", which reads as success and answers nothing.
        return _record_immediate_failure(
            db,
            connector,
            failure_code=ConnectorAccessTestFailure.NO_APPROVED_PERMISSION_PROFILE.value,
            failure_detail=None,
            requested_by_user_id=requested_by_user_id,
        )

    test = ConnectorAccessTest(
        organization_id=connector.organization_id,
        connector_id=connector.id,
        # Pinned, because profiles supersede. A result that outlived the grant it
        # was measured against would be unreadable a version later.
        permission_profile_id=profile.id,
        status=ConnectorAccessTestStatus.REQUESTED.value,
        requested_by_user_id=requested_by_user_id,
    )
    db.add(test)
    db.flush()
    append_audit_event(
        db,
        connector.organization_id,
        TEST_AUDIT_REQUESTED,
        actor_user_id=requested_by_user_id,
        metadata=_metadata(test),
    )
    return test


def record_access_test_result(
    db: Session,
    test: ConnectorAccessTest,
    *,
    reachable: bool,
    permissions_adequate: bool,
    capabilities_confirmed: list[str] | None = None,
    failure_code: str | None = None,
    failure_detail: str | None = None,
) -> ConnectorAccessTest:
    """Record what the Collector reported. The platform observed none of it.

    A result may only be reported once: a test that could be overwritten would
    lose the very thing a history table exists to keep.
    """
    if test.status != ConnectorAccessTestStatus.REQUESTED.value:
        raise ConnectorAccessTestValidationError(TEST_ERROR_ALREADY_COMPLETE)

    succeeded = bool(reachable) and bool(permissions_adequate)
    if failure_code is not None:
        if failure_code not in {f.value for f in ConnectorAccessTestFailure}:
            raise ConnectorAccessTestValidationError(
                TEST_ERROR_UNKNOWN_FAILURE_CODE.format(code=failure_code)
            )
        # A code alongside "everything worked" is a contradiction, and silently
        # picking one of the two would decide for the operator.
        succeeded = False
    elif not succeeded:
        # The story's fourth criterion, enforced rather than hoped for: a failure
        # with no code is the "connection error" that tells nobody anything.
        raise ConnectorAccessTestValidationError(TEST_ERROR_FAILURE_CODE_REQUIRED)

    test.reachable = bool(reachable)
    test.permissions_adequate = bool(permissions_adequate)
    test.capabilities_confirmed = _validate_confirmed(db, test, capabilities_confirmed or [])
    test.failure_code = failure_code
    test.failure_detail = failure_detail
    test.status = (
        ConnectorAccessTestStatus.SUCCEEDED.value
        if succeeded
        else ConnectorAccessTestStatus.FAILED.value
    )
    test.completed_at = utcnow()
    db.add(test)
    append_audit_event(
        db, test.organization_id, TEST_AUDIT_RESULT_RECORDED, metadata=_metadata(test)
    )
    return test


def expire_stale_access_tests(db: Session, *, organization_id: int) -> list[ConnectorAccessTest]:
    """Close out requests the Collector never answered.

    ``EXPIRED`` is its own status and not a kind of ``FAILED``, because *"we asked
    and heard nothing"* and *"we asked and it said no"* send an operator to
    different places — the first to the Collector, the second to the target.
    """
    cutoff = utcnow() - timedelta(minutes=ACCESS_TEST_TIMEOUT_MINUTES)
    stale = (
        db.query(ConnectorAccessTest)
        .filter(
            ConnectorAccessTest.organization_id == organization_id,
            ConnectorAccessTest.status == ConnectorAccessTestStatus.REQUESTED.value,
            ConnectorAccessTest.requested_at < cutoff,
        )
        .all()
    )
    for test in stale:
        test.status = ConnectorAccessTestStatus.EXPIRED.value
        test.completed_at = utcnow()
        db.add(test)
        append_audit_event(
            db, organization_id, TEST_AUDIT_EXPIRED, metadata=_metadata(test)
        )
    return stale


def list_access_tests(
    db: Session, *, organization_id: int, connector_id: str, limit: int = 50
) -> list[ConnectorAccessTest]:
    """The Connector's test history, newest first."""
    return (
        db.query(ConnectorAccessTest)
        .filter(
            ConnectorAccessTest.organization_id == organization_id,
            ConnectorAccessTest.connector_id == connector_id,
        )
        .order_by(ConnectorAccessTest.requested_at.desc())
        .limit(limit)
        .all()
    )


def _pending_test(db: Session, connector: AccessConnector) -> ConnectorAccessTest | None:
    return (
        db.query(ConnectorAccessTest)
        .filter(
            ConnectorAccessTest.organization_id == connector.organization_id,
            ConnectorAccessTest.connector_id == connector.id,
            ConnectorAccessTest.status == ConnectorAccessTestStatus.REQUESTED.value,
        )
        .first()
    )


def _record_immediate_failure(
    db: Session,
    connector: AccessConnector,
    *,
    failure_code: str,
    failure_detail: str | None,
    requested_by_user_id: int | None,
) -> ConnectorAccessTest:
    """A failure the platform can state on its own, kept in the same history.

    Written as a completed test rather than raised as an error so that the answer
    to "why has this not been tested?" sits beside every other result, instead of
    only in whatever the requester saw on screen at the time.
    """
    now = utcnow()
    test = ConnectorAccessTest(
        organization_id=connector.organization_id,
        connector_id=connector.id,
        status=ConnectorAccessTestStatus.FAILED.value,
        requested_by_user_id=requested_by_user_id,
        completed_at=now,
        reachable=None,
        permissions_adequate=None,
        failure_code=failure_code,
        failure_detail=failure_detail,
    )
    db.add(test)
    db.flush()
    append_audit_event(
        db,
        connector.organization_id,
        TEST_AUDIT_RESULT_RECORDED,
        actor_user_id=requested_by_user_id,
        metadata=_metadata(test),
    )
    return test


def _validate_confirmed(
    db: Session, test: ConnectorAccessTest, capabilities: list[str]
) -> list[str]:
    """A Collector may only confirm what its approved profile granted.

    A report naming something outside the profile is either confused or claiming
    more than it was given, and recording it as fact would turn the test history
    into a second, unapproved record of what a Connector may do.
    """
    if not capabilities:
        return []
    granted = _granted_capabilities(db, test)
    cleaned: list[str] = []
    for capability in capabilities:
        if capability not in granted:
            raise ConnectorAccessTestValidationError(
                TEST_ERROR_CAPABILITY_NOT_IN_PROFILE.format(capability=capability)
            )
        if capability not in cleaned:
            cleaned.append(capability)
    return cleaned


def _granted_capabilities(db: Session, test: ConnectorAccessTest) -> set[str]:
    if test.permission_profile_id is None:
        return set()
    profile = db.get(PermissionProfile, test.permission_profile_id)
    return set(profile.capabilities or []) if profile is not None else set()


def _metadata(test: ConnectorAccessTest) -> dict:
    """What the trail carries. No failure detail: it is free text from a machine
    that is the only party holding a credential, and an audit table is the last
    place an echoed secret should come to rest."""
    return {
        "access_test_id": test.id,
        "connector_id": test.connector_id,
        "permission_profile_id": test.permission_profile_id,
        "status": test.status,
        "reachable": test.reachable,
        "permissions_adequate": test.permissions_adequate,
        "failure_code": test.failure_code,
    }

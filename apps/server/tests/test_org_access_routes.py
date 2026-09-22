"""Organisation access configuration is tenant-scoped and mandate-specific."""

from __future__ import annotations

from uuid import uuid4

import pytest

from src.api.middleware.tenant_context import TenantContext
from src.api.routes import org_access
from src.api.schemas.org_access import (
    MandateRoleAssignmentWriteRequest,
    MandateScopeBindingWriteRequest,
    ReportingLineExceptionWriteRequest,
    VisibilityPolicyWriteRequest,
)
from src.core.constants.org_access_enums import (
    CanonicalMandateRole,
    IdentityProvider,
    MandateAssignmentSubjectType,
    MandateScopeType,
    OrgAccessAuditEvent,
)
from src.core.exceptions import AuthorizationError, ResourceNotFoundError, ValidationError
from src.core.model_defs.org_access import (
    OrgMandateRoleAssignment,
    OrgMandateScopeBinding,
    OrgReportingLineException,
    OrgVisibilityPolicy,
)
from src.core.models import AuditEvent, BusinessService, User, ValueStream
from src.core.services.org_access_policy_service import (
    OrgAccessPolicyValidationError,
    validate_assignment_subject,
)


class FakeDB:
    def __init__(self, records=None):
        self.records = records or {}
        self.added: list[object] = []
        self.deleted: list[object] = []
        self.commits = 0

    def add(self, record):
        self.added.append(record)
        self.records.setdefault(type(record), []).append(record)

    def commit(self):
        self.commits += 1

    def flush(self):
        for record in self.added:
            if isinstance(
                record,
                (
                    OrgMandateRoleAssignment,
                    OrgMandateScopeBinding,
                    OrgReportingLineException,
                ),
            ) and record.id is None:
                record.id = str(uuid4())

    def refresh(self, _record):
        pass


class FakeTenantRepository:
    scope_ids: list[int] = []

    def __init__(self, db, model_class, organization_id):
        self.db = db
        self.model_class = model_class
        self.organization_id = organization_id
        self.scope_ids.append(organization_id)

    def _records(self):
        return [
            record
            for record in self.db.records.get(self.model_class, [])
            if record.organization_id == self.organization_id
        ]

    def get_all(self):
        return self._records()

    def get_by_id(self, record_id):
        return next((record for record in self._records() if record.id == record_id), None)

    def filter_by(self, **kwargs):
        return [
            record
            for record in self._records()
            if all(getattr(record, key) == value for key, value in kwargs.items())
        ]

    def create(self, **kwargs):
        kwargs["organization_id"] = self.organization_id
        record = self.model_class(**kwargs)
        self.db.add(record)
        return record

    def update(self, record, **kwargs):
        for key, value in kwargs.items():
            setattr(record, key, value)
        return record

    def delete(self, record):
        self.db.deleted.append(record)


def _context(*, role="org_admin"):
    return TenantContext(
        user_id=1,
        organization_id=7,
        email="admin@risklence.test",
        roles=[role],
        permissions=[],
    )


def _user(user_id, organization_id, role="member"):
    return User(
        id=user_id,
        organization_id=organization_id,
        email=f"user-{user_id}@risklence.test",
        role=role,
        is_active=True,
    )


@pytest.fixture(autouse=True)
def tenant_repository(monkeypatch):
    FakeTenantRepository.scope_ids = []
    monkeypatch.setattr(org_access, "TenantRepository", FakeTenantRepository)


def test_assignment_subject_rejects_mixed_user_and_identity_group():
    with pytest.raises(OrgAccessPolicyValidationError):
        validate_assignment_subject(
            subject_type=MandateAssignmentSubjectType.USER,
            user_id=3,
            identity_group_id="group-1",
            identity_provider=None,
        )


def test_create_role_assignment_scopes_target_user_and_writes_audit_event():
    db = FakeDB({User: [_user(1, 7, role="org_admin"), _user(2, 7)]})

    response = org_access.create_role_assignment(
        MandateRoleAssignmentWriteRequest(
            canonical_role=CanonicalMandateRole.BUSINESS_PROCESS_OWNER,
            subject_type=MandateAssignmentSubjectType.USER,
            user_id=2,
        ),
        ctx=_context(),
        db=db,
    )

    assignment = db.records[OrgMandateRoleAssignment][0]
    audit_event = next(record for record in db.added if isinstance(record, AuditEvent))
    assert response.user_id == 2
    assert assignment.organization_id == 7
    assert audit_event.organization_id == 7
    assert audit_event.event_type == OrgAccessAuditEvent.MANDATE_ROLE_ASSIGNED.value
    assert FakeTenantRepository.scope_ids == [7, 7, 7]


def test_create_role_assignment_rejects_a_user_from_another_organisation():
    db = FakeDB({User: [_user(1, 7, role="org_admin"), _user(2, 9)]})

    with pytest.raises(ResourceNotFoundError):
        org_access.create_role_assignment(
            MandateRoleAssignmentWriteRequest(
                canonical_role=CanonicalMandateRole.BUSINESS_SERVICE_OWNER,
                subject_type=MandateAssignmentSubjectType.USER,
                user_id=2,
            ),
            ctx=_context(),
            db=db,
        )

    assert OrgMandateRoleAssignment not in db.records


def test_identity_group_mappings_distinguish_identity_provider():
    db = FakeDB({User: [_user(1, 7, role="org_admin")]})
    request = {
        "canonical_role": CanonicalMandateRole.BUSINESS_SERVICE_OWNER,
        "subject_type": MandateAssignmentSubjectType.IDENTITY_GROUP,
        "identity_group_id": "operations",
    }

    org_access.create_role_assignment(
        MandateRoleAssignmentWriteRequest(
            **request,
            identity_provider=IdentityProvider.AZURE_AD,
        ),
        ctx=_context(),
        db=db,
    )
    org_access.create_role_assignment(
        MandateRoleAssignmentWriteRequest(
            **request,
            identity_provider=IdentityProvider.GOOGLE_WORKSPACE,
        ),
        ctx=_context(),
        db=db,
    )

    assert len(db.records[OrgMandateRoleAssignment]) == 2


def test_identity_group_mapping_rejects_the_same_provider_and_group():
    assignment = OrgMandateRoleAssignment(
        id="assignment-1",
        organization_id=7,
        canonical_role=CanonicalMandateRole.BUSINESS_SERVICE_OWNER.value,
        subject_type=MandateAssignmentSubjectType.IDENTITY_GROUP.value,
        identity_group_id="operations",
        identity_provider=IdentityProvider.AZURE_AD.value,
    )
    db = FakeDB({User: [_user(1, 7, role="org_admin")], OrgMandateRoleAssignment: [assignment]})

    with pytest.raises(ValidationError):
        org_access.create_role_assignment(
            MandateRoleAssignmentWriteRequest(
                canonical_role=CanonicalMandateRole.BUSINESS_SERVICE_OWNER,
                subject_type=MandateAssignmentSubjectType.IDENTITY_GROUP,
                identity_group_id="operations",
                identity_provider=IdentityProvider.AZURE_AD,
            ),
            ctx=_context(),
            db=db,
        )


def test_visibility_policy_keeps_overview_and_full_detail_rules_independent():
    db = FakeDB({User: [_user(1, 7, role="org_admin")]})

    response = org_access.update_visibility_policy(
        VisibilityPolicyWriteRequest(
            overview_role_keys=[
                CanonicalMandateRole.ORG_WIDE_VISIBILITY,
                CanonicalMandateRole.ORG_WIDE_VISIBILITY,
            ],
            full_detail_role_keys=[CanonicalMandateRole.BUSINESS_PROCESS_OWNER],
        ),
        ctx=_context(),
        db=db,
    )

    policy = db.records[OrgVisibilityPolicy][0]
    assert response.overview_role_keys == [CanonicalMandateRole.ORG_WIDE_VISIBILITY]
    assert response.full_detail_role_keys == [CanonicalMandateRole.BUSINESS_PROCESS_OWNER]
    assert policy.overview_role_keys == [CanonicalMandateRole.ORG_WIDE_VISIBILITY.value]
    assert policy.full_detail_role_keys == [CanonicalMandateRole.BUSINESS_PROCESS_OWNER.value]


def test_scope_binding_uses_an_eligible_role_assignment_and_writes_an_audit_event():
    assignment = OrgMandateRoleAssignment(
        id="assignment-1",
        organization_id=7,
        canonical_role=CanonicalMandateRole.BUSINESS_PROCESS_OWNER.value,
        subject_type=MandateAssignmentSubjectType.USER.value,
        user_id=2,
    )
    process = ValueStream(id="process-1", organization_id=7, name="Order to cash")
    db = FakeDB(
        {
            User: [_user(1, 7, role="org_admin"), _user(2, 7)],
            OrgMandateRoleAssignment: [assignment],
            ValueStream: [process],
        }
    )

    response = org_access.upsert_scope_binding(
        MandateScopeBindingWriteRequest(
            scope_type=MandateScopeType.BUSINESS_PROCESS,
            scope_id=process.id,
            canonical_role=CanonicalMandateRole.BUSINESS_PROCESS_OWNER,
            role_assignment_id=assignment.id,
        ),
        ctx=_context(),
        db=db,
    )

    binding = db.records[OrgMandateScopeBinding][0]
    audit_event = next(record for record in db.added if isinstance(record, AuditEvent))
    assert response.value_stream_id == process.id
    assert binding.organization_id == 7
    assert binding.role_assignment_id == assignment.id
    assert audit_event.event_type == OrgAccessAuditEvent.MANDATE_SCOPE_BOUND.value


def test_scope_binding_rejects_wrong_role_or_another_tenants_scope():
    assignment = OrgMandateRoleAssignment(
        id="assignment-1",
        organization_id=7,
        canonical_role=CanonicalMandateRole.BUSINESS_PROCESS_OWNER.value,
        subject_type=MandateAssignmentSubjectType.USER.value,
        user_id=2,
    )
    other_tenant_service = BusinessService(
        id="service-9",
        organization_id=9,
        name="Payments",
    )
    db = FakeDB(
        {
            User: [_user(1, 7, role="org_admin"), _user(2, 7)],
            OrgMandateRoleAssignment: [assignment],
            BusinessService: [other_tenant_service],
        }
    )

    with pytest.raises(ValidationError):
        org_access.upsert_scope_binding(
            MandateScopeBindingWriteRequest(
                scope_type=MandateScopeType.BUSINESS_SERVICE,
                scope_id=other_tenant_service.id,
                canonical_role=CanonicalMandateRole.BUSINESS_PROCESS_OWNER,
                role_assignment_id=assignment.id,
            ),
            ctx=_context(),
            db=db,
        )

    with pytest.raises(ResourceNotFoundError):
        org_access.upsert_scope_binding(
            MandateScopeBindingWriteRequest(
                scope_type=MandateScopeType.BUSINESS_PROCESS,
                scope_id="process-other-tenant",
                canonical_role=CanonicalMandateRole.BUSINESS_PROCESS_OWNER,
                role_assignment_id=assignment.id,
            ),
            ctx=_context(),
            db=db,
        )


def test_scope_binding_rejects_a_role_assignment_for_a_different_canonical_role():
    assignment = OrgMandateRoleAssignment(
        id="assignment-1",
        organization_id=7,
        canonical_role=CanonicalMandateRole.BUSINESS_SERVICE_OWNER.value,
        subject_type=MandateAssignmentSubjectType.USER.value,
        user_id=2,
    )
    process = ValueStream(id="process-1", organization_id=7, name="Order to cash")
    db = FakeDB(
        {
            User: [_user(1, 7, role="org_admin"), _user(2, 7)],
            OrgMandateRoleAssignment: [assignment],
            ValueStream: [process],
        }
    )

    with pytest.raises(ValidationError):
        org_access.upsert_scope_binding(
            MandateScopeBindingWriteRequest(
                scope_type=MandateScopeType.BUSINESS_PROCESS,
                scope_id=process.id,
                canonical_role=CanonicalMandateRole.BUSINESS_PROCESS_OWNER,
                role_assignment_id=assignment.id,
            ),
            ctx=_context(),
            db=db,
        )


def test_reporting_line_exception_is_tenant_scoped_and_audited():
    db = FakeDB({User: [_user(1, 7, role="org_admin"), _user(2, 7), _user(3, 7)]})

    response = org_access.set_reporting_line_exception(
        2,
        ReportingLineExceptionWriteRequest(
            manager_user_id=3,
            exception_reason="Directory manager data is unavailable for this contractor.",
        ),
        ctx=_context(),
        db=db,
    )

    exception = db.records[OrgReportingLineException][0]
    audit_event = next(record for record in db.added if isinstance(record, AuditEvent))
    assert response.employee_user_id == 2
    assert response.manager_user_id == 3
    assert exception.organization_id == 7
    assert audit_event.event_type == OrgAccessAuditEvent.REPORTING_LINE_EXCEPTION_SET.value


def test_reporting_line_exception_rejects_self_manager_and_other_tenant_manager():
    db = FakeDB({User: [_user(1, 7, role="org_admin"), _user(2, 7), _user(3, 9)]})

    with pytest.raises(ValidationError):
        org_access.set_reporting_line_exception(
            2,
            ReportingLineExceptionWriteRequest(
                manager_user_id=2,
                exception_reason="Invalid self relationship.",
            ),
            ctx=_context(),
            db=db,
        )

    with pytest.raises(ResourceNotFoundError):
        org_access.set_reporting_line_exception(
            2,
            ReportingLineExceptionWriteRequest(
                manager_user_id=3,
                exception_reason="Manager is in another tenant.",
            ),
            ctx=_context(),
            db=db,
        )


def test_delete_role_assignment_does_not_cross_tenant_boundary():
    assignment = OrgMandateRoleAssignment(
        id="assignment-other-tenant",
        organization_id=9,
        canonical_role=CanonicalMandateRole.BUSINESS_PROCESS_OWNER.value,
        subject_type=MandateAssignmentSubjectType.USER.value,
        user_id=2,
    )
    db = FakeDB({User: [_user(1, 7, role="org_admin")], OrgMandateRoleAssignment: [assignment]})

    with pytest.raises(ResourceNotFoundError):
        org_access.delete_role_assignment(assignment.id, ctx=_context(), db=db)

    assert db.deleted == []


def test_delete_role_assignment_requires_scoped_bindings_to_be_explicitly_removed():
    assignment = OrgMandateRoleAssignment(
        id="assignment-1",
        organization_id=7,
        canonical_role=CanonicalMandateRole.BUSINESS_PROCESS_OWNER.value,
        subject_type=MandateAssignmentSubjectType.USER.value,
        user_id=2,
    )
    binding = OrgMandateScopeBinding(
        id="binding-1",
        organization_id=7,
        scope_type=MandateScopeType.BUSINESS_PROCESS.value,
        value_stream_id="process-1",
        canonical_role=CanonicalMandateRole.BUSINESS_PROCESS_OWNER.value,
        role_assignment_id=assignment.id,
    )
    db = FakeDB(
        {
            User: [_user(1, 7, role="org_admin")],
            OrgMandateRoleAssignment: [assignment],
            OrgMandateScopeBinding: [binding],
        }
    )

    with pytest.raises(ValidationError):
        org_access.delete_role_assignment(assignment.id, ctx=_context(), db=db)

    assert db.deleted == []


def test_role_mapping_requires_global_org_administration_not_a_mandate_role():
    db = FakeDB({User: [_user(1, 7, role="member")]})

    with pytest.raises(AuthorizationError):
        org_access.get_org_access_configuration(ctx=_context(role="member"), db=db)

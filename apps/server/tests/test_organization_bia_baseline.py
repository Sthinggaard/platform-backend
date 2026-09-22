"""Organisation-wide BIA baseline lifecycle and authorisation."""

from __future__ import annotations

import pytest
from sqlalchemy import create_engine
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.dialects.sqlite import JSON as SqliteJSON
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool
from sqlalchemy.sql.sqltypes import ARRAY as SqlArray

from src.api.middleware.tenant_context import TenantContext
from src.api.routes import organization_bia
from src.core.database import Base
from src.core.exceptions import AuthorizationError
from src.core.model_defs.organization_bia_baseline import (
    ORGANIZATION_BIA_AUDIT_SET,
    ORGANIZATION_BIA_BASELINE_SUPERSEDED,
    OrganizationBiaBaseline,
)
from src.core.models import AuditEvent, Organization, User

_ANSWERS = {
    "impact1h": "severe",
    "impact4h": "high",
    "impact24h": "medium",
    "mtd": "le_4h",
    "workaround": "partial",
    "alternativeChannel": "none",
    "dataSensitivity": "high",
}


@pytest.fixture()
def db() -> Session:
    engine = create_engine(
        "sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool
    )
    for table in Base.metadata.tables.values():
        for column in table.columns:
            if isinstance(column.type, (SqlArray, JSONB)):
                column.type = SqliteJSON()
    Base.metadata.create_all(
        engine,
        tables=[
            Organization.__table__,
            User.__table__,
            OrganizationBiaBaseline.__table__,
            AuditEvent.__table__,
        ],
    )
    session = sessionmaker(bind=engine)()
    session.add(Organization(id=1, name="Org", slug="org"))
    session.add_all(
        [
            User(id=7, organization_id=1, email="admin@org.com", role="org_admin"),
            User(id=8, organization_id=1, email="member@org.com", role="member"),
        ]
    )
    session.commit()
    yield session
    session.close()


def _admin_context() -> TenantContext:
    return TenantContext(
        user_id=7,
        organization_id=1,
        email="admin@org.com",
        roles=["org_admin"],
        permissions=[],
    )


def _member_context() -> TenantContext:
    return TenantContext(
        user_id=8,
        organization_id=1,
        email="member@org.com",
        roles=["member"],
        permissions=[],
    )


def _payload() -> organization_bia.OrganizationBiaBaselineWriteRequest:
    return organization_bia.OrganizationBiaBaselineWriteRequest(
        answers=organization_bia.OrganizationBiaAnswers(**_ANSWERS)
    )


def test_admin_sets_organisation_bia_baseline_with_audit_record(db: Session):
    response = organization_bia.set_organization_bia(_payload(), ctx=_admin_context(), db=db)

    assert response.baseline is not None
    assert response.baseline.answers.mtd == _ANSWERS["mtd"]
    assert response.baseline.set_by_user_id == 7
    audit = db.query(AuditEvent).one()
    assert audit.event_type == ORGANIZATION_BIA_AUDIT_SET
    assert audit.metadata_json["baseline_id"] == response.baseline.baseline_id


def test_new_organisation_bia_baseline_supersedes_previous_version(db: Session):
    first = organization_bia.set_organization_bia(_payload(), ctx=_admin_context(), db=db).baseline
    assert first is not None

    updated_answers = {**_ANSWERS, "mtd": "le_1h"}
    second = organization_bia.set_organization_bia(
        organization_bia.OrganizationBiaBaselineWriteRequest(
            answers=organization_bia.OrganizationBiaAnswers(**updated_answers)
        ),
        ctx=_admin_context(),
        db=db,
    ).baseline

    assert second is not None
    records = db.query(OrganizationBiaBaseline).all()
    predecessor = next(record for record in records if record.id == first.baseline_id)
    assert predecessor.status == ORGANIZATION_BIA_BASELINE_SUPERSEDED
    assert predecessor.superseded_by_id == second.baseline_id
    assert organization_bia.get_organization_bia(ctx=_admin_context(), db=db).baseline == second


def test_member_cannot_set_organisation_bia_baseline(db: Session):
    with pytest.raises(AuthorizationError, match="Organisation administrator access is required"):
        organization_bia.set_organization_bia(_payload(), ctx=_member_context(), db=db)

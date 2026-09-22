"""A1 security remediation (H2): TenantRepository must fail closed when
constructed against a model with no organization_id column, instead of the
old silent no-op in _apply_tenant_filter that made the learning.py/
template_governance.py cross-tenant leaks possible."""

import pytest

from src.core.models import Base
from src.core.repository import GlobalRepository, TenantRepository
from sqlalchemy import Column, Integer, String


class _NoOrgModel(Base):
    __tablename__ = "test_tenant_repository_no_org_model"

    id = Column(Integer, primary_key=True)
    name = Column(String, nullable=True)


class _OrgScopedModel(Base):
    __tablename__ = "test_tenant_repository_org_scoped_model"

    id = Column(Integer, primary_key=True)
    organization_id = Column(Integer, nullable=False)


def test_tenant_repository_rejects_model_without_organization_id():
    with pytest.raises(TypeError, match="organization_id"):
        TenantRepository(session=None, model_class=_NoOrgModel, organization_id=1)


def test_tenant_repository_accepts_org_scoped_model():
    repo = TenantRepository(session=None, model_class=_OrgScopedModel, organization_id=1)
    assert repo.organization_id == 1


def test_global_repository_accepts_model_without_organization_id():
    repo = GlobalRepository(session=None, model_class=_NoOrgModel)
    assert repo.model_class is _NoOrgModel

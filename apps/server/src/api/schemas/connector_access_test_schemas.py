"""How an access test is described — including the remedy, never just the code.

The story's fourth criterion is that a failure says something an operator can act
on. A response carrying only ``failure_code`` would push the job of turning
``permission_insufficient`` into advice onto whatever renders it, and each
surface would word it differently. So the remedy travels with the result, from
the single lookup in ``connector_access_test_service.remedy_for``.

``reachable`` and ``permissions_adequate`` stay two nullable fields here, exactly
as they are in the table. Flattening them into one status on the way out would
undo the distinction the table exists to keep.
"""

from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel

from src.core.model_defs.connector_access_test import ConnectorAccessTest
from src.core.services.connector_access_test_service import remedy_for
from src.api.schemas.timestamps import UtcTimestamp


class ConnectorAccessTestResponse(BaseModel):
    id: str
    connector_id: str
    permission_profile_id: str | None = None
    status: str
    requested_at: UtcTimestamp
    requested_by_user_id: int | None = None
    completed_at: UtcTimestamp | None = None
    reachable: bool | None = None
    permissions_adequate: bool | None = None
    capabilities_confirmed: list[str] = []
    failure_code: str | None = None
    #: What to go and do about ``failure_code``. Derived, never stored twice.
    remedy: str | None = None
    failure_detail: str | None = None


class ConnectorAccessTestListResponse(BaseModel):
    tests: list[ConnectorAccessTestResponse]


def _iso(value: datetime | None) -> str | None:
    return value.isoformat() if value else None


def to_access_test_response(test: ConnectorAccessTest) -> ConnectorAccessTestResponse:
    return ConnectorAccessTestResponse(
        id=test.id,
        connector_id=test.connector_id,
        permission_profile_id=test.permission_profile_id,
        status=test.status,
        requested_at=_iso(test.requested_at) or "",
        requested_by_user_id=test.requested_by_user_id,
        completed_at=_iso(test.completed_at),
        reachable=test.reachable,
        permissions_adequate=test.permissions_adequate,
        capabilities_confirmed=list(test.capabilities_confirmed or []),
        failure_code=test.failure_code,
        remedy=remedy_for(test.failure_code),
        failure_detail=test.failure_detail,
    )


__all__ = [
    "ConnectorAccessTestListResponse",
    "ConnectorAccessTestResponse",
    "to_access_test_response",
]

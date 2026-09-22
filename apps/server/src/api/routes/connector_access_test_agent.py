"""CA-07.4 — where the Collector reports what an access test found.

Its own surface, authenticated by the Collector's own credential rather than a
tenant session, because the Collector is the party that ran the test. Credentials
are local to it (CA-07.2), so the platform never observes any of this — it
records what it was told, the shape ``record_test_scan_result`` already uses.

**The instance is checked against the Connector, not just against the tenant.**
A Collector may only report on tests for Connectors that are its own. Without
that, one authenticated Collector could file results for another's Connectors
inside the same organisation, and a test result is a statement about whether
access works — a place where a wrong attribution is not a cosmetic error.

The result is free text from a machine that holds a credential, so
``failure_detail`` never enters the audit trail; only the closed failure code
does. See ``connector_access_test_service._metadata``.
"""

from __future__ import annotations

import structlog
from fastapi import APIRouter, Depends, Request
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from src.api.routes.scanner_agent import require_scanner_instance
from src.api.schemas.connector_access_test_schemas import (
    ConnectorAccessTestResponse,
    to_access_test_response,
)
from src.core.constants.connector_access_test_enums import (
    TEST_ERROR_NOT_FOUND,
    ConnectorAccessTestFailure,
)
from src.core.database import get_db
from src.core.exceptions import ResourceNotFoundError, ValidationError
from src.core.model_defs.access_connector import AccessConnector
from src.core.model_defs.connector_access_test import ConnectorAccessTest
from src.core.services.connector_access_test_service import (
    ConnectorAccessTestValidationError,
    record_access_test_result,
)

logger = structlog.get_logger(__name__)

#: A Collector's own note about the failure. Bounded because it is unvalidated
#: text from a remote process, and unbounded remote text in a database is how a
#: log line becomes a storage problem.
FAILURE_DETAIL_MAX_LENGTH = 2000

router = APIRouter(prefix="/api/v1/scanner-agent", tags=["Scanner agent"])


class AccessTestResultRequest(BaseModel):
    """What the Collector observed. Two answers, never one verdict.

    ``failure_code`` is constrained to the closed vocabulary by its type, so a
    Collector cannot invent a code that no remedy exists for — which is what
    "a failure names something a person can act on" comes down to in practice.
    """

    reachable: bool
    permissions_adequate: bool
    capabilities_confirmed: list[str] = Field(default_factory=list)
    failure_code: ConnectorAccessTestFailure | None = None
    failure_detail: str | None = Field(default=None, max_length=FAILURE_DETAIL_MAX_LENGTH)


@router.post("/access-tests/{test_id}/result", response_model=ConnectorAccessTestResponse)
def report_access_test_result(
    test_id: str,
    body: AccessTestResultRequest,
    request: Request,
    db: Session = Depends(get_db),
) -> ConnectorAccessTestResponse:
    instance = require_scanner_instance(request, db)
    test = (
        db.query(ConnectorAccessTest)
        .join(AccessConnector, AccessConnector.id == ConnectorAccessTest.connector_id)
        .filter(
            ConnectorAccessTest.id == test_id,
            ConnectorAccessTest.organization_id == instance.organization_id,
            AccessConnector.scanner_instance_id == instance.id,
        )
        .one_or_none()
    )
    if test is None:
        # Deliberately the same answer whether the test does not exist or belongs
        # to another Collector: an authenticated Collector should not be able to
        # map out the Connectors it was not given.
        raise ResourceNotFoundError(TEST_ERROR_NOT_FOUND)

    try:
        record_access_test_result(
            db,
            test,
            reachable=body.reachable,
            permissions_adequate=body.permissions_adequate,
            capabilities_confirmed=body.capabilities_confirmed,
            failure_code=body.failure_code.value if body.failure_code else None,
            failure_detail=body.failure_detail,
        )
    except ConnectorAccessTestValidationError as exc:
        raise ValidationError(str(exc)) from exc
    db.commit()
    db.refresh(test)
    return to_access_test_response(test)


__all__ = ["router"]

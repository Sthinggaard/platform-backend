"""CA-07.4 — asking whether access works, and reading what it said last time.

**Requesting a test is not requesting verification.** This surface asks the
Collector to prove the pipe is open and the approved permissions are sufficient.
It reads nothing about the estate and reaches no conclusion about risk — CA-08
does that, behind its own human approval. The story's boundary is that reaching a
working Connector never begins anything.

The history endpoint is not a convenience. *"When did this stop working, and what
did it say at the time?"* is the question a Connector's owner actually asks, and
a surface that showed only the latest result could not answer it.

The Collector reports outcomes on its own authenticated surface — see
``connector_access_test_agent.py``. Nothing here accepts a result, because a
tenant user is not the party that ran the test.
"""

from __future__ import annotations

import structlog
from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from src.api.middleware.tenant_context import TenantContext, get_tenant_context
from src.api.routes.access_connectors import require_connector, require_org_admin
from src.api.schemas.connector_access_test_schemas import (
    ConnectorAccessTestListResponse,
    ConnectorAccessTestResponse,
    to_access_test_response,
)
from src.core.database import get_db
from src.core.exceptions import ValidationError
from src.core.services.connector_access_test_service import (
    ConnectorAccessTestValidationError,
    expire_stale_access_tests,
    list_access_tests,
    request_access_test,
)

logger = structlog.get_logger(__name__)

router = APIRouter(prefix="/api/v1/access-connectors", tags=["Access connectors"])


@router.post("/{connector_id}/access-tests", response_model=ConnectorAccessTestResponse)
def request_test(
    connector_id: str,
    ctx: TenantContext = Depends(get_tenant_context),
    db: Session = Depends(get_db),
) -> ConnectorAccessTestResponse:
    """Ask the Collector to prove this Connector works.

    Returns a test in ``requested`` when the Collector has been asked, and one
    already in ``failed`` when the answer needed no Collector — a withdrawn
    Connector, or no approved permission profile to measure adequacy against.
    Both are real results and both belong in the same history, so neither is
    returned as an error.
    """
    require_org_admin(db, ctx)
    connector = require_connector(db, ctx=ctx, connector_id=connector_id)
    try:
        test = request_access_test(db, connector, requested_by_user_id=ctx.user_id)
    except ConnectorAccessTestValidationError as exc:
        raise ValidationError(str(exc)) from exc
    db.commit()
    db.refresh(test)
    return to_access_test_response(test)


@router.get("/{connector_id}/access-tests", response_model=ConnectorAccessTestListResponse)
def list_tests(
    connector_id: str,
    ctx: TenantContext = Depends(get_tenant_context),
    db: Session = Depends(get_db),
) -> ConnectorAccessTestListResponse:
    """This Connector's test history, newest first.

    Stale requests are closed out first, so a Collector that went quiet shows as
    ``expired`` rather than sitting in ``requested`` forever, which reads as work
    in progress and is actually silence.
    """
    connector = require_connector(db, ctx=ctx, connector_id=connector_id)
    expired = expire_stale_access_tests(db, organization_id=ctx.organization_id)
    if expired:
        db.commit()
    return ConnectorAccessTestListResponse(
        tests=[
            to_access_test_response(test)
            for test in list_access_tests(
                db, organization_id=ctx.organization_id, connector_id=connector.id
            )
        ]
    )


__all__ = ["router"]

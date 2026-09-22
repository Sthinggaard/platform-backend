"""CA-04.1 — shared helper for building a wire-shaped, genuinely
signature-valid discovery command for tests, so the CLI's real
verify-then-execute path is actually exercised rather than mocked away.

The signable payload is built by the agent's own ``_signable_payload`` rather
than restated here. A hand-rolled copy was a third definition of the wire
contract, and when CA-04.7 added the process/service fields it silently went
stale — every one of these tests kept passing against a payload the server had
already stopped sending (BUG-DISC-07). Cross-implementation drift is caught by
``apps/server/tests/test_command_signing_contract.py``, which compares the
server and agent builders directly.
"""

from __future__ import annotations

import hashlib
import hmac
import json
from datetime import datetime, timedelta, timezone

from scanner_agent.command_signing import _signable_payload, derive_command_signing_key

DEFAULT_ACTIVATION_TOKEN = "tok_secret"
DEFAULT_SCANNER_INSTANCE_ID = "instance-1"


def build_signed_command(
    *,
    command_id: str = "cmd-1",
    discovery_run_id: str = "run-1",
    organisation_id: int = 1,
    scanner_instance_id: str = DEFAULT_SCANNER_INSTANCE_ID,
    provider_execution_id: str | None = None,
    business_process_id: str | None = None,
    business_service_id: str | None = None,
    check_key: str | None = None,
    issued_at: datetime | None = None,
    expires_at: datetime | None = None,
    activation_token: str = DEFAULT_ACTIVATION_TOKEN,
    profile: dict | None = None,
    targets: list[dict] | None = None,
    execution_policy: dict | None = None,
    tamper_signature: bool = False,
) -> dict:
    now = datetime.now(timezone.utc)
    issued = issued_at or now
    expires = expires_at or (now + timedelta(minutes=15))

    envelope = {
        "command_id": command_id,
        "command_type": "run_discovery",
        "organisation_id": organisation_id,
        "scanner_instance_id": scanner_instance_id,
        "discovery_run_id": discovery_run_id,
        "provider_execution_id": provider_execution_id,
        "business_process_id": business_process_id,
        "business_service_id": business_service_id,
        "issued_at": issued.isoformat(),
        "expires_at": expires.isoformat(),
    }
    payload = _signable_payload(envelope)
    signing_key = derive_command_signing_key(activation_token, scanner_instance_id)
    signature = hmac.new(signing_key, payload.encode("utf-8"), hashlib.sha256).hexdigest()
    if tamper_signature:
        signature = "0" * len(signature)

    return {
        "command_id": command_id,
        "command_type": "run_discovery",
        "organisation_id": organisation_id,
        "scanner_instance_id": scanner_instance_id,
        "discovery_run_id": discovery_run_id,
        "provider_execution_id": provider_execution_id,
        "business_process_id": business_process_id,
        "business_service_id": business_service_id,
        "check_key": check_key,
        "issued_at": issued.isoformat(),
        "expires_at": expires.isoformat(),
        "profile": profile if profile is not None else {"profileType": "safe_discovery"},
        "targets": targets if targets is not None else [],
        # The real envelope carries this (discovery_command_agent.py's
        # CommandEnvelopeResponse) and the Collector now reads its
        # maximumDurationSeconds instead of hardcoding a per-target timeout. A
        # fixture missing a field the server always sends is how a defect stays
        # invisible to a green suite — AGENTS.md §11.5.
        "execution_policy": execution_policy
        if execution_policy is not None
        else {"maximumDurationSeconds": 15 * 60, "stopAtWindowEnd": True, "allowPartialUpload": True},
        "signature": signature,
    }

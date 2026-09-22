"""BUG-DISC-07 — the server and the Collector must sign the same payload.

Both sides build the signable payload independently: the server from a
``ScannerCommand`` row, the agent from the JSON envelope it receives. Nothing
tied the two together, so CA-04.7 added ``businessProcessId``/
``businessServiceId`` to the server's payload, left ``apps/scanner`` untouched,
and every command a CA-04.7-or-later server issued failed verification with
``command_signature_invalid``. Discovery could not execute at all.

Both sides had passing tests throughout — each against its own idea of the
payload. This test is deliberately the one that fails if either side adds,
removes or renames a field without the other.
"""

from __future__ import annotations

import importlib.util
import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from src.core.model_defs.discovery_run import ScannerCommand
from src.core.services.discovery_command_service import _signable_payload as server_payload

# Imported by path rather than as a package: apps/scanner is a separate
# distribution with its own pyproject, not a dependency of the server.
_AGENT_MODULE = (
    Path(__file__).resolve().parents[2] / "scanner" / "scanner_agent" / "command_signing.py"
)


def _load_agent_module():
    if not _AGENT_MODULE.exists():  # pragma: no cover - layout guard
        pytest.skip(f"Collector source not present at {_AGENT_MODULE}")
    spec = importlib.util.spec_from_file_location("agent_command_signing", _AGENT_MODULE)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


ISSUED_AT = datetime(2026, 8, 12, 10, 0, 0, tzinfo=timezone.utc)
EXPIRES_AT = ISSUED_AT + timedelta(minutes=15)


def _command(**overrides) -> ScannerCommand:
    defaults = dict(
        id="cmd-1",
        organization_id=1,
        scanner_instance_id="inst-1",
        discovery_run_id="run-1",
        command_type="run_discovery",
        provider_execution_id=None,
        business_process_id=None,
        business_service_id=None,
        issued_at=ISSUED_AT,
        expires_at=EXPIRES_AT,
    )
    defaults.update(overrides)
    return ScannerCommand(**defaults)


def _envelope(command: ScannerCommand) -> dict:
    """The JSON envelope the agent receives, matching the API's field names."""
    return {
        "command_id": command.id,
        "command_type": command.command_type,
        "organisation_id": command.organization_id,
        "scanner_instance_id": command.scanner_instance_id,
        "discovery_run_id": command.discovery_run_id,
        "provider_execution_id": command.provider_execution_id,
        "business_process_id": command.business_process_id,
        "business_service_id": command.business_service_id,
        "issued_at": command.issued_at.isoformat(),
        "expires_at": command.expires_at.isoformat(),
    }


@pytest.mark.parametrize(
    "overrides",
    [
        pytest.param({}, id="org-wide run"),
        pytest.param({"business_process_id": "proc-1"}, id="process-scoped run (CA-04.7)"),
        pytest.param(
            {"business_process_id": "proc-1", "business_service_id": "svc-1"},
            id="process and service scoped",
        ),
        pytest.param({"provider_execution_id": "exec-1"}, id="delegated per-job command"),
    ],
)
def test_server_and_agent_sign_identical_payloads(overrides) -> None:
    agent = _load_agent_module()
    command = _command(**overrides)

    assert server_payload(command) == agent._signable_payload(_envelope(command))


def test_both_sides_sign_every_field_the_other_does() -> None:
    """Field-level assertion so a failure names the offending key rather than
    printing two long JSON strings."""
    agent = _load_agent_module()
    command = _command(business_process_id="proc-1", business_service_id="svc-1")

    server_keys = set(json.loads(server_payload(command)))
    agent_keys = set(json.loads(agent._signable_payload(_envelope(command))))

    assert server_keys == agent_keys, (
        f"only the server signs: {sorted(server_keys - agent_keys)}; "
        f"only the Collector signs: {sorted(agent_keys - server_keys)}"
    )

import json

import pytest
import responses
from click.testing import CliRunner

from conftest import DEFAULT_ACTIVATION_TOKEN, DEFAULT_SCANNER_INSTANCE_ID, build_signed_command
from scanner_agent import cli as cli_module
from scanner_agent.cli import cli
from scanner_agent.config import ScannerCredentials
from scanner_agent.nmap_runner import NmapScanResult
from scanner_agent.nuclei_runner import NucleiScanResult

NMAP_XML_SAMPLE = (
    '<?xml version="1.0"?><nmaprun><host><address addr="10.0.0.5" addrtype="ipv4"/>'
    '<ports><port protocol="tcp" portid="443"><state state="open"/>'
    '<service name="https"/></port></ports></host></nmaprun>'
)


def _stub_credentials(monkeypatch, *, scanner_instance_id: str | None = DEFAULT_SCANNER_INSTANCE_ID):
    monkeypatch.setattr(
        cli_module,
        "load_credentials",
        lambda: ScannerCredentials(
            base_url="https://api.example.com",
            activation_token=DEFAULT_ACTIVATION_TOKEN,
            scanner_instance_id=scanner_instance_id,
        ),
    )


@responses.activate
def test_poll_reports_no_pending_work(monkeypatch):
    """CA-08.2 renamed this from "no pending discovery command".

    The poll now returns two kinds of work, so a message naming only discovery
    would be wrong half the time — an operator seeing "no pending discovery
    command" while an inspection sat in the queue would reasonably conclude the
    queue was empty.
    """
    _stub_credentials(monkeypatch)
    responses.add(
        responses.GET,
        "https://api.example.com/api/v1/scanner-agent/commands/next",
        json={"has_command": False, "command": None},
        status=200,
    )

    result = CliRunner().invoke(cli, ["poll"])

    assert result.exit_code == 0
    assert "No pending work." in result.output


@responses.activate
def test_poll_verifies_executes_and_reports_a_real_result(monkeypatch):
    """CA-04.1 — a genuinely signed command is executed for real (no
    targets here, so nmap runs zero scans) and a real result is reported
    through the whole-run status route, not the old unconditional
    acknowledge-and-stop placeholder."""
    _stub_credentials(monkeypatch)
    command = build_signed_command(command_id="cmd-1", discovery_run_id="run-1", targets=[])
    responses.add(
        responses.GET,
        "https://api.example.com/api/v1/scanner-agent/commands/next",
        json={"has_command": True, "command": command},
        status=200,
    )
    responses.add(
        responses.POST,
        "https://api.example.com/api/v1/scanner-agent/commands/cmd-1/acknowledge",
        json={"command_id": "cmd-1", "discovery_run_id": "run-1", "status": "acknowledged", "accepted": True},
        status=200,
    )
    responses.add(
        responses.POST,
        "https://api.example.com/api/v1/scanner-agent/discovery-runs/run-1/status",
        json={"discovery_run_id": "run-1", "status": "running", "current_stage": "external_discovery"},
        status=200,
    )
    responses.add(
        responses.POST,
        "https://api.example.com/api/v1/scanner-agent/discovery-runs/run-1/status",
        json={"discovery_run_id": "run-1", "status": "completed", "current_stage": "complete"},
        status=200,
    )

    result = CliRunner().invoke(cli, ["poll"])

    assert result.exit_code == 0
    assert "cmd-1" in result.output
    assert "Acknowledged" in result.output
    assert "Reported real result" in result.output
    acknowledge_call = next(c for c in responses.calls if c.request.url.endswith("/commands/cmd-1/acknowledge"))
    assert '"accepted": true' in acknowledge_call.request.body.decode()


@responses.activate
def test_poll_rejects_a_tampered_command_instead_of_executing_it(monkeypatch):
    _stub_credentials(monkeypatch)
    command = build_signed_command(command_id="cmd-2", discovery_run_id="run-2", tamper_signature=True)
    responses.add(
        responses.GET,
        "https://api.example.com/api/v1/scanner-agent/commands/next",
        json={"has_command": True, "command": command},
        status=200,
    )
    responses.add(
        responses.POST,
        "https://api.example.com/api/v1/scanner-agent/commands/cmd-2/acknowledge",
        json={"command_id": "cmd-2", "discovery_run_id": "run-2", "status": "rejected", "accepted": False},
        status=200,
    )

    result = CliRunner().invoke(cli, ["poll"])

    assert result.exit_code == 0
    assert "Rejecting command (command_signature_invalid)" in result.output
    acknowledge_call = responses.calls[-1]
    assert acknowledge_call.request.url.endswith("/commands/cmd-2/acknowledge")
    body = acknowledge_call.request.body.decode()
    assert '"accepted": false' in body
    assert "command_signature_invalid" in body
    # A rejected command must never be executed or reported as a result.
    assert not any(call.request.url.endswith("/discovery-runs/run-2/status") for call in responses.calls)


@responses.activate
def test_poll_executes_subfinder_for_a_delegated_command_and_reports_via_result_route(monkeypatch):
    """CA-04.3 — a delegated command (provider_execution_id set) with
    check_key=subfinder must report through the per-job result route
    (discovery_execution_agent.py), never the whole-run status route."""
    _stub_credentials(monkeypatch)
    command = build_signed_command(
        command_id="cmd-3",
        discovery_run_id="run-3",
        provider_execution_id="pe-1",
        check_key="subfinder",
        targets=[],
    )
    responses.add(
        responses.GET,
        "https://api.example.com/api/v1/scanner-agent/commands/next",
        json={"has_command": True, "command": command},
        status=200,
    )
    responses.add(
        responses.POST,
        "https://api.example.com/api/v1/scanner-agent/commands/cmd-3/acknowledge",
        json={"command_id": "cmd-3", "discovery_run_id": "run-3", "status": "acknowledged", "accepted": True},
        status=200,
    )
    responses.add(
        responses.POST,
        "https://api.example.com/api/v1/scanner-agent/commands/cmd-3/result",
        json={"provider_execution_id": "pe-1", "status": "completed"},
        status=200,
    )

    result = CliRunner().invoke(cli, ["poll"])

    assert result.exit_code == 0
    assert "Reported real result — job status: completed." in result.output
    result_call = next(c for c in responses.calls if c.request.url.endswith("/commands/cmd-3/result"))
    body = result_call.request.body.decode()
    assert '"evidence_format": "text"' in body
    # No whole-run status call must ever be made for a delegated command.
    assert not any(call.request.url.endswith("/status") for call in responses.calls)


@responses.activate
def test_poll_executes_nmap_for_a_delegated_command_and_attaches_xml_evidence(monkeypatch):
    """CA-04.3 + BUG-DISC-08 — a delegated nmap command completes through the
    per-job result route and now attaches its NMAP_XML evidence.

    It previously reported completion with no evidence at all, so the scan ran,
    the stage went green, and every finding was thrown away — no evidence
    package meant nothing to normalise and no asset was ever created."""
    _stub_credentials(monkeypatch)
    command = build_signed_command(
        command_id="cmd-5",
        discovery_run_id="run-5",
        provider_execution_id="pe-3",
        check_key="nmap",
        targets=[{"approvedValue": "10.0.0.5"}],
    )
    monkeypatch.setattr(
        cli_module,
        "run_discovery_scan",
        lambda targets, **kwargs: [
            NmapScanResult(target="10.0.0.5", open_ports=[443], raw_output=NMAP_XML_SAMPLE)
        ],
    )
    responses.add(
        responses.GET,
        "https://api.example.com/api/v1/scanner-agent/commands/next",
        json={"has_command": True, "command": command},
        status=200,
    )
    responses.add(
        responses.POST,
        "https://api.example.com/api/v1/scanner-agent/commands/cmd-5/acknowledge",
        json={"command_id": "cmd-5", "discovery_run_id": "run-5", "status": "acknowledged", "accepted": True},
        status=200,
    )
    responses.add(
        responses.POST,
        "https://api.example.com/api/v1/scanner-agent/commands/cmd-5/result",
        json={"provider_execution_id": "pe-3", "status": "completed"},
        status=200,
    )

    result = CliRunner().invoke(cli, ["poll"])

    assert result.exit_code == 0
    assert "Reported real result — job status: completed." in result.output
    result_call = next(c for c in responses.calls if c.request.url.endswith("/commands/cmd-5/result"))
    body = json.loads(result_call.request.body.decode())
    # nmap_xml is the format the server's evidence adapter has a parser for;
    # anything else is stored and then never normalised.
    assert body["evidence_format"] == "nmap_xml"
    assert body["raw_evidence_payload"] == NMAP_XML_SAMPLE
    assert not any(call.request.url.endswith("/status") for call in responses.calls)


@responses.activate
def test_poll_executes_nuclei_for_a_delegated_command_and_attaches_its_findings(monkeypatch):
    """CA-04.4 — a delegated nuclei command with nothing in scope says so.

    ⚠️ **Amended 2026-09-06, and it had encoded the defect.** This test asserted
    `'"evidence_format"' not in body` — it required that a scan which found real
    vulnerabilities discarded them, and passed for as long as that was true. The
    platform held 69 evidence packages and zero findings, and the suite was
    green throughout.

    The "never an arbitrary template fetch" criterion is still proven at the
    runner level in test_nuclei_runner.py, not re-proven here."""
    _stub_credentials(monkeypatch)
    command = build_signed_command(
        command_id="cmd-6",
        discovery_run_id="run-6",
        provider_execution_id="pe-4",
        check_key="nuclei",
        targets=[],
    )
    responses.add(
        responses.GET,
        "https://api.example.com/api/v1/scanner-agent/commands/next",
        json={"has_command": True, "command": command},
        status=200,
    )
    responses.add(
        responses.POST,
        "https://api.example.com/api/v1/scanner-agent/commands/cmd-6/acknowledge",
        json={"command_id": "cmd-6", "discovery_run_id": "run-6", "status": "acknowledged", "accepted": True},
        status=200,
    )
    responses.add(
        responses.POST,
        "https://api.example.com/api/v1/scanner-agent/commands/cmd-6/result",
        json={"provider_execution_id": "pe-4", "status": "completed"},
        status=200,
    )

    result = CliRunner().invoke(cli, ["poll"])

    assert result.exit_code == 0
    # ⚠️ **Amended again 2026-09-07, and it had encoded a second defect.** This
    # asserted that a nuclei command with *no targets* reported `completed`
    # with an empty payload — "an empty payload is a real result, not a missing
    # one". It is not. Nothing was scanned, and the platform's resolution rule
    # is that a later scan finding nothing is what proves a finding resolved,
    # so a scan that never happened must never arrive looking like one that
    # came back clean. The command is now reported as failed, naming why.
    result_call = next(c for c in responses.calls if c.request.url.endswith("/commands/cmd-6/result"))
    body = json.loads(result_call.request.body.decode())
    assert body["status"] == "failed"
    assert body["failure_code"] == "no_targets_in_scope"
    assert "raw_evidence_payload" not in body
    assert not any(call.request.url.endswith("/status") for call in responses.calls)


@responses.activate
def test_a_real_nuclei_finding_reaches_the_server(monkeypatch):
    """The whole point: a vulnerability the scan found arrives on the platform.

    Before 2026-09-06 this journey ended here — nuclei ran, matched, and the
    Collector reported "completed" while dropping every line it produced.
    """
    _stub_credentials(monkeypatch)
    log4j = (
        '{"template-id":"CVE-2021-44228","type":"http","host":"https://billing.example.com",'
        '"matched-at":"https://billing.example.com/api","ip":"10.0.0.4",'
        '"info":{"name":"Apache Log4j2 Remote Code Execution","severity":"critical"}}'
    )
    command = build_signed_command(
        command_id="cmd-9",
        discovery_run_id="run-9",
        provider_execution_id="pe-9",
        check_key="nuclei",
        targets=[{"approvedValue": "billing.example.com"}],
    )
    monkeypatch.setattr(
        cli_module,
        "run_nuclei_discovery",
        lambda targets, **kwargs: [
            NucleiScanResult(target="billing.example.com", raw_output=log4j)
        ],
    )
    for path, payload in (
        ("commands/next", {"has_command": True, "command": command}),
    ):
        responses.add(responses.GET, f"https://api.example.com/api/v1/scanner-agent/{path}", json=payload, status=200)
    responses.add(
        responses.POST,
        "https://api.example.com/api/v1/scanner-agent/commands/cmd-9/acknowledge",
        json={"command_id": "cmd-9", "discovery_run_id": "run-9", "status": "acknowledged", "accepted": True},
        status=200,
    )
    responses.add(
        responses.POST,
        "https://api.example.com/api/v1/scanner-agent/commands/cmd-9/result",
        json={"provider_execution_id": "pe-9", "status": "completed"},
        status=200,
    )

    result = CliRunner().invoke(cli, ["poll"])

    assert result.exit_code == 0
    assert "1 finding(s)." in result.output
    body = json.loads(
        next(c for c in responses.calls if c.request.url.endswith("/commands/cmd-9/result")).request.body.decode()
    )
    assert body["evidence_format"] == "json"
    assert "CVE-2021-44228" in body["raw_evidence_payload"]


@responses.activate
def test_poll_rejects_a_delegated_command_with_an_unrecognised_check_key(monkeypatch):
    _stub_credentials(monkeypatch)
    command = build_signed_command(
        command_id="cmd-4",
        discovery_run_id="run-4",
        provider_execution_id="pe-2",
        check_key="nikto",  # not registered — CA-04.4 registered nuclei, not this
        targets=[],
    )
    responses.add(
        responses.GET,
        "https://api.example.com/api/v1/scanner-agent/commands/next",
        json={"has_command": True, "command": command},
        status=200,
    )
    responses.add(
        responses.POST,
        "https://api.example.com/api/v1/scanner-agent/commands/cmd-4/acknowledge",
        json={"command_id": "cmd-4", "discovery_run_id": "run-4", "status": "acknowledged", "accepted": True},
        status=200,
    )
    responses.add(
        responses.POST,
        "https://api.example.com/api/v1/scanner-agent/commands/cmd-4/result",
        json={"provider_execution_id": "pe-2", "status": "failed"},
        status=200,
    )

    result = CliRunner().invoke(cli, ["poll"])

    assert result.exit_code == 0
    assert "Unrecognised check key" in result.output
    result_call = next(c for c in responses.calls if c.request.url.endswith("/commands/cmd-4/result"))
    body = result_call.request.body.decode()
    assert '"failure_code": "check_key_unknown"' in body


def test_poll_requires_credentials(monkeypatch):
    def _raise_not_found():
        raise FileNotFoundError("No scanner credentials found. Run `risklence-scanner activate` first.")

    monkeypatch.setattr(cli_module, "load_credentials", _raise_not_found)

    result = CliRunner().invoke(cli, ["poll"])

    assert result.exit_code != 0
    assert "activate" in result.output


@responses.activate
def test_a_truncated_nuclei_scan_is_reported_partial_and_keeps_its_findings(monkeypatch):
    """🐞 The ten-day defect, at the layer that reported it.

    Every nuclei run since 2026-08-27 was killed at the time budget — the
    approved scope was a /24, which cannot finish in it — and each was reported
    as `completed` with an empty payload. The platform recorded a clean scan
    that had never happened.
    """
    _stub_credentials(monkeypatch)
    partial = '{"template-id":"CVE-2021-44228","host":"https://192.168.50.152","info":{"severity":"critical"}}'
    command = build_signed_command(
        command_id="cmd-11",
        discovery_run_id="run-11",
        provider_execution_id="pe-11",
        check_key="nuclei",
        targets=[{"approvedValue": "192.168.50.152"}, {"approvedValue": "192.168.50.176"}],
    )
    monkeypatch.setattr(
        cli_module,
        "run_nuclei_discovery",
        lambda targets, **kwargs: [
            NucleiScanResult(target="192.168.50.152", raw_output=partial, completed=True),
            NucleiScanResult(target="192.168.50.176", raw_output="", completed=False),
        ],
    )
    responses.add(
        responses.GET,
        "https://api.example.com/api/v1/scanner-agent/commands/next",
        json={"has_command": True, "command": command},
        status=200,
    )
    responses.add(
        responses.POST,
        "https://api.example.com/api/v1/scanner-agent/commands/cmd-11/acknowledge",
        json={"command_id": "cmd-11", "discovery_run_id": "run-11", "status": "acknowledged", "accepted": True},
        status=200,
    )
    responses.add(
        responses.POST,
        "https://api.example.com/api/v1/scanner-agent/commands/cmd-11/result",
        json={"provider_execution_id": "pe-11", "status": "partially_completed"},
        status=200,
    )

    result = CliRunner().invoke(cli, ["poll"])

    assert result.exit_code == 0
    body = json.loads(
        next(c for c in responses.calls if c.request.url.endswith("/commands/cmd-11/result")).request.body.decode()
    )
    assert body["status"] == "partially_completed"
    assert body["failure_code"] == "scan_time_budget_exceeded"
    # Partial evidence is still real evidence — what did complete is attached.
    assert "CVE-2021-44228" in body["raw_evidence_payload"]
    # And the operator watching the console is told which target fell short.
    assert "192.168.50.176" in result.output


@responses.activate
def test_a_fully_scanned_nuclei_command_is_still_reported_completed(monkeypatch):
    """The other side of the same rule: nothing truncated means a clean scan,
    and that must keep reading as one — this is the result the platform is
    entitled to treat as evidence a host is clear."""
    _stub_credentials(monkeypatch)
    command = build_signed_command(
        command_id="cmd-12",
        discovery_run_id="run-12",
        provider_execution_id="pe-12",
        check_key="nuclei",
        targets=[{"approvedValue": "192.168.50.152"}],
    )
    monkeypatch.setattr(
        cli_module,
        "run_nuclei_discovery",
        lambda targets, **kwargs: [NucleiScanResult(target="192.168.50.152", raw_output="", completed=True)],
    )
    responses.add(
        responses.GET,
        "https://api.example.com/api/v1/scanner-agent/commands/next",
        json={"has_command": True, "command": command},
        status=200,
    )
    responses.add(
        responses.POST,
        "https://api.example.com/api/v1/scanner-agent/commands/cmd-12/acknowledge",
        json={"command_id": "cmd-12", "discovery_run_id": "run-12", "status": "acknowledged", "accepted": True},
        status=200,
    )
    responses.add(
        responses.POST,
        "https://api.example.com/api/v1/scanner-agent/commands/cmd-12/result",
        json={"provider_execution_id": "pe-12", "status": "completed"},
        status=200,
    )

    result = CliRunner().invoke(cli, ["poll"])

    assert result.exit_code == 0
    body = json.loads(
        next(c for c in responses.calls if c.request.url.endswith("/commands/cmd-12/result")).request.body.decode()
    )
    assert body["status"] == "completed"
    assert "failure_code" not in body


def test_the_target_timeout_comes_from_the_command_not_a_literal():
    """AGENTS.md §19.2 in the one place the correct value was already on the
    wire: the platform states how long it will wait, and the Collector used to
    ignore it and hardcode 180s per target regardless."""
    command = {"execution_policy": {"maximumDurationSeconds": 900}}

    # 900 less the reporting reserve, split across the command's own targets.
    assert cli_module._target_timeout_seconds(command, 1) == pytest.approx(870.0)
    assert cli_module._target_timeout_seconds(command, 13) == pytest.approx(870.0 / 13)


def test_a_target_is_never_given_a_budget_too_short_to_find_anything():
    """A scan too short to match reports the same clean empty result this whole
    path exists to stop being a lie, so the split is floored rather than
    divided blindly."""
    command = {"execution_policy": {"maximumDurationSeconds": 900}}

    assert cli_module._target_timeout_seconds(command, 200) == pytest.approx(30.0)


@pytest.mark.parametrize(
    "policy",
    [None, {}, {"maximumDurationSeconds": None}, {"maximumDurationSeconds": 0}, {"maximumDurationSeconds": "900"}],
)
def test_a_command_with_no_usable_budget_falls_back_to_the_runner_default(policy):
    assert cli_module._target_timeout_seconds({"execution_policy": policy}, 1) == pytest.approx(180.0)

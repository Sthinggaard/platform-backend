import os
import signal

import responses
from click.testing import CliRunner

from conftest import DEFAULT_ACTIVATION_TOKEN, DEFAULT_SCANNER_INSTANCE_ID, build_signed_command
from scanner_agent import cli as cli_module
from scanner_agent.cli import cli
from scanner_agent.config import ScannerCredentials


def _stub_credentials(monkeypatch):
    monkeypatch.setattr(
        cli_module,
        "load_credentials",
        lambda: ScannerCredentials(
            base_url="https://api.example.com",
            activation_token=DEFAULT_ACTIVATION_TOKEN,
            scanner_instance_id=DEFAULT_SCANNER_INSTANCE_ID,
        ),
    )


def _capture_signal_handlers(monkeypatch):
    """Replaces the real signal.signal registration with one that records the
    handler `run` installs, so the test can trigger a stop deterministically
    instead of relying on real OS signal delivery timing."""
    handlers: dict[int, object] = {}

    def _fake_signal(sig, handler):
        handlers[sig] = handler

    monkeypatch.setattr(cli_module.signal, "signal", _fake_signal)
    return handlers


@responses.activate
def test_run_stops_after_sigterm_received_mid_cycle(monkeypatch):
    _stub_credentials(monkeypatch)
    handlers = _capture_signal_handlers(monkeypatch)

    def _heartbeat_callback(request):
        handlers[signal.SIGTERM](signal.SIGTERM, None)
        return (200, {}, '{"scanner_instance_id": "abc123", "status": "online"}')

    responses.add_callback(
        responses.POST,
        "https://api.example.com/api/v1/scanner-agent/heartbeat",
        callback=_heartbeat_callback,
        content_type="application/json",
    )

    result = CliRunner().invoke(cli, ["run", "--interval", "0"])

    assert result.exit_code == 0
    assert "Heartbeat OK" in result.output
    assert "Stopped." in result.output
    # Stop must be honored before the poll step of the same cycle runs.
    assert len(responses.calls) == 1


@responses.activate
def test_run_retries_after_heartbeat_failure_then_stops(monkeypatch):
    _stub_credentials(monkeypatch)
    handlers = _capture_signal_handlers(monkeypatch)

    call_count = {"n": 0}

    def _heartbeat_callback(request):
        call_count["n"] += 1
        if call_count["n"] == 1:
            return (401, {}, '{"detail": "revoked"}')
        handlers[signal.SIGTERM](signal.SIGTERM, None)
        return (200, {}, '{"scanner_instance_id": "abc123", "status": "online"}')

    responses.add_callback(
        responses.POST,
        "https://api.example.com/api/v1/scanner-agent/heartbeat",
        callback=_heartbeat_callback,
        content_type="application/json",
    )
    responses.add(
        responses.GET,
        "https://api.example.com/api/v1/scanner-agent/commands/next",
        json={"has_command": False, "command": None},
        status=200,
    )

    result = CliRunner().invoke(cli, ["run", "--interval", "0"])

    assert result.exit_code == 0
    assert "Heartbeat failed, will retry next cycle" in result.output
    assert "Stopped." in result.output
    assert call_count["n"] == 2


@responses.activate
def test_run_acknowledges_pending_command_before_sleeping(monkeypatch):
    _stub_credentials(monkeypatch)
    handlers = _capture_signal_handlers(monkeypatch)

    responses.add(
        responses.POST,
        "https://api.example.com/api/v1/scanner-agent/heartbeat",
        json={"scanner_instance_id": "abc123", "status": "online"},
        status=200,
    )
    command = build_signed_command(command_id="cmd-1", discovery_run_id="run-1", targets=[])

    def _poll_callback(request):
        handlers[signal.SIGINT](signal.SIGINT, None)
        return (200, {}, '{"has_command": true, "command": ' + _command_json(command) + "}")

    responses.add_callback(
        responses.GET,
        "https://api.example.com/api/v1/scanner-agent/commands/next",
        callback=_poll_callback,
        content_type="application/json",
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

    result = CliRunner().invoke(cli, ["run", "--interval", "0"])

    assert result.exit_code == 0
    assert "Acknowledged — discovery run status: acknowledged." in result.output
    assert "Reported real result" in result.output
    assert "Stopped." in result.output


@responses.activate
def test_run_survives_a_failure_to_report_a_finished_command(monkeypatch):
    """Søren's Collector died exactly here: it acknowledged a command, ran the
    scan for real, then the result POST timed out — and the agent exited 1 and
    stopped, so three further commands queued up with nothing to execute them.

    Every other network failure in this loop is caught and retried; the
    result-reporting path raised ClickException, which the loop does not catch,
    so a single transient blip took the whole agent down. The remedy for an
    unreported command is that the platform reissues it — losing a cycle is
    recoverable, losing the agent is not.
    """
    _stub_credentials(monkeypatch)
    handlers = _capture_signal_handlers(monkeypatch)

    heartbeats = {"n": 0}

    def _heartbeat_callback(request):
        heartbeats["n"] += 1
        # Stop on the *second* cycle: the loop must have survived the first.
        if heartbeats["n"] == 2:
            handlers[signal.SIGTERM](signal.SIGTERM, None)
        return (200, {}, '{"scanner_instance_id": "abc123", "status": "online"}')

    responses.add_callback(
        responses.POST,
        "https://api.example.com/api/v1/scanner-agent/heartbeat",
        callback=_heartbeat_callback,
        content_type="application/json",
    )
    responses.add(
        responses.POST,
        "https://api.example.com/api/v1/scanner-agent/readiness",
        json={"scanner_instance_id": "abc123", "status": "online"},
    )

    command = build_signed_command(command_id="cmd-1", discovery_run_id="run-1", targets=[])
    polls = {"n": 0}

    def _poll_callback(request):
        polls["n"] += 1
        if polls["n"] == 1:
            return (200, {}, '{"has_command": true, "command": ' + _command_json(command) + "}")
        return (200, {}, '{"has_command": false, "command": null}')

    responses.add_callback(
        responses.GET,
        "https://api.example.com/api/v1/scanner-agent/commands/next",
        callback=_poll_callback,
        content_type="application/json",
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
    # The result report fails, exactly as it did on his machine.
    responses.add(
        responses.POST,
        "https://api.example.com/api/v1/scanner-agent/discovery-runs/run-1/status",
        json={"detail": "gateway timeout"},
        status=504,
    )

    result = CliRunner().invoke(cli, ["run", "--interval", "0"])

    assert result.exit_code == 0
    assert "could not be completed, will retry next cycle" in result.output
    # The agent kept running rather than exiting on the failure.
    assert "Stopped." in result.output
    assert heartbeats["n"] == 2


@responses.activate
def test_poll_still_exits_non_zero_when_it_cannot_report(monkeypatch):
    """The one-shot command must keep failing loudly. A script that runs
    `poll` needs a non-zero exit to know the command did not complete — the
    fix above must not quietly turn that into success."""
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
        json={"detail": "gateway timeout"},
        status=504,
    )

    result = CliRunner().invoke(cli, ["poll"])

    assert result.exit_code != 0


def _command_json(command: dict) -> str:
    import json

    return json.dumps(command)


def test_run_requires_credentials(monkeypatch):
    def _raise_not_found():
        raise FileNotFoundError("No scanner credentials found. Run `risklence-scanner activate` first.")

    monkeypatch.setattr(cli_module, "load_credentials", _raise_not_found)

    result = CliRunner().invoke(cli, ["run"])

    assert result.exit_code != 0
    assert "activate" in result.output


@responses.activate
def test_run_loop_reports_a_self_check_without_anyone_asking(monkeypatch):
    """CA-02.3 — the platform now treats this report as the only authoritative
    statement about whether the Collector can work, so an unattended Collector
    that never self-checks can never finish its setup. It used to run only when
    a person typed `validate-tools` by hand."""
    _stub_credentials(monkeypatch)
    handlers = _capture_signal_handlers(monkeypatch)

    responses.add(
        responses.POST,
        "https://api.example.com/api/v1/scanner-agent/heartbeat",
        json={"scanner_instance_id": "abc123", "status": "online"},
    )

    def _self_check_callback(request):
        handlers[signal.SIGTERM](signal.SIGTERM, None)
        return (200, {}, '{"scanner_instance_id": "abc123", "status": "online"}')

    responses.add_callback(
        responses.POST,
        "https://api.example.com/api/v1/scanner-agent/readiness",
        callback=_self_check_callback,
        content_type="application/json",
    )

    result = CliRunner().invoke(cli, ["run", "--interval", "0"])

    assert result.exit_code == 0
    assert "Self-check reported." in result.output
    # Heartbeat first: liveness must not wait on local subprocesses.
    assert responses.calls[0].request.url.endswith("/heartbeat")
    assert responses.calls[1].request.url.endswith("/readiness")


@responses.activate
def test_a_requested_self_check_runs_immediately_and_says_so(monkeypatch):
    """CA-02.3 slice 3 — "Run self-check again".

    The platform cannot push to a polling Collector, so the instruction rides
    back on the heartbeat. A person waiting on a screen takes priority over the
    ~hourly schedule, and the report must carry *why* it ran so the platform can
    attribute it to whoever asked.
    """
    _stub_credentials(monkeypatch)
    handlers = _capture_signal_handlers(monkeypatch)

    responses.add(
        responses.POST,
        "https://api.example.com/api/v1/scanner-agent/heartbeat",
        json={"scanner_instance_id": "abc123", "status": "online", "pending_instruction": "self_check"},
    )

    def _readiness_callback(request):
        handlers[signal.SIGTERM](signal.SIGTERM, None)
        return (200, {}, '{"scanner_instance_id": "abc123", "status": "online"}')

    responses.add_callback(
        responses.POST,
        "https://api.example.com/api/v1/scanner-agent/readiness",
        callback=_readiness_callback,
        content_type="application/json",
    )

    result = CliRunner().invoke(cli, ["run", "--interval", "0"])

    assert result.exit_code == 0
    assert "Self-check reported (requested)." in result.output

    import json as _json

    body = _json.loads(responses.calls[1].request.body)
    assert body["trigger"] == "requested"
    # The agent says what it was asked to do; it must never name a person. The
    # platform resolves that from its own pending instruction, so a Collector
    # cannot attribute a report to an arbitrary user.
    assert "requested_by" not in body and "requestedBy" not in body


@responses.activate
def test_a_heartbeat_without_the_field_does_not_break_an_agent(monkeypatch):
    """Forward/backward compatibility: an older platform sends no
    pending_instruction at all, and the agent must not crash on its absence."""
    _stub_credentials(monkeypatch)
    handlers = _capture_signal_handlers(monkeypatch)

    def _heartbeat_callback(request):
        handlers[signal.SIGTERM](signal.SIGTERM, None)
        return (200, {}, '{"scanner_instance_id": "abc123", "status": "online"}')

    responses.add_callback(
        responses.POST,
        "https://api.example.com/api/v1/scanner-agent/heartbeat",
        callback=_heartbeat_callback,
        content_type="application/json",
    )

    result = CliRunner().invoke(cli, ["run", "--interval", "0"])

    assert result.exit_code == 0
    assert "Stopped." in result.output


@responses.activate
def test_a_periodic_self_check_is_labelled_periodic(monkeypatch):
    _stub_credentials(monkeypatch)
    handlers = _capture_signal_handlers(monkeypatch)

    responses.add(
        responses.POST,
        "https://api.example.com/api/v1/scanner-agent/heartbeat",
        json={"scanner_instance_id": "abc123", "status": "online", "pending_instruction": None},
    )

    def _readiness_callback(request):
        handlers[signal.SIGTERM](signal.SIGTERM, None)
        return (200, {}, '{"scanner_instance_id": "abc123", "status": "online"}')

    responses.add_callback(
        responses.POST,
        "https://api.example.com/api/v1/scanner-agent/readiness",
        callback=_readiness_callback,
        content_type="application/json",
    )

    result = CliRunner().invoke(cli, ["run", "--interval", "0"])

    import json as _json

    body = _json.loads(responses.calls[1].request.body)
    assert body["trigger"] == "periodic"
    assert "Self-check reported." in result.output


def test_a_rotated_credential_is_picked_up_without_reinstalling(monkeypatch, tmp_path):
    """Søren, 2026-08-25: "If the scanner exists then just update the token".

    Rotating invalidates the old credential immediately — the platform answers
    401 — but the loop read its token once at startup, so a running Collector
    kept presenting a dead one until the container was removed and recreated.
    Re-running `activate` wrote the new token to the same file and nothing ever
    looked at it again.
    """
    from click.testing import CliRunner

    from scanner_agent import cli as cli_module
    from scanner_agent.config import ScannerCredentials, save_credentials

    monkeypatch.setattr(cli_module, "DEFAULT_CONFIG_DIR", tmp_path, raising=False)
    save_credentials(
        ScannerCredentials(base_url="https://api.example.com", activation_token="OLD"),
        config_dir=tmp_path,
    )

    seen: list[str] = []

    class _Client:
        def __init__(self, base_url: str, token: str) -> None:
            seen.append(token)

    monkeypatch.setattr(cli_module, "ScannerApiClient", _Client)

    def _load(*_args, **_kwargs):
        # Rotated between the first cycle and the second.
        token = "NEW" if seen else "OLD"
        return ScannerCredentials(base_url="https://api.example.com", activation_token=token)

    monkeypatch.setattr(cli_module, "load_credentials", _load)
    monkeypatch.setattr(cli_module, "_require_credentials", lambda: _load())

    # One heartbeat, then stop — enough to prove the reload happens before the
    # first request rather than after a restart.
    def _heartbeat(_client):
        raise KeyboardInterrupt

    monkeypatch.setattr(cli_module, "_send_heartbeat", _heartbeat)

    CliRunner().invoke(cli_module.cli, ["run", "--interval", "1"])

    assert "NEW" in seen, seen

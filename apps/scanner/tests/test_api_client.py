import pytest
import requests
import responses

from scanner_agent import api_client
from scanner_agent.api_client import ScannerApiClient, ScannerApiError


@responses.activate
def test_heartbeat_sends_bearer_token_and_parses_response():
    responses.add(
        responses.POST,
        "https://api.example.com/api/v1/scanner-agent/heartbeat",
        json={"scanner_instance_id": "abc123", "status": "online"},
        status=200,
    )

    client = ScannerApiClient("https://api.example.com", "tok_secret")
    result = client.heartbeat()

    assert result == {"scanner_instance_id": "abc123", "status": "online"}
    assert responses.calls[0].request.headers["Authorization"] == "Bearer tok_secret"


@responses.activate
def test_heartbeat_includes_os_and_architecture_when_provided():
    responses.add(
        responses.POST,
        "https://api.example.com/api/v1/scanner-agent/heartbeat",
        json={"scanner_instance_id": "abc123", "status": "online"},
        status=200,
    )

    client = ScannerApiClient("https://api.example.com", "tok_secret")
    client.heartbeat(os_name="Ubuntu", os_version="22.04", architecture="x86_64")

    sent_body = responses.calls[0].request.body
    assert b'"os_name": "Ubuntu"' in sent_body or b'"os_name":"Ubuntu"' in sent_body
    assert b'"os_version": "22.04"' in sent_body or b'"os_version":"22.04"' in sent_body
    assert b'"architecture": "x86_64"' in sent_body or b'"architecture":"x86_64"' in sent_body


@responses.activate
def test_heartbeat_omits_os_fields_when_not_provided():
    responses.add(
        responses.POST,
        "https://api.example.com/api/v1/scanner-agent/heartbeat",
        json={"scanner_instance_id": "abc123", "status": "online"},
        status=200,
    )

    client = ScannerApiClient("https://api.example.com", "tok_secret")
    client.heartbeat()

    sent_body = responses.calls[0].request.body
    assert sent_body == b"{}"


@responses.activate
def test_validate_tools_includes_scanner_version_when_present():
    responses.add(
        responses.POST,
        "https://api.example.com/api/v1/scanner-agent/tools/validate",
        json={
            "scanner_instance_id": "abc123",
            "status": "online",
            "scan_profile": None,
            "tool_status": {"nmap": "available"},
            "test_scan_status": None,
        },
        status=200,
    )

    client = ScannerApiClient("https://api.example.com", "tok_secret")
    client.validate_tools({"nmap": "available"}, scanner_version="1.2.3")

    sent_body = responses.calls[0].request.body
    assert b'"scanner_version": "1.2.3"' in sent_body or b'"scanner_version":"1.2.3"' in sent_body


@responses.activate
def test_post_raises_scanner_api_error_on_4xx():
    responses.add(
        responses.POST,
        "https://api.example.com/api/v1/scanner-agent/heartbeat",
        json={"detail": "Invalid or revoked scanner credential."},
        status=401,
    )

    client = ScannerApiClient("https://api.example.com", "tok_bad")
    with pytest.raises(ScannerApiError, match="401"):
        client.heartbeat()


@responses.activate
def test_fetch_next_command_returns_none_when_no_command():
    responses.add(
        responses.GET,
        "https://api.example.com/api/v1/scanner-agent/commands/next",
        json={"has_command": False, "command": None},
        status=200,
    )

    client = ScannerApiClient("https://api.example.com", "tok_secret")
    assert client.fetch_next_command() is None
    assert responses.calls[0].request.headers["Authorization"] == "Bearer tok_secret"


@responses.activate
def test_fetch_next_command_returns_command_payload():
    command = {
        "command_id": "cmd-1",
        "command_type": "run_discovery",
        "discovery_run_id": "run-1",
        "profile": {"profileType": "safe_discovery"},
        "targets": [],
        "expires_at": "2026-07-18T00:00:00",
    }
    responses.add(
        responses.GET,
        "https://api.example.com/api/v1/scanner-agent/commands/next",
        json={"has_command": True, "command": command},
        status=200,
    )

    client = ScannerApiClient("https://api.example.com", "tok_secret")
    assert client.fetch_next_command() == command


@responses.activate
def test_acknowledge_command_sends_accepted_and_version():
    responses.add(
        responses.POST,
        "https://api.example.com/api/v1/scanner-agent/commands/cmd-1/acknowledge",
        json={"command_id": "cmd-1", "discovery_run_id": "run-1", "status": "acknowledged", "accepted": True},
        status=200,
    )

    client = ScannerApiClient("https://api.example.com", "tok_secret")
    result = client.acknowledge_command("cmd-1", accepted=True, scanner_runtime_version="0.1.0")

    assert result["status"] == "acknowledged"
    sent_body = responses.calls[0].request.body
    assert b'"accepted": true' in sent_body or b'"accepted":true' in sent_body


class TestFinishedWorkIsNotLostToOneBlip:
    """Søren's Collector ran a real scan and then threw it away.

    The result POST was a single attempt with a 15-second timeout; one
    ConnectTimeoutError and the evidence was gone, the whole scan to be redone.
    Cheap for an nmap sweep, expensive for nuclei over 13,500 templates, and it
    repeats for as long as the platform is unreachable.

    Retrying is only safe because the platform is idempotent here —
    `record_provider_execution_result` returns the already-recorded outcome for
    a terminal job rather than applying it twice — so a response lost in transit
    cannot cause a double-report.
    """

    @responses.activate
    def test_a_result_report_survives_a_transient_failure(self, monkeypatch):
        monkeypatch.setattr(api_client.time, "sleep", lambda _seconds: None)
        calls = {"n": 0}

        def _callback(request):
            calls["n"] += 1
            if calls["n"] == 1:
                raise requests.exceptions.ConnectTimeout("connection timed out")
            return (200, {}, '{"provider_execution_id": "pe-1", "status": "completed"}')

        responses.add_callback(
            responses.POST,
            "https://api.example.com/api/v1/scanner-agent/commands/cmd-1/result",
            callback=_callback,
            content_type="application/json",
        )

        client = ScannerApiClient("https://api.example.com", "token")
        result = client.report_provider_execution_result(
            "cmd-1", status="completed", evidence_format="nmap_xml", raw_evidence_payload="<nmaprun/>"
        )

        assert result["status"] == "completed"
        assert calls["n"] == 2

    @responses.activate
    def test_it_gives_up_rather_than_retrying_forever(self, monkeypatch):
        # A command carries its own expiry; retrying past it only stops the
        # agent picking up work it could still do.
        monkeypatch.setattr(api_client.time, "sleep", lambda _seconds: None)
        calls = {"n": 0}

        def _callback(request):
            calls["n"] += 1
            raise requests.exceptions.ConnectTimeout("connection timed out")

        responses.add_callback(
            responses.POST,
            "https://api.example.com/api/v1/scanner-agent/commands/cmd-1/result",
            callback=_callback,
            content_type="application/json",
        )

        client = ScannerApiClient("https://api.example.com", "token")
        with pytest.raises(ScannerApiError):
            client.report_provider_execution_result("cmd-1", status="completed")

        assert calls["n"] == api_client._REPORT_ATTEMPTS

    @responses.activate
    def test_a_rejection_is_not_retried(self, monkeypatch):
        # A 4xx is the platform's considered answer — an expired command, a
        # revoked credential. Repeating it turns a clear rejection into a slow
        # one and hammers the API while it is already saying no.
        monkeypatch.setattr(api_client.time, "sleep", lambda _seconds: None)
        responses.add(
            responses.POST,
            "https://api.example.com/api/v1/scanner-agent/commands/cmd-1/result",
            json={"detail": "command expired"},
            status=400,
        )

        client = ScannerApiClient("https://api.example.com", "token")
        with pytest.raises(ScannerApiError):
            client.report_provider_execution_result("cmd-1", status="completed")

        assert len(responses.calls) == 1

    @responses.activate
    def test_a_poll_is_still_a_single_attempt(self, monkeypatch):
        # Nothing is lost by letting the next cycle poll again, so retrying
        # here would only stall the loop.
        monkeypatch.setattr(api_client.time, "sleep", lambda _seconds: None)
        calls = {"n": 0}

        def _callback(request):
            calls["n"] += 1
            raise requests.exceptions.ConnectTimeout("connection timed out")

        responses.add_callback(
            responses.GET,
            "https://api.example.com/api/v1/scanner-agent/commands/next",
            callback=_callback,
            content_type="application/json",
        )

        client = ScannerApiClient("https://api.example.com", "token")
        with pytest.raises(ScannerApiError):
            client.fetch_next_command()

        assert calls["n"] == 1


def test_every_client_path_carries_the_api_prefix():
    """The bug this test exists for, found by hand on 2026-08-24.

    ``report_inspection`` was written as ``/scanner-agent/inspections/...`` while
    every other call in this client carries ``/api/v1``. Nothing failed — the
    agent suite stubs whatever URL the code asks for, so a wrong path is a green
    test and a 404 in production.

    Asserted against the source rather than by calling each method, so a method
    added later is covered without anybody remembering to extend a list. Only
    strings naming the scanner-agent surface are examined: an f-string's tail
    fragments (``"/report"`` after ``{command_id}``) are not paths, and neither
    is a lone ``"/"`` used for trimming.
    """
    import ast
    import inspect as _inspect

    from scanner_agent import api_client as module

    tree = ast.parse(_inspect.getsource(module))
    paths: list[str] = []

    def _collect(node: ast.AST) -> None:
        if isinstance(node, ast.JoinedStr):
            head = node.values[0] if node.values else None
            if isinstance(head, ast.Constant) and isinstance(head.value, str):
                paths.append(head.value)
            return  # do not descend: the tail fragments are not paths
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            paths.append(node.value)
            return
        for child in ast.iter_child_nodes(node):
            _collect(child)

    _collect(tree)

    # A leading slash as well as the word: a docstring mentioning "scanner-agent"
    # is prose, not a path, and matching it would fail this test for no reason.
    surface = [path for path in paths if path.startswith("/") and "scanner-agent" in path]
    assert surface, "found no scanner-agent paths at all — the walk is wrong, not the client"

    offenders = [path for path in surface if not path.startswith("/api/v1/scanner-agent")]
    assert offenders == [], offenders

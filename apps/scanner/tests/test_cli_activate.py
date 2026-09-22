import responses
from click.testing import CliRunner

from scanner_agent import cli as cli_module
from scanner_agent.cli import cli
from scanner_agent.config import ScannerCredentials


@responses.activate
def test_activate_stores_the_scanner_instance_id(monkeypatch):
    """CA-04.1 — `poll` needs its own scanner_instance_id locally to reject
    a wrong-instance command, so `activate` must capture it from the
    heartbeat response, not just base_url/activation_token."""
    saved: dict[str, ScannerCredentials] = {}

    def _fake_save(credentials: ScannerCredentials):
        saved["credentials"] = credentials
        return "/fake/path/credentials.json"

    monkeypatch.setattr(cli_module, "save_credentials", _fake_save)
    responses.add(
        responses.POST,
        "https://api.example.com/api/v1/scanner-agent/heartbeat",
        json={"scanner_instance_id": "instance-xyz", "status": "registered"},
        status=200,
    )

    result = CliRunner().invoke(
        cli, ["activate", "--base-url", "https://api.example.com", "--token", "tok_abc123"]
    )

    assert result.exit_code == 0
    assert "Activated scanner instance instance-xyz" in result.output
    assert saved["credentials"] == ScannerCredentials(
        base_url="https://api.example.com", activation_token="tok_abc123", scanner_instance_id="instance-xyz"
    )

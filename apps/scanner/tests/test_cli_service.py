from pathlib import Path
from unittest.mock import patch

from click.testing import CliRunner

from scanner_agent.cli import cli
from scanner_agent.service import ServiceError


def test_install_command_reports_success():
    unit_path = Path("/home/user/.config/systemd/user/risklence-scanner.service")
    with patch("scanner_agent.cli.install_service", return_value=unit_path):
        result = CliRunner().invoke(cli, ["install"])

    assert result.exit_code == 0
    assert "Installed and started" in result.output
    assert str(unit_path) in result.output


def test_install_command_reports_service_error():
    with patch(
        "scanner_agent.cli.install_service",
        side_effect=ServiceError("systemctl not found — service install/uninstall requires a systemd host."),
    ):
        result = CliRunner().invoke(cli, ["install"])

    assert result.exit_code != 0
    assert "systemd host" in result.output


def test_uninstall_command_reports_success():
    with patch("scanner_agent.cli.uninstall_service") as mock_uninstall:
        result = CliRunner().invoke(cli, ["uninstall"])

    mock_uninstall.assert_called_once()
    assert result.exit_code == 0
    assert "Service stopped and removed." in result.output


def test_uninstall_command_reports_service_error():
    with patch("scanner_agent.cli.uninstall_service", side_effect=ServiceError("boom")):
        result = CliRunner().invoke(cli, ["uninstall"])

    assert result.exit_code != 0
    assert "boom" in result.output

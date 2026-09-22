import subprocess
from unittest.mock import patch

import pytest

from scanner_agent.service import ServiceError, SERVICE_NAME, install_service, uninstall_service, unit_path


def test_install_service_writes_unit_and_enables_it(tmp_path):
    unit_dir = tmp_path / "systemd" / "user"
    with (
        patch("scanner_agent.service._executable_path", return_value="/usr/local/bin/risklence-scanner"),
        patch("scanner_agent.service._run_systemctl") as mock_systemctl,
    ):
        path = install_service(unit_dir)

    assert path == unit_dir / SERVICE_NAME
    content = path.read_text()
    assert "ExecStart=/usr/local/bin/risklence-scanner run" in content
    assert "Restart=on-failure" in content
    mock_systemctl.assert_any_call("daemon-reload")
    mock_systemctl.assert_any_call("enable", "--now", SERVICE_NAME)


def test_install_service_raises_when_executable_not_found(tmp_path):
    with patch("scanner_agent.service._executable_path", side_effect=ServiceError("not found")):
        with pytest.raises(ServiceError):
            install_service(tmp_path)


def test_uninstall_service_removes_unit_and_disables_it(tmp_path):
    unit_dir = tmp_path / "systemd" / "user"
    unit_dir.mkdir(parents=True)
    path = unit_path(unit_dir)
    path.write_text("[Unit]\n")

    with patch("scanner_agent.service._run_systemctl") as mock_systemctl:
        uninstall_service(unit_dir)

    assert not path.exists()
    mock_systemctl.assert_any_call("disable", "--now", SERVICE_NAME)
    mock_systemctl.assert_any_call("daemon-reload")


def test_uninstall_service_is_a_safe_no_op_when_never_installed(tmp_path):
    unit_dir = tmp_path / "systemd" / "user"
    with patch("scanner_agent.service._run_systemctl") as mock_systemctl:
        uninstall_service(unit_dir)  # must not raise
    mock_systemctl.assert_not_called()


def test_run_systemctl_wraps_called_process_error():
    from scanner_agent.service import _run_systemctl

    with patch(
        "subprocess.run",
        side_effect=subprocess.CalledProcessError(1, ["systemctl"], stderr="unit not found"),
    ):
        with pytest.raises(ServiceError, match="unit not found"):
            _run_systemctl("enable", "--now", "risklence-scanner.service")


def test_run_systemctl_wraps_missing_systemctl_binary():
    from scanner_agent.service import _run_systemctl

    with patch("subprocess.run", side_effect=FileNotFoundError()):
        with pytest.raises(ServiceError, match="systemd host"):
            _run_systemctl("daemon-reload")

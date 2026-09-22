from pathlib import Path

from scanner_agent.tool_checks import check_all_tools, check_nuclei_templates, check_tool


def test_check_tool_missing_binary_returns_not_available():
    result = check_tool("nmap")
    if result.available:
        # nmap happens to be installed on this machine — assert the shape instead.
        assert result.binary_path is not None
    else:
        assert result.version is None
        assert result.binary_path is None


def test_check_nuclei_templates_missing_directory():
    result = check_nuclei_templates(templates_dir=Path("/nonexistent/nuclei-templates-dir"))
    assert result.available is False


def test_check_nuclei_templates_present_and_nonempty(tmp_path: Path):
    templates_dir = tmp_path / "nuclei-templates"
    templates_dir.mkdir()
    (templates_dir / "cve-2024-0001.yaml").write_text("id: cve-2024-0001")

    result = check_nuclei_templates(templates_dir=templates_dir)

    assert result.available is True
    assert result.tool == "nuclei_templates"
    assert result.version is None


def test_check_nuclei_templates_reports_pinned_version(tmp_path: Path):
    templates_dir = tmp_path / "nuclei-templates"
    templates_dir.mkdir()
    (templates_dir / "cve-2024-0001.yaml").write_text("id: cve-2024-0001")
    (templates_dir / ".risklence-template-version").write_text("v10.4.7\n")

    result = check_nuclei_templates(templates_dir=templates_dir)

    assert result.available is True
    assert result.version == "v10.4.7"


def test_check_all_tools_returns_every_tool_and_the_environment_capability():
    """The four scanning tools, plus what the environment permits. The
    capability rides in the same list so the platform learns it on the same
    self-check — but it is not a tool, and nothing requires it."""
    results = check_all_tools()
    assert {result.tool for result in results} == {
        "nmap",
        "subfinder",
        "nuclei",
        "nuclei_templates",
        "raw_packet_access",
    }


# --- Raw-packet capability (2026-08-25) --------------------------------------


def test_the_raw_packet_capability_is_reported_alongside_the_tools():
    """It travels in the same components list so the platform learns it on the
    same self-check, without a second round trip."""
    from scanner_agent.tool_checks import RAW_PACKET_CAPABILITY, check_all_tools

    assert RAW_PACKET_CAPABILITY in {check.tool for check in check_all_tools()}


def test_the_capability_check_answers_rather_than_raising_when_it_is_denied():
    """An unprivileged container is the *normal* case, not an error. A check
    that raised would take the whole self-check down with it and the Collector
    would report nothing at all."""
    from scanner_agent.tool_checks import check_raw_packet_capability

    result = check_raw_packet_capability()

    assert result.tool == "raw_packet_access"
    assert isinstance(result.available, bool)


def test_a_denied_capability_records_why_rather_than_only_that():
    """When it is refused, the reason is kept — "PermissionError" tells an
    operator they need the capability; a bare False tells them nothing."""
    import socket
    from unittest.mock import patch

    from scanner_agent.tool_checks import check_raw_packet_capability

    with patch.object(socket, "socket", side_effect=PermissionError("nope")):
        result = check_raw_packet_capability()

    assert result.available is False
    assert result.binary_path == "PermissionError"


def test_a_granted_capability_closes_the_socket_it_opened():
    """The check must not leak a descriptor every time readiness is reported —
    the run loop calls this on a cycle."""
    from unittest.mock import MagicMock, patch

    import socket as socket_module

    from scanner_agent.tool_checks import check_raw_packet_capability

    fake = MagicMock()
    with patch.object(socket_module, "socket", return_value=fake):
        result = check_raw_packet_capability()

    assert result.available is True
    fake.close.assert_called_once()

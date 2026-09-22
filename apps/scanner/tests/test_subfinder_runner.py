import pytest

from scanner_agent import subfinder_runner
from scanner_agent.subfinder_runner import (
    SubfinderNotAvailableError,
    SubfinderScanResult,
    run_subfinder_discovery,
    run_subfinder_scan,
)


def test_run_subfinder_scan_raises_when_binary_missing(monkeypatch):
    monkeypatch.setattr(subfinder_runner.shutil, "which", lambda _binary: None)

    with pytest.raises(SubfinderNotAvailableError):
        run_subfinder_scan("example.com")


def test_run_subfinder_scan_parses_discovered_subdomains(monkeypatch):
    monkeypatch.setattr(subfinder_runner.shutil, "which", lambda _binary: "/usr/bin/subfinder")

    class _FakeResult:
        returncode = 0
        stdout = "app.example.com\nmail.example.com\n"
        stderr = ""

    monkeypatch.setattr(subfinder_runner.subprocess, "run", lambda *args, **kwargs: _FakeResult())

    result = run_subfinder_scan("example.com")

    assert result.domain == "example.com"
    assert result.subdomains == ["app.example.com", "mail.example.com"]


def test_run_subfinder_discovery_scans_every_domain(monkeypatch):
    calls: list[str] = []

    def _fake_scan(domain: str, *, timeout: float = 60.0) -> SubfinderScanResult:
        calls.append(domain)
        return SubfinderScanResult(domain=domain, subdomains=[f"a.{domain}"], raw_output="")

    monkeypatch.setattr(subfinder_runner, "run_subfinder_scan", _fake_scan)

    results = run_subfinder_discovery(["example.com", "example.org"])

    assert calls == ["example.com", "example.org"]
    assert [r.subdomains for r in results] == [["a.example.com"], ["a.example.org"]]


def test_run_subfinder_discovery_raises_immediately_when_binary_missing(monkeypatch):
    monkeypatch.setattr(subfinder_runner.shutil, "which", lambda _binary: None)

    with pytest.raises(SubfinderNotAvailableError):
        run_subfinder_discovery(["example.com"])

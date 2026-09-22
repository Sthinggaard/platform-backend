import pytest
from pathlib import Path

from scanner_agent import nuclei_runner
from scanner_agent.nuclei_runner import (
    NucleiNotAvailableError,
    NucleiScanResult,
    run_nuclei_discovery,
    run_nuclei_scan,
)


def test_run_nuclei_scan_raises_when_binary_missing(monkeypatch, tmp_path):
    monkeypatch.setattr(nuclei_runner.shutil, "which", lambda _binary: None)

    with pytest.raises(NucleiNotAvailableError):
        run_nuclei_scan("https://example.com", templates_dir=tmp_path)


def test_run_nuclei_scan_raises_when_pinned_templates_missing(monkeypatch, tmp_path):
    monkeypatch.setattr(nuclei_runner.shutil, "which", lambda _binary: "/usr/bin/nuclei")
    missing_dir = tmp_path / "nuclei-templates"  # never created

    with pytest.raises(NucleiNotAvailableError):
        run_nuclei_scan("https://example.com", templates_dir=missing_dir)


def test_run_nuclei_scan_raises_when_pinned_templates_directory_is_empty(monkeypatch, tmp_path):
    monkeypatch.setattr(nuclei_runner.shutil, "which", lambda _binary: "/usr/bin/nuclei")
    empty_dir = tmp_path / "nuclei-templates"
    empty_dir.mkdir()

    with pytest.raises(NucleiNotAvailableError):
        run_nuclei_scan("https://example.com", templates_dir=empty_dir)


def test_run_nuclei_scan_never_invokes_an_arbitrary_template_update(monkeypatch, tmp_path):
    """The acceptance criterion this whole story exists for: the real check
    this runner wires up must run against the pinned, versioned CA-03.2
    template pack, never reintroduce an unpinned `-update-templates` fetch
    at runtime."""
    templates_dir = tmp_path / "nuclei-templates"
    templates_dir.mkdir()
    (templates_dir / "cve-2024-0001.yaml").write_text("id: cve-2024-0001")
    monkeypatch.setattr(nuclei_runner.shutil, "which", lambda _binary: "/usr/bin/nuclei")

    captured: dict = {}

    class _FakeResult:
        returncode = 0
        stdout = ""
        stderr = ""

    def _fake_run(command, **kwargs):
        captured["command"] = command
        return _FakeResult()

    monkeypatch.setattr(nuclei_runner.subprocess, "run", _fake_run)

    run_nuclei_scan("https://example.com", templates_dir=templates_dir)

    invoked = captured["command"]
    assert "-update-templates" not in invoked
    assert "-ut" not in invoked
    assert "-t" in invoked
    assert str(templates_dir) in invoked
    assert "-duc" in invoked  # disables nuclei's own auto-update-check network call


def test_run_nuclei_scan_parses_raw_jsonl_output(monkeypatch, tmp_path):
    templates_dir = tmp_path / "nuclei-templates"
    templates_dir.mkdir()
    (templates_dir / "cve-2024-0001.yaml").write_text("id: cve-2024-0001")
    monkeypatch.setattr(nuclei_runner.shutil, "which", lambda _binary: "/usr/bin/nuclei")

    class _FakeResult:
        returncode = 1  # a real finding match — not a process failure for nuclei
        stdout = '{"template-id": "cve-2024-0001", "host": "https://example.com"}\n'
        stderr = ""

    monkeypatch.setattr(nuclei_runner.subprocess, "run", lambda *args, **kwargs: _FakeResult())

    result = run_nuclei_scan("https://example.com", templates_dir=templates_dir)

    assert result.target == "https://example.com"
    assert "cve-2024-0001" in result.raw_output


def test_run_nuclei_discovery_scans_every_target(monkeypatch):
    """Both targets are covered — now in one invocation, because they share a
    scope and the template load is the dominant cost."""
    calls: list[list[str]] = []

    def _fake_scan(
        target, *, templates_dir, timeout: float = 180.0, template_trees=None
    ) -> NucleiScanResult:
        calls.append(target)
        return NucleiScanResult(target="group", raw_output="", targets=tuple(target))

    monkeypatch.setattr(nuclei_runner, "run_nuclei_scan", _fake_scan)

    results = run_nuclei_discovery(["https://a.example.com", "https://b.example.com"])

    assert calls == [["https://a.example.com", "https://b.example.com"]]
    covered = [host for result in results for host in result.targets]
    assert covered == ["https://a.example.com", "https://b.example.com"]


def test_run_nuclei_discovery_raises_immediately_when_templates_missing(monkeypatch, tmp_path):
    monkeypatch.setattr(nuclei_runner.shutil, "which", lambda _binary: "/usr/bin/nuclei")
    missing_dir = tmp_path / "nuclei-templates"

    with pytest.raises(NucleiNotAvailableError):
        run_nuclei_discovery(["https://example.com"], templates_dir=missing_dir)


def _templates(tmp_path):
    templates_dir = tmp_path / "nuclei-templates"
    templates_dir.mkdir()
    (templates_dir / "cve-2024-0001.yaml").write_text("id: cve-2024-0001")
    return templates_dir


def test_a_timeout_keeps_what_nuclei_had_already_written(monkeypatch, tmp_path):
    """🐞 The defect. nuclei streams JSONL as it matches, so a scan killed at
    the time budget has already written real findings — and they used to be
    discarded with the exception."""
    templates_dir = _templates(tmp_path)
    monkeypatch.setattr(nuclei_runner.shutil, "which", lambda _binary: "/usr/bin/nuclei")
    partial = b'{"template-id": "cve-2024-0001", "host": "192.168.50.152"}\n'

    def _timeout(*args, **kwargs):
        raise nuclei_runner.subprocess.TimeoutExpired(cmd="nuclei", timeout=180.0, output=partial)

    monkeypatch.setattr(nuclei_runner.subprocess, "run", _timeout)

    result = run_nuclei_scan("192.168.50.0/24", templates_dir=templates_dir)

    assert "cve-2024-0001" in result.raw_output


def test_a_timeout_is_never_reported_as_a_completed_scan(monkeypatch, tmp_path):
    """The safety property. A scan that was killed must be distinguishable from
    one that ran to the end and matched nothing — the platform's resolution rule
    is that a later scan finding nothing proves a finding resolved, so the two
    must never be the same result."""
    templates_dir = _templates(tmp_path)
    monkeypatch.setattr(nuclei_runner.shutil, "which", lambda _binary: "/usr/bin/nuclei")

    def _timeout(*args, **kwargs):
        raise nuclei_runner.subprocess.TimeoutExpired(cmd="nuclei", timeout=180.0, output=b"")

    monkeypatch.setattr(nuclei_runner.subprocess, "run", _timeout)

    truncated = run_nuclei_scan("192.168.50.0/24", templates_dir=templates_dir)

    assert truncated.completed is False
    assert truncated.raw_output == ""

    class _Clean:
        returncode = 0
        stdout = ""
        stderr = ""

    monkeypatch.setattr(nuclei_runner.subprocess, "run", lambda *a, **k: _Clean())
    clean = run_nuclei_scan("192.168.50.152", templates_dir=templates_dir)

    # Same empty output, opposite meanings.
    assert clean.raw_output == truncated.raw_output
    assert clean.completed is True


def test_a_truncated_multibyte_character_does_not_lose_the_scan(monkeypatch, tmp_path):
    """A kill lands wherever it lands. Losing every finding in a long scan to
    the last half-character of it is the failure this decode guards."""
    templates_dir = _templates(tmp_path)
    monkeypatch.setattr(nuclei_runner.shutil, "which", lambda _binary: "/usr/bin/nuclei")
    cut_mid_character = b'{"template-id": "cve-2024-0001"}\n{"host": "\xc3'

    def _timeout(*args, **kwargs):
        raise nuclei_runner.subprocess.TimeoutExpired(cmd="nuclei", timeout=180.0, output=cut_mid_character)

    monkeypatch.setattr(nuclei_runner.subprocess, "run", _timeout)

    result = run_nuclei_scan("192.168.50.0/24", templates_dir=templates_dir)

    assert "cve-2024-0001" in result.raw_output


def test_a_scan_that_finished_is_marked_complete(monkeypatch, tmp_path):
    templates_dir = _templates(tmp_path)
    monkeypatch.setattr(nuclei_runner.shutil, "which", lambda _binary: "/usr/bin/nuclei")

    class _FakeResult:
        returncode = 1
        stdout = '{"template-id": "cve-2024-0001"}\n'
        stderr = ""

    monkeypatch.setattr(nuclei_runner.subprocess, "run", lambda *a, **k: _FakeResult())

    assert run_nuclei_scan("192.168.50.152", templates_dir=templates_dir).completed is True


def test_one_scope_being_truncated_does_not_truncate_another(monkeypatch):
    """Truncation is per **invocation**, and an invocation is per scope.

    This used to be per target. Grouping changed it deliberately: nuclei's JSONL
    says which host produced a finding but not which hosts it *finished*, so
    after a kill the honest answer for every host in that group is "not
    complete". That over-reports rather than under-reports, which is the only
    safe direction — the platform reads a later scan finding nothing as proof a
    fix held, so claiming a host was fully scanned when it was not could
    silently discharge a real finding.

    Two different scopes are still two invocations and still independent.
    """
    def _fake_scan(
        target, *, templates_dir, timeout: float = 180.0, template_trees=None
    ) -> NucleiScanResult:
        hosts = tuple(target)
        return NucleiScanResult(
            target=hosts[0], raw_output="", completed="192.168.50.1" not in hosts, targets=hosts
        )

    monkeypatch.setattr(nuclei_runner, "run_nuclei_scan", _fake_scan)

    results = run_nuclei_discovery(
        [("192.168.50.1", ["http"]), ("192.168.50.152", ["network"])]
    )

    by_host = {host: r.completed for r in results for host in r.targets}
    assert by_host == {"192.168.50.1": False, "192.168.50.152": True}


# --- CA-09V: the command scopes which template trees run --------------------
#
# Narrowing to discovered hosts left the 2026-09-07 07:12 run at 606 seconds and
# 0 bytes, because the organisation holds an artefact per address across a whole
# /24. The server now sends the trees each host is worth scanning; this agent
# resolves them against its own pinned pack and will not accept a path.


def _pack(tmp_path, trees=("http", "network", "ssl", "dns", "javascript")):
    root = tmp_path / "nuclei-templates"
    for tree in trees:
        (root / tree).mkdir(parents=True)
        (root / tree / "example.yaml").write_text("id: example\n")
    return root


def test_no_scope_runs_the_whole_pack(tmp_path):
    """`None` is what an older server sends, and it must keep working — the
    agent and the server are deployed separately and cannot be assumed in step.
    """
    root = _pack(tmp_path)
    assert nuclei_runner.resolve_template_paths(root, None) == [root]


def test_a_scope_becomes_one_dash_t_per_tree(tmp_path):
    root = _pack(tmp_path)
    paths = nuclei_runner.resolve_template_paths(root, ["network", "ssl"])
    assert paths == [root / "network", root / "ssl"]


def test_the_http_tree_is_dropped_when_the_server_did_not_scope_it(tmp_path):
    """The 82% saving, at the point it actually takes effect."""
    root = _pack(tmp_path)
    paths = nuclei_runner.resolve_template_paths(root, ["network", "ssl", "dns", "javascript"])
    assert root / "http" not in paths


@pytest.mark.parametrize(
    "hostile",
    ["../../../etc", "/etc/passwd", "http/../../..", "..", "helpers", "profiles", ""],
)
def test_a_tree_name_outside_the_allowlist_is_refused(tmp_path, hostile):
    """The wire carries names, never paths, and this is why.

    The agent joins only allowlisted names to its pack root, so a malformed or
    hostile command cannot walk out of the pack directory or point nuclei at
    templates nobody reviewed.
    """
    root = _pack(tmp_path)
    assert nuclei_runner.resolve_template_paths(root, [hostile]) == []


def test_a_non_string_tree_is_refused(tmp_path):
    root = _pack(tmp_path)
    assert nuclei_runner.resolve_template_paths(root, [None, 7, {"http": True}]) == []


def test_a_tree_missing_from_this_pack_is_skipped_not_fatal(tmp_path):
    """nuclei errors on a missing `-t` path. Losing a whole host's scan to one
    absent directory would be worse than scanning the trees that are there."""
    root = _pack(tmp_path, trees=("network", "ssl"))
    assert nuclei_runner.resolve_template_paths(root, ["http", "network"]) == [root / "network"]


def test_a_scope_that_resolves_to_nothing_refuses_to_scan_the_whole_pack(tmp_path):
    """The quiet-failure guard.

    Falling back to the full pack here would ignore a deliberate narrowing and
    do far more work than was asked for — and would look, from the outside, like
    the scoping simply had not helped.
    """
    root = _pack(tmp_path)
    with pytest.raises(nuclei_runner.NucleiScanError) as excinfo:
        nuclei_runner.run_nuclei_scan(
            "192.168.50.152", templates_dir=root, template_trees=["nonsense"]
        )
    assert "whole pack" in str(excinfo.value)


def test_the_scope_reaches_the_nuclei_command_line(tmp_path, monkeypatch):
    """End of the wire: what the server chose is what nuclei is invoked with."""
    root = _pack(tmp_path)
    captured: dict = {}

    def _fake_run(command, **kwargs):
        captured["command"] = command

        class _Result:
            stdout = ""
            returncode = 0

        return _Result()

    monkeypatch.setattr(nuclei_runner.shutil, "which", lambda _: "/usr/local/bin/nuclei")
    monkeypatch.setattr(nuclei_runner.subprocess, "run", _fake_run)

    nuclei_runner.run_nuclei_scan(
        "192.168.50.152", templates_dir=root, template_trees=["network", "ssl"]
    )

    command = captured["command"]
    assert command.count("-t") == 2
    assert str(root / "network") in command and str(root / "ssl") in command
    assert str(root / "http") not in command
    # The pinned-pack guarantees are not weakened by scoping.
    assert "-duc" in command
    assert "-update-templates" not in command and "-ut" not in command


def test_hosts_sharing_a_scope_are_scanned_in_one_invocation(tmp_path, monkeypatch):
    """The fix for the 676s run.

    Measured on the Pi against the pinned pack: the http tree costs 46s of fixed
    load plus ~20s of work per target, so eight separate invocations spent 371s
    — 41% of that run — re-loading the same templates. Hosts that share a scope
    now load them once.
    """
    seen: list[tuple[object, object]] = []

    def _fake_scan(target, *, templates_dir, timeout=180.0, template_trees=None):
        seen.append((tuple(target), tuple(template_trees or ())))
        return NucleiScanResult(target=tuple(target)[0], raw_output="", targets=tuple(target))

    monkeypatch.setattr(nuclei_runner, "run_nuclei_scan", _fake_scan)

    run_nuclei_discovery(
        [
            ("192.168.50.152", ["http", "network"]),
            ("192.168.50.1", ["http", "network"]),
            ("192.168.50.96", ["network"]),
        ]
    )

    assert seen == [
        (("192.168.50.152", "192.168.50.1"), ("http", "network")),
        (("192.168.50.96",), ("network",)),
    ], "three hosts, two scopes, two invocations"


def test_a_group_is_given_every_target_s_share_of_the_budget(monkeypatch):
    """The caller divides the budget per target; an invocation covering three
    of them is owed all three shares, or grouping would make the timeout
    tighter than scanning them separately."""
    seen: list[float] = []

    def _fake_scan(target, *, templates_dir, timeout=180.0, template_trees=None):
        seen.append(timeout)
        return NucleiScanResult(target=tuple(target)[0], raw_output="", targets=tuple(target))

    monkeypatch.setattr(nuclei_runner, "run_nuclei_scan", _fake_scan)
    run_nuclei_discovery(
        [("a", ["http"]), ("b", ["http"]), ("c", ["http"]), ("d", ["network"])], timeout=100.0
    )

    assert seen == [300.0, 100.0]


def test_a_bare_string_target_still_works(monkeypatch):
    """Backward compatibility with every other runner's shape."""
    seen: list[tuple[str, object]] = []

    def _fake_scan(target, *, templates_dir, timeout=180.0, template_trees=None):
        seen.append((target, template_trees))
        return NucleiScanResult(target=target, raw_output="")

    monkeypatch.setattr(nuclei_runner, "run_nuclei_scan", _fake_scan)
    run_nuclei_discovery(["192.168.50.152"])
    assert seen == [(["192.168.50.152"], None)]


def test_a_group_reaches_nuclei_as_a_list_file(tmp_path, monkeypatch):
    """`-target` takes one host. A group goes through nuclei's own `-list`,
    which also keeps the command line from growing with the estate."""
    root = _pack(tmp_path)
    captured: dict = {}

    def _fake_run(command, **kwargs):
        captured["command"] = list(command)
        # Read it now — the temporary directory is gone once the call returns.
        if "-list" in command:
            captured["listed"] = Path(command[command.index("-list") + 1]).read_text()

        class _R:
            stdout = ""
            returncode = 0

        return _R()

    monkeypatch.setattr(nuclei_runner.shutil, "which", lambda _: "/usr/local/bin/nuclei")
    monkeypatch.setattr(nuclei_runner.subprocess, "run", _fake_run)

    result = nuclei_runner.run_nuclei_scan(
        ["192.168.50.1", "192.168.50.152"], templates_dir=root, template_trees=["network"]
    )

    assert "-target" not in captured["command"]
    assert captured["listed"].split() == ["192.168.50.1", "192.168.50.152"]
    assert result.targets == ("192.168.50.1", "192.168.50.152")


def test_a_single_host_still_uses_target_not_a_list_file(tmp_path, monkeypatch):
    root = _pack(tmp_path)
    captured: dict = {}

    def _fake_run(command, **kwargs):
        captured["command"] = list(command)

        class _R:
            stdout = ""
            returncode = 0

        return _R()

    monkeypatch.setattr(nuclei_runner.shutil, "which", lambda _: "/usr/local/bin/nuclei")
    monkeypatch.setattr(nuclei_runner.subprocess, "run", _fake_run)

    result = nuclei_runner.run_nuclei_scan(
        "192.168.50.152", templates_dir=root, template_trees=["network"]
    )

    assert "-list" not in captured["command"]
    assert "-target" in captured["command"]
    assert result.targets == ("192.168.50.152",)


def test_a_truncated_group_names_every_host_it_covered(tmp_path, monkeypatch):
    """The caller reports which hosts were not fully scanned, so a group that
    was killed has to surrender all of its host names, not just a label."""
    root = _pack(tmp_path)

    def _fake_run(command, **kwargs):
        raise nuclei_runner.subprocess.TimeoutExpired(cmd=command, timeout=1.0, output=b"")

    monkeypatch.setattr(nuclei_runner.shutil, "which", lambda _: "/usr/local/bin/nuclei")
    monkeypatch.setattr(nuclei_runner.subprocess, "run", _fake_run)

    result = nuclei_runner.run_nuclei_scan(
        ["192.168.50.1", "192.168.50.152"], templates_dir=root, template_trees=["network"]
    )

    assert result.completed is False
    assert result.targets == ("192.168.50.1", "192.168.50.152")


def test_an_empty_group_is_refused(tmp_path):
    root = _pack(tmp_path)
    with pytest.raises(nuclei_runner.NucleiScanError):
        nuclei_runner.run_nuclei_scan([], templates_dir=root, template_trees=["network"])

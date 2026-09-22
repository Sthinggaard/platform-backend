"""CA-02.3 slice 3 — the conditions that make working binaries useless anyway.

Both of these must report ``unknown`` rather than guessing. Søren's decision for
this slice is that unknown never blocks discovery, which is only safe because
"we did not look" stays distinguishable from "we looked and it is broken".
"""

from __future__ import annotations

from pathlib import Path

import pytest

from scanner_agent import health_checks
from scanner_agent.health_checks import (
    UNSTABLE_FAILURE_THRESHOLD,
    check_evidence_storage,
    check_platform_connectivity,
)


class TestEvidenceStorage:
    def test_a_writable_directory_with_headroom_is_ready(self, tmp_path: Path):
        result = check_evidence_storage(tmp_path)

        assert result.status == "ready"

    def test_the_directory_is_created_if_missing(self, tmp_path: Path):
        # A freshly installed Collector has no state directory yet, and that is
        # not a fault.
        target = tmp_path / "does-not-exist-yet"

        assert check_evidence_storage(target).status == "ready"
        assert target.is_dir()

    def test_an_unwritable_directory_is_unavailable(self, tmp_path: Path, monkeypatch):
        # Genuinely exercised rather than inferred from permission bits: a
        # read-only mount, a full disk and an SELinux denial all pass
        # os.access(W_OK) and then fail the write.
        def _boom(*_args, **_kwargs):
            raise OSError("read-only file system")

        monkeypatch.setattr(health_checks.tempfile, "NamedTemporaryFile", _boom)

        result = check_evidence_storage(tmp_path)

        assert result.status == "unavailable"
        assert result.reason_code == "state_dir_not_writable"

    def test_low_free_space_degrades_rather_than_blocks(self, tmp_path: Path, monkeypatch):
        # Writable, so evidence can still be handled — but the durable spool
        # that would survive a long platform outage is exactly what needs this
        # space, and finding out then is finding out too late.
        class _Usage:
            total = 100
            used = 99
            free = 1

        monkeypatch.setattr(health_checks.shutil, "disk_usage", lambda _p: _Usage())

        result = check_evidence_storage(tmp_path)

        assert result.status == "degraded"
        assert result.reason_code == "low_free_space"

    def test_unknown_headroom_is_degraded_not_ready(self, tmp_path: Path, monkeypatch):
        # The write demonstrably worked, so "unavailable" would be false; but
        # claiming "ready" would overclaim on a figure we could not read.
        def _boom(_p):
            raise OSError("statvfs unavailable")

        monkeypatch.setattr(health_checks.shutil, "disk_usage", _boom)

        result = check_evidence_storage(tmp_path)

        assert result.status == "degraded"
        assert result.reason_code == "free_space_unknown"


class TestPlatformConnectivity:
    def test_no_observed_history_is_unknown_not_healthy(self):
        # A one-shot `validate-tools`, or the very first cycle. The run loop is
        # what accumulates this, and absence of evidence is not health.
        result = check_platform_connectivity(recent_failures=0, recent_attempts=0)

        assert result.status == "unknown"
        assert result.reason_code == "no_attempts_recorded"

    def test_a_stable_link_is_ready(self):
        assert check_platform_connectivity(recent_failures=0, recent_attempts=10).status == "ready"

    def test_one_blip_is_not_reported_as_degradation(self):
        # A single transient failure is normal on any real network; reporting
        # it would make the signal noise, and a noisy panel stops being read.
        result = check_platform_connectivity(recent_failures=1, recent_attempts=10)

        assert result.status == "ready"

    def test_a_repeatedly_dropping_link_is_degraded(self):
        result = check_platform_connectivity(
            recent_failures=UNSTABLE_FAILURE_THRESHOLD, recent_attempts=10
        )

        assert result.status == "degraded"
        assert result.reason_code == "intermittent_connectivity"

    def test_it_never_claims_the_platform_is_unreachable(self):
        # It cannot: this result is delivered *to* the platform, so a report
        # that arrives at all proves current reachability. A genuinely
        # unreachable Collector sends nothing. The field describes stability,
        # and liveness stays derived platform-side from heartbeat age.
        worst = check_platform_connectivity(recent_failures=10, recent_attempts=10)

        assert worst.status == "degraded"
        assert worst.status != "unavailable"

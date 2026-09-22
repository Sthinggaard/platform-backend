"""CA-09A / #322 — the Collector proves it is alive while it is working."""

import threading
import time

import pytest

from scanner_agent.lease_heartbeat import (
    WORKING_HEARTBEAT_SECONDS,
    heartbeat_while_working,
)


def test_a_long_job_is_heartbeated_throughout_not_only_at_its_edges():
    """The whole point. The agent loop executes a scan synchronously, so
    without this the Collector is silent for exactly as long as the scan
    takes — and a /24 with version detection outlasts the platform's lease
    every time. Silence during work is indistinguishable from a dead machine,
    so the job was reclaimed from a Collector that was busy doing it."""
    beats = []

    with heartbeat_while_working(lambda: beats.append(time.monotonic()), every_seconds=0.05):
        time.sleep(0.28)

    assert len(beats) >= 4, f"expected repeated beats across the job, got {len(beats)}"


def test_the_first_beat_waits_one_interval():
    """The caller has just heartbeated as part of its own cycle. A second beat
    on the same second tells the platform nothing it does not already know."""
    beats = []

    with heartbeat_while_working(lambda: beats.append(1), every_seconds=5):
        pass

    assert beats == []


def test_beating_stops_when_the_job_does():
    """A thread that outlived its job would renew a lease for work that is no
    longer running — which is the lease lying in the other direction."""
    beats = []

    with heartbeat_while_working(lambda: beats.append(1), every_seconds=0.05):
        time.sleep(0.12)
    settled = len(beats)
    time.sleep(0.2)

    assert len(beats) == settled


def test_a_failing_heartbeat_never_takes_down_the_scan():
    """The scan is the valuable thing. A beat that cannot be delivered costs at
    most the lease expiry that happens today anyway; killing the job to report
    it would cost the whole scan."""
    seen = []

    def _explode():
        raise RuntimeError("platform unreachable")

    with heartbeat_while_working(_explode, every_seconds=0.05, on_error=seen.append):
        time.sleep(0.16)

    assert seen, "the failure should be reported to the caller"
    assert all(isinstance(exc, RuntimeError) for exc in seen)


def test_the_job_result_is_returned_and_exceptions_still_propagate():
    """The context manager is transparent: it protects the lease and changes
    nothing else about how a command succeeds or fails."""
    with pytest.raises(ValueError, match="scan failed"):
        with heartbeat_while_working(lambda: None, every_seconds=5):
            raise ValueError("scan failed")


def test_the_working_cadence_leaves_room_inside_the_platform_lease():
    """`WORKER_LEASE_DEFAULT_SECONDS` is 300. A cadence at or near that is the
    bug this fixes (#322), so the constant is asserted rather than trusted —
    it is written down in two repositories and nothing else stops them
    drifting back together."""
    assert WORKING_HEARTBEAT_SECONDS * 4 <= 300


def test_no_thread_is_left_behind():
    before = threading.active_count()

    with heartbeat_while_working(lambda: None, every_seconds=0.05):
        time.sleep(0.08)
    time.sleep(0.15)

    assert threading.active_count() <= before

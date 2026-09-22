"""Can this Collector actually do its job? (CA-02.3 slice 3)

Distinct from ``tool_checks``, which answers "are the bundled binaries present
and runnable". These are the conditions that make a working set of binaries
useless anyway: nowhere to put evidence, or a link to the platform too unstable
to deliver it.

**Both are reported as ``unknown`` until genuinely measured.** Søren's decision
for this slice is that ``unknown`` never blocks discovery — absence of evidence
is not evidence of health, but it is not evidence of failure either, and
blocking on it would strand every Collector that has not upgraded its agent.
"""

from __future__ import annotations

import os
import shutil
import tempfile
from dataclasses import dataclass
from pathlib import Path

#: Headroom below which storage is reported degraded rather than ready.
#:
#: A Collector does not stream evidence to disk today (nmap runs with ``-oX -``
#: and the payload is POSTed from memory), so this is not a hard requirement
#: yet. It is a *leading* indicator: the durable evidence spool that would let a
#: finished scan survive a long platform outage is exactly what needs this space,
#: and discovering the disk is full at that moment is discovering it too late.
LOW_DISK_BYTES = 512 * 1024 * 1024

#: How many of the agent's recent platform calls may fail before the link is
#: reported as degraded. Not zero: a single transient failure is normal on any
#: real network and reporting it as degradation would make the signal noise.
UNSTABLE_FAILURE_THRESHOLD = 3


@dataclass(frozen=True)
class HealthResult:
    status: str  # ready | degraded | unavailable | unknown
    reason_code: str | None = None
    detail: str | None = None


def check_evidence_storage(state_dir: Path) -> HealthResult:
    """Whether this Collector can write where it keeps its own state.

    Genuinely exercised rather than inferred: a real file is created, written,
    flushed to disk and removed. ``os.access(W_OK)`` would answer a question
    about permission bits, which is not the same question — a read-only mount, a
    full disk, or an SELinux denial all pass that check and then fail the write.
    """
    try:
        state_dir.mkdir(parents=True, exist_ok=True)
    except OSError as exc:
        return HealthResult("unavailable", "state_dir_uncreatable", str(exc))

    try:
        with tempfile.NamedTemporaryFile(dir=state_dir, prefix=".risklence-write-test-") as handle:
            handle.write(b"risklence")
            handle.flush()
            os.fsync(handle.fileno())
    except OSError as exc:
        return HealthResult("unavailable", "state_dir_not_writable", str(exc))

    try:
        usage = shutil.disk_usage(state_dir)
    except OSError:
        # Writable, but headroom is unknown. Reporting "ready" would overclaim
        # and "unavailable" would be false — the write demonstrably worked.
        return HealthResult("degraded", "free_space_unknown")

    if usage.free < LOW_DISK_BYTES:
        return HealthResult(
            "degraded",
            "low_free_space",
            f"{usage.free // (1024 * 1024)} MB free",
        )
    return HealthResult("ready", None, f"{usage.free // (1024 * 1024)} MB free")


def check_platform_connectivity(*, recent_failures: int, recent_attempts: int) -> HealthResult:
    """How stable this Collector's link to the platform has been.

    **Deliberately not "can I reach the platform right now".** This result is
    delivered *to* the platform, so a report that arrives at all proves current
    reachability, and a genuinely unreachable Collector cannot send anything —
    the interesting state is unreportable through the only channel that would
    carry it. A field defined that way could only ever say ``ready``, which is
    an answer nobody needs.

    What the agent knows and the platform does not is *instability*. The
    platform sees a gap in heartbeats; it cannot tell a Collector that was
    switched off from one whose network kept dropping. This reports that
    difference, and liveness stays where it already works — derived
    platform-side from heartbeat age.
    """
    if recent_attempts <= 0:
        return HealthResult("unknown", "no_attempts_recorded")
    if recent_failures >= UNSTABLE_FAILURE_THRESHOLD:
        return HealthResult(
            "degraded",
            "intermittent_connectivity",
            f"{recent_failures} of the last {recent_attempts} platform calls failed",
        )
    return HealthResult("ready", None, f"{recent_attempts} recent platform calls, {recent_failures} failed")

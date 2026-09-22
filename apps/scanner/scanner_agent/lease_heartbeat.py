"""Proof of life while the Collector is busy, not only while it is idle.

**The gap this closes.** The agent loop heartbeats, polls, and then executes the
whole command *synchronously* before sleeping. A heartbeat is what renews the
platform's worker lease (`worker_lease_renewal_service`), so for the entire
duration of a scan — the one time the Collector is unambiguously alive — it says
nothing at all. A `/24` sweep with version detection takes far longer than the
lease, so the lease expired mid-scan, the job was reclaimed from a healthy
Collector, and the retry did the same thing again.

Søren watched exactly that on 2026-08-25: *"nmap attempt 1 expired, attempt 2
expired, attempt 3 started, and the run never finished."* The server side was
then built to renew a lease while its holder is heartbeating — correct, and it
could never fire, because no heartbeat arrives during the work it was meant to
protect.

**Why a thread rather than heartbeating between stages.** The unit that outlives
the lease is a single nmap invocation, not the gap between two of them; anything
that only ticks between stages still leaves one scan unprotected. The thread is a
daemon and holds no state: if the process dies the heartbeats stop, which is
precisely the signal the lease is there to detect. A Collector that is alive keeps
its lease; one that is gone loses it on the original schedule.

**Failures here are deliberately silent.** A heartbeat that cannot be delivered
must never take down the scan it is protecting — the scan is the valuable thing,
and a missed beat costs at most the same lease expiry that happens today.
"""

from __future__ import annotations

import threading
from collections.abc import Callable
from contextlib import contextmanager
from collections.abc import Iterator

#: How often to prove liveness while a command is running.
#:
#: The platform's ``WORKER_LEASE_DEFAULT_SECONDS`` is 300, so this leaves five
#: beats per lease window — enough that a lost beat, a slow response or a brief
#: network blip cannot expire a lease on its own.
#:
#: ⚠️ Written down twice, which is how the poll interval and the lease came to be
#: the same number in the first place (#322). The Collector should be *told* the
#: lease duration and derive this from it; until it is, this constant must stay
#: comfortably below the platform's.
WORKING_HEARTBEAT_SECONDS = 60


@contextmanager
def heartbeat_while_working(
    send_heartbeat: Callable[[], object],
    *,
    every_seconds: int = WORKING_HEARTBEAT_SECONDS,
    on_error: Callable[[BaseException], None] | None = None,
) -> Iterator[None]:
    """Send ``send_heartbeat()`` every ``every_seconds`` until the block exits.

    The first beat is one interval *after* entry, not immediately: the caller has
    just heartbeated as part of its own cycle, and a duplicate on the same second
    tells the platform nothing it does not already know.
    """
    stop = threading.Event()

    def _beat() -> None:
        while not stop.wait(every_seconds):
            try:
                send_heartbeat()
            except BaseException as exc:  # noqa: BLE001 — see module docstring
                if on_error is not None:
                    try:
                        on_error(exc)
                    except BaseException:  # noqa: BLE001, S110
                        pass

    thread = threading.Thread(target=_beat, name="lease-heartbeat", daemon=True)
    thread.start()
    try:
        yield
    finally:
        stop.set()
        # Bounded: the loop is either waiting on the event, which returns at
        # once, or mid-request, which the client's own timeout ends. A daemon
        # thread cannot hold the process open either way.
        thread.join(timeout=5)

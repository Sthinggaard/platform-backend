"""Operational instructions the platform asks a Collector to carry out (CA-02.3 slice 3).

**Why this is not a discovery command.** ``ScannerCommand`` carries authority to
act on approved *external targets*: it is signed, scope-bound, and NOT NULL on
``discovery_run_id``. An operational instruction touches nothing outside the
Collector itself — a self-check runs local ``--version`` probes — so that
envelope would contribute no security value while forcing a genuinely-required
invariant to be dropped. Two mechanisms here reflect two different kinds of
authority, not a failure to reuse.

**Why the heartbeat carries it.** The Collector polls; the platform cannot push.
The heartbeat is the message it already sends most often, so an instruction
arrives within one interval (30s by default) instead of waiting on a command
poll. No new channel, no new credential, no new route for the agent.

**Why one column and not a queue.** These instructions coalesce by nature. A
user pressing "Run self-check again" five times wants one fresh answer, not five
checks — a queue would faithfully deliver five. It also cannot grow unbounded
while a Collector is offline.

This module owns the request/deliver/complete lifecycle only. What a self-check
*measures* belongs to ``collector_readiness_service``, and the two stay separate
so that adding an instruction never means touching readiness.
"""

from __future__ import annotations

from datetime import timedelta

from sqlalchemy.orm import Session

from src.core.constants.evidence_scanner_enums import CollectorInstruction
from src.core.model_defs.common import utcnow
from src.core.model_defs.evidence_scanner import ScannerInstance

#: How long a pending instruction stays deliverable.
#:
#: It exists because the flag is cleared on *completion*, not on delivery — a
#: Collector that receives an instruction and then dies must not silently lose
#: it. The cost of that choice is that an instruction the Collector cannot carry
#: out would otherwise be redelivered forever, so it expires instead.
#:
#: Fifteen minutes: long enough to survive a restart or a short outage, short
#: enough that nobody is surprised by a self-check firing from a button they
#: pressed before lunch.
INSTRUCTION_TTL = timedelta(minutes=15)


def request_instruction(
    db: Session,
    instance: ScannerInstance,
    *,
    instruction: CollectorInstruction,
    requested_by_user_id: int | None,
) -> ScannerInstance:
    """Ask this Collector to carry out an instruction on its next heartbeat.

    Coalescing: requesting again while one is already pending **refreshes** it
    rather than queueing a second. The later request wins the attribution,
    because that is the person now waiting for an answer on their screen.
    """
    instance.pending_instruction = instruction.value
    instance.pending_instruction_requested_at = utcnow()
    instance.pending_instruction_requested_by_user_id = requested_by_user_id
    db.flush()
    return instance


def _naive(value):
    return value.replace(tzinfo=None) if getattr(value, "tzinfo", None) else value


def pending_instruction_for(instance: ScannerInstance) -> str | None:
    """The instruction to hand this Collector now, or ``None``.

    Returns ``None`` for an expired request rather than deleting it here: this
    is called on the heartbeat path, and a read should not quietly mutate.
    ``clear_instruction`` is the one place that writes.
    """
    if not instance.pending_instruction:
        return None
    requested_at = instance.pending_instruction_requested_at
    if requested_at is None:
        # No timestamp means we cannot tell whether it is stale. Deliver it —
        # a self-check is cheap and harmless, where dropping a real request
        # leaves a user watching a button that did nothing.
        return instance.pending_instruction
    if (_naive(utcnow()) - _naive(requested_at)) > INSTRUCTION_TTL:
        return None
    return instance.pending_instruction


def clear_instruction(db: Session, instance: ScannerInstance) -> ScannerInstance:
    """Mark the pending instruction as dealt with.

    Called when the *result* arrives — a readiness report for a self-check — not
    when the instruction is handed over. Delivery is not evidence that anything
    happened, and this story exists precisely to stop treating one as the other.
    """
    instance.pending_instruction = None
    instance.pending_instruction_requested_at = None
    instance.pending_instruction_requested_by_user_id = None
    db.flush()
    return instance

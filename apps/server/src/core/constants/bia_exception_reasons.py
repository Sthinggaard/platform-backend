"""#463 — why a Business Service's BIA answer differs from its Business Process's.

Søren, 2026-09-15 (option B): a service inherits each process's Business Impact Assessment and
records only where it genuinely differs, with a structured reason. A code, not free text, so
findings can group and count exceptions. "Other" says nothing on its own, so it needs a note.

Served to the tenant rather than restated there, as `SLOT_REJECTION_REASONS` is. The labels are
the ones Søren approved; change them here and nowhere else.
"""

from __future__ import annotations

from enum import Enum


class BiaExceptionReasonCode(str, Enum):
    OWN_WORKAROUND = "own_workaround"
    PART_OF_PROCESS = "part_of_process"
    DIFFERENT_DATA = "different_data"
    DIFFERENT_RECOVERY = "different_recovery"
    CONTRACT_OR_REGULATION = "contract_or_regulation"
    OTHER = "other"


BIA_EXCEPTION_REASON_PROMPT = "Why does this service differ from the process?"

#: (code, label), in the order to offer them.
BIA_EXCEPTION_REASONS: tuple[tuple[str, str], ...] = (
    (BiaExceptionReasonCode.OWN_WORKAROUND.value, "It has its own workaround or alternative"),
    (BiaExceptionReasonCode.PART_OF_PROCESS.value, "It supports only part of the process"),
    (BiaExceptionReasonCode.DIFFERENT_DATA.value, "It handles different data than the process"),
    (BiaExceptionReasonCode.DIFFERENT_RECOVERY.value, "It recovers on a different timeline"),
    (
        BiaExceptionReasonCode.CONTRACT_OR_REGULATION.value,
        "A contract or regulation applies to this service",
    ),
    (BiaExceptionReasonCode.OTHER.value, "Other — explained in a note"),
)

BIA_EXCEPTION_REASON_CODES: frozenset[str] = frozenset(code for code, _ in BIA_EXCEPTION_REASONS)

#: A reason that explains nothing by itself; the owner has to write why.
BIA_EXCEPTION_REASONS_REQUIRING_NOTE: frozenset[str] = frozenset(
    {BiaExceptionReasonCode.OTHER.value}
)

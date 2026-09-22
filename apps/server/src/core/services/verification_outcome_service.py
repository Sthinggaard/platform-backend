"""CA-08.2 — deciding what an inspection attempt *meant*, on the platform.

Søren, 2026-08-24: **the Collector stays naive.** It collects; the engine reads.
This module holds the reading.

It exists because the first cut of #290 put this classification on the Collector,
which broke the pattern the rest of the agent already follows — ``nmap_runner``
returns raw NMAP XML and *the server's evidence adapter parses it*. A Collector
that concludes "this was an authentication failure" is a Collector reaching a
conclusion, and conclusions are the engine's job.

The rule that came out of that conversation, and the reason this file is not
simply "everything moves to the server":

    **The Collector is naive about meaning, and never naive about secrets.**

It must not decide what an artefact is. It must still refuse to transmit what it
must not hold — CA-07.2's rule that the platform *cannot* receive a credential
means redaction happens before the wire, not here. Those are different jobs, and
only the second one belongs on the Collector.

So what arrives here is mechanical and uninterpreted: an exit status, whatever
was written to stderr, and whether the process ever returned at all.
"""

from __future__ import annotations

from src.core.constants.verification_inspection_enums import InspectionOutcome

#: OpenSSH exits 255 for *its own* failures. Any other non-zero status came from
#: the command on the far side, which means the login worked. That single
#: distinction is what lets "we could not get in" be told apart from "we got in
#: and the command failed" — and getting it wrong sends somebody to rotate a key
#: that works.
SSH_OWN_FAILURE = 255

#: Matched against OpenSSH's own messages. Deliberately narrow: an unrecognised
#: failure stays HOST_UNREACHABLE rather than being guessed into a more specific
#: claim the evidence does not support.
_AUTH_FAILURE_MARKERS = (
    "permission denied",
    "too many authentication failures",
    "host key verification failed",
    "no supported authentication methods",
)

#: Only "command not found". A missing *file* also says "no such file or
#: directory", and matching that would report a missing nginx.conf as a missing
#: `cat` — exit 127 already covers a missing binary without the false positive.
_NOT_AVAILABLE_MARKERS = ("command not found",)

_DENIED_ON_HOST_MARKERS = ("permission denied", "operation not permitted")


def classify_inspection_outcome(
    *, exit_code: int | None, stderr: str, timed_out: bool = False
) -> str:
    """What the attempt says about the artefact.

    Every return value describes the *host*, never the platform. CA-08.2's
    criterion is that a failure to authenticate is a fact about the artefact,
    and a fact about the artefact is something a person can act on.
    """
    if timed_out:
        return InspectionOutcome.TIMED_OUT.value
    if exit_code is None:
        # No status and no timeout: the attempt never produced a result we can
        # read. Not claimed as anything more specific.
        return InspectionOutcome.HOST_UNREACHABLE.value
    if exit_code == 0:
        return InspectionOutcome.SUCCEEDED.value

    lowered = (stderr or "").lower()

    if exit_code == SSH_OWN_FAILURE:
        if any(marker in lowered for marker in _AUTH_FAILURE_MARKERS):
            return InspectionOutcome.AUTHENTICATION_FAILED.value
        return InspectionOutcome.HOST_UNREACHABLE.value

    # Past this point the login succeeded, so everything describes the host.
    if exit_code == 127 or any(marker in lowered for marker in _NOT_AVAILABLE_MARKERS):
        return InspectionOutcome.COMMAND_NOT_AVAILABLE.value
    if any(marker in lowered for marker in _DENIED_ON_HOST_MARKERS):
        return InspectionOutcome.PERMISSION_DENIED_ON_HOST.value

    # It ran, it failed, and we cannot say why. Claiming a permissions problem
    # here would send somebody to fix an access control when the real answer
    # might be that the file simply is not there.
    return InspectionOutcome.COMMAND_FAILED.value

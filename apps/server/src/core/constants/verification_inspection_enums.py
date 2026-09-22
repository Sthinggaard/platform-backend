"""CA-08.3 (#291) — the vocabulary of an inspection that was allowed to run.

Søren chose **option C** on 2026-08-24 (see
``tasks/active/CA-08-Q3-capability-vocabulary-decision.md``): a capability names
a **command template the server resolves per platform and signs**, and the
Collector runs only what verifies. The boundary is structural because an
unsigned command cannot run — not because the Collector intends to stay inside
it.

The two rejected options are worth keeping visible, because the shape of this
module only makes sense against them. Option A pinned each capability to one
exact command and paid a code change per distribution. Option B let the
Collector choose its own command and would have made *"technical evidence cannot
exceed the approved access boundary"* a promise rather than a property — a
compromised Collector would have been unbounded, and the audit trail could only
ever have said what was *asked for*, never what ran.

**No vocabulary is invented here.** ``ConnectorCapability`` already describes
what deeper access may read on a host, which is deep verification's question,
and the reuse-first rule forbids a third capability enum beside it and
``DiscoveryCapability``. #291's criterion reads *"a verification capability is
not a discovery capability and not a connector capability"*; the disjointness it
protects is from ``DiscoveryCapability``, which is discovery-run-shaped and maps
onto ``ScannerProfile``'s flags. Building ``VerificationCapability`` with the
same eight members would be the duplicate the programme forbids — recorded here
rather than resolved silently.
"""

from enum import StrEnum


class VerificationPlatform(StrEnum):
    """What a host is, to the precision the command templates need.

    Deliberately coarse. This is not an OS inventory — it is the smallest set
    that decides which command answers a capability, and a member only earns its
    place by making some template differ.

    There is **no** ``UNKNOWN``. A host whose platform was never determined has
    no resolvable template, and the honest behaviour is to refuse and say so —
    the same distinction ``ArtefactIdentityUndetermined`` already draws between
    *we looked and could not tell* and *we never looked*. An ``UNKNOWN`` member
    would invite a fallback command, and a fallback command is how a bounded
    inspection quietly becomes an unbounded one.
    """

    DEBIAN = "debian"
    RHEL = "rhel"
    ALPINE = "alpine"


#: Used as a template key for capabilities whose command genuinely does not vary
#: by platform. Not a member of the enum: it is a property of a *template*, not
#: a kind of host, and putting it in the enum would let a caller claim to be
#: running on "any".
PLATFORM_ANY = "any"


#: Domain separation for the signature. The signing key is the per-instance key
#: derived at activation and shared with discovery — deliberately, because a
#: second key would be a second thing to rotate, revoke and lose. Signing a
#: different payload shape with the same key **without** a distinct domain would
#: let a discovery command's signature be presented as a verification command's,
#: or the reverse. This string is part of every signed payload, so the two can
#: never be confused.
VERIFICATION_COMMAND_SIGNATURE_VERSION = "v1-verification"

#: How long a signed inspection stays valid. Short on purpose: a signed command
#: is a bearer instruction to read something on a customer's host, and one that
#: stays valid for a day is one that can be replayed for a day. Discovery's
#: envelope makes the same argument at a longer horizon because a discovery run
#: is long; a single inspection is not.
VERIFICATION_COMMAND_EXPIRY_SECONDS = 300


class InspectionCommandStatus(StrEnum):
    """Where a queued inspection is on its way to and from a Collector.

    Mirrors ``ScannerCommandStatus``'s shape rather than inventing a lifecycle:
    an operator debugging a stuck Collector should not have to learn two.
    """

    PENDING = "pending"
    DELIVERED = "delivered"
    #: The Collector ran it and reported. Whether the *host* cooperated is
    #: ``outcome``'s business — a command that came back saying "permission
    #: denied" completed perfectly well as a command.
    COMPLETED = "completed"
    #: The Collector refused it — bad signature, wrong instance, expired.
    REJECTED = "rejected"
    #: Nobody collected it in time.
    EXPIRED = "expired"


INSPECTION_COMMAND_TERMINAL = (
    InspectionCommandStatus.COMPLETED.value,
    InspectionCommandStatus.REJECTED.value,
    InspectionCommandStatus.EXPIRED.value,
)


class InspectionOutcome(StrEnum):
    """How an inspection ended — as a fact about the artefact, not about us.

    CA-08.2's criterion: *a failure to authenticate is reported as a fact about
    the artefact, not as a platform error.* "We could not log in to this host"
    is something the organisation needs to know and act on; "the platform threw
    an exception" is not the same statement and must not be able to impersonate
    it.

    The Collector mirrors these values in
    ``scanner_agent/host_inspection.py``. They are duplicated across that
    boundary on purpose and must match exactly — the Collector bundle is
    deliberately dependency-free from the server (CA-03), which is the same
    reason ``CommandRejectionCode`` is mirrored in ``command_signing.py``
    rather than imported.
    """

    #: It ran and produced output.
    SUCCEEDED = "succeeded"
    #: The host answered and refused the credential. The single most useful
    #: failure to report, because it is actionable by a person.
    AUTHENTICATION_FAILED = "authentication_failed"
    #: Nothing answered at the address and port at all.
    HOST_UNREACHABLE = "host_unreachable"
    #: Logged in, and the account may not read what was asked for. Distinct
    #: from AUTHENTICATION_FAILED: the credential was accepted, the access was
    #: not — a different conversation with a different person.
    PERMISSION_DENIED_ON_HOST = "permission_denied_on_host"
    #: The approved command is not installed there. A fact about how the host is
    #: built, not a failure of the inspection.
    COMMAND_NOT_AVAILABLE = "command_not_available"
    #: It logged in, the command ran, and it exited non-zero for a reason we
    #: cannot classify — a missing file, an unreadable path, an unhappy tool.
    #: Its own member rather than being folded into PERMISSION_DENIED_ON_HOST:
    #: reporting "you have a permissions problem" when the real answer is "that
    #: file is not there" sends somebody to fix the wrong thing.
    COMMAND_FAILED = "command_failed"
    TIMED_OUT = "timed_out"


#: Outcomes that say something about the artefact rather than about a run. #293
#: turns these into what a person reads; none of them is a platform error.
INSPECTION_ARTEFACT_FACTS = (
    InspectionOutcome.AUTHENTICATION_FAILED.value,
    InspectionOutcome.HOST_UNREACHABLE.value,
    InspectionOutcome.PERMISSION_DENIED_ON_HOST.value,
    InspectionOutcome.COMMAND_NOT_AVAILABLE.value,
    # Added with the member itself. A test asserts this tuple covers every
    # non-success outcome bar TIMED_OUT, so a member added without a line here
    # fails rather than quietly dropping out of what the surface reports.
    InspectionOutcome.COMMAND_FAILED.value,
)


# --- Audit events ---------------------------------------------------------

#: The interesting record, per CA-08.3's own criterion: *an inspection that would
#: exceed the profile is refused **and audited** — the attempt is the interesting
#: record.* Refusals inside the enforcement point already raise
#: ``permission_profile_capability_denied``; this fires for the refusals that
#: happen after permission passed, where the reason is the template, not policy.
VERIFICATION_INSPECTION_AUDIT_REFUSED = "verification_inspection_refused"
VERIFICATION_INSPECTION_AUDIT_AUTHORISED = "verification_inspection_authorised"
#: What the Collector came back with. Separate from AUTHORISED so the trail can
#: answer "we allowed this" and "this is what happened" independently — an
#: inspection that was authorised and never reported is its own kind of problem.
VERIFICATION_INSPECTION_AUDIT_REPORTED = "verification_inspection_reported"

# CA-08.4 — what the run established, as its own events. "It ran" and "it
# learned something" are different facts, and an auditor asks the second.
VERIFICATION_IDENTITY_AUDIT_DETERMINED = "verification_identity_determined"
#: An empty result is a finding, not a gap — so it is recorded, not skipped.
VERIFICATION_IDENTITY_AUDIT_UNDETERMINED = "verification_identity_undetermined"
#: The output was never carried off the Collector, because this capability can
#: return a credential and redaction does not exist yet (#296). Audited so a
#: successful run that established nothing cannot be mistaken for one where the
#: platform looked and found nothing.
VERIFICATION_IDENTITY_AUDIT_OUTPUT_WITHHELD = "verification_identity_output_withheld"


# --- Errors ---------------------------------------------------------------

VERIFICATION_INSPECTION_ERROR_RUN_NOT_OPEN = (
    "This verification run has finished, so nothing further may be inspected under it"
)
VERIFICATION_INSPECTION_ERROR_NO_TEMPLATE = (
    "'{capability}' has no approved way to be read on a {platform} host, so it cannot run there"
)
VERIFICATION_INSPECTION_ERROR_NOT_A_HOST_READ = (
    "'{capability}' is not something read by inspecting a host, so deep verification has no "
    "command for it"
)
VERIFICATION_INSPECTION_ERROR_UNKNOWN_PLATFORM = (
    "This host's platform was never determined, so there is no approved command for it. "
    "Guessing one would be an inspection nobody bounded"
)
VERIFICATION_INSPECTION_ERROR_UNKNOWN_PARAMETER = (
    "'{parameter}' is not part of the approved command for '{capability}'"
)
VERIFICATION_INSPECTION_ERROR_MISSING_PARAMETER = (
    "The approved command for '{capability}' needs '{parameter}', which was not supplied"
)
VERIFICATION_INSPECTION_ERROR_BAD_PARAMETER = (
    "'{parameter}' is not in a shape the approved command accepts"
)
VERIFICATION_INSPECTION_ERROR_UNKNOWN_CONFIG_TARGET = (
    "'{target}' is not a configuration file this platform is approved to read. The approved "
    "set is named here, and never supplied by the caller"
)
VERIFICATION_INSPECTION_ERROR_NO_SIGNING_KEY = (
    "This Collector has no signing key, so no command can be issued to it that it could prove "
    "came from us"
)

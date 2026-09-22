"""CA-07.4 — proving access works, in words an operator can act on.

**A connection test is not verification.** CA-07's headline rule is that access
never starts verification, and this is the line: a test proves the pipe is open
and the granted permissions are sufficient. It reads nothing about the estate,
produces no evidence, and reaches no conclusion about risk. CA-08 does that,
separately and with its own human approval.

**The platform does not perform the test.** Credentials are local to the
Collector (CA-07.2), so the platform *requests* a test and the Collector reports
the outcome — the same shape as ``record_test_scan_result``, which already
records what the agent reported rather than what the server observed.

The failure vocabulary below is the point of the story's fourth criterion. A
test that fails with "connection error" tells an operator nothing; each code
here maps to something a person can actually go and change.
"""

from enum import StrEnum


class ConnectorAccessTestStatus(StrEnum):
    REQUESTED = "requested"
    SUCCEEDED = "succeeded"
    FAILED = "failed"
    # The Collector never came back. Distinct from FAILED: "we asked and heard
    # nothing" and "we asked and it said no" send an operator to different
    # places.
    EXPIRED = "expired"


class ConnectorAccessTestFailure(StrEnum):
    """Why a test failed, in terms that name the thing to fix.

    Every member answers "what would I go and do about this?". Codes that could
    only be answered with "look at the logs" are deliberately absent.
    """

    # Network / addressing — the host did not answer at all.
    HOST_UNREACHABLE = "host_unreachable"
    PORT_CLOSED = "port_closed"
    DNS_UNRESOLVED = "dns_unresolved"
    TLS_UNTRUSTED = "tls_untrusted"
    # Identity — we reached it and it would not let us in.
    AUTHENTICATION_REJECTED = "authentication_rejected"
    CREDENTIAL_MISSING_ON_COLLECTOR = "credential_missing_on_collector"
    CREDENTIAL_EXPIRED = "credential_expired"
    # Authorisation — we got in, and the account cannot do what was granted.
    # The distinction that makes "permission adequacy" a separate answer from
    # "reachability": a Connector can be perfectly reachable and still useless.
    PERMISSION_INSUFFICIENT = "permission_insufficient"
    DOCKER_SOCKET_UNAVAILABLE = "docker_socket_unavailable"
    # Ours, not theirs.
    NO_APPROVED_PERMISSION_PROFILE = "no_approved_permission_profile"
    CONNECTOR_NOT_ACTIVE = "connector_not_active"


# What an operator should do about each failure. Kept beside the codes so a
# surface can explain a failure without inventing its own wording, and so the
# claim "in terms an operator can act on" is checkable rather than aspirational.
CONNECTOR_ACCESS_TEST_REMEDIES: dict[str, str] = {
    ConnectorAccessTestFailure.HOST_UNREACHABLE.value: (
        "The host did not answer. Check it is running and that the Collector's network can reach it."
    ),
    ConnectorAccessTestFailure.PORT_CLOSED.value: (
        "The host answered but the port is closed. Check the service is listening and that a "
        "firewall rule allows the Collector."
    ),
    ConnectorAccessTestFailure.DNS_UNRESOLVED.value: (
        "The hostname could not be resolved. Check the name is correct and resolvable from the "
        "Collector."
    ),
    ConnectorAccessTestFailure.TLS_UNTRUSTED.value: (
        "The certificate was not trusted. Check the certificate chain, or add the internal "
        "authority to the Collector's trust store."
    ),
    ConnectorAccessTestFailure.AUTHENTICATION_REJECTED.value: (
        "The host refused the credential. Check the account exists and the key on the Collector is "
        "the one the host expects."
    ),
    ConnectorAccessTestFailure.CREDENTIAL_MISSING_ON_COLLECTOR.value: (
        "The Collector has no credential for this Connector. Install it on the Collector — the "
        "platform never holds one."
    ),
    ConnectorAccessTestFailure.CREDENTIAL_EXPIRED.value: (
        "The credential has expired. Rotate it on the Collector and register the new fingerprint."
    ),
    ConnectorAccessTestFailure.PERMISSION_INSUFFICIENT.value: (
        "Access worked, but the account cannot do everything the approved profile grants. Either "
        "widen the account's rights on the host, or approve a narrower profile."
    ),
    ConnectorAccessTestFailure.DOCKER_SOCKET_UNAVAILABLE.value: (
        "The Docker socket could not be read. Check the socket path and that the account is in the "
        "group permitted to read it."
    ),
    ConnectorAccessTestFailure.NO_APPROVED_PERMISSION_PROFILE.value: (
        "No approved permission profile exists for this Connector, so there is nothing to test. "
        "Define one and have it approved first."
    ),
    ConnectorAccessTestFailure.CONNECTOR_NOT_ACTIVE.value: (
        "This Connector is paused, revoked or disconnected, so it is not in use. Resume it first if "
        "it should be."
    ),
}


# How long the platform waits for a Collector before calling a test EXPIRED.
# A request that stays "requested" forever is the worst of the three outcomes:
# it looks like work in progress and is actually silence.
ACCESS_TEST_TIMEOUT_MINUTES = 15


TEST_AUDIT_REQUESTED = "connector_access_test_requested"
TEST_AUDIT_RESULT_RECORDED = "connector_access_test_result_recorded"
TEST_AUDIT_EXPIRED = "connector_access_test_expired"

TEST_ERROR_NOT_FOUND = "Access test not found"
TEST_ERROR_ALREADY_COMPLETE = "This access test has already reported a result"
TEST_ERROR_UNKNOWN_FAILURE_CODE = "Unknown failure code: {code}"
TEST_ERROR_FAILURE_CODE_REQUIRED = (
    "A failed test must say what failed, so the operator is told something they can act on"
)
TEST_ERROR_NO_PROFILE = (
    "This Connector has no approved permission profile, so there is nothing to test yet"
)
TEST_ERROR_ALREADY_PENDING = (
    "A test of this Connector is already waiting on the Collector. Wait for it to report, or for "
    f"it to time out after {ACCESS_TEST_TIMEOUT_MINUTES} minutes"
)
# The Collector may only confirm capabilities the approved profile actually
# granted. A Collector reporting something outside the profile is either
# confused or exceeding its grant, and neither should be recorded as fact.
TEST_ERROR_CAPABILITY_NOT_IN_PROFILE = (
    "'{capability}' is not in the approved permission profile this test was run against"
)

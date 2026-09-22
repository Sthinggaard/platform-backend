"""CA-07.2 — Connector types, credential models, and the words for what is *not* held.

The contract: *"Support restricted SSH, read-only Docker and service Connectors;
keep credentials local and platform-visible metadata only."*

**The trap this module exists to avoid.** The repository holds two contradictory
credential patterns, and the obvious one to reuse is the one the contract
forbids. ``CloudCredentials`` + ``crypto.CredentialEncryption`` is complete,
tested, and stores secrets the platform can decrypt — so an engineer reaching for
"we already have credential encryption" violates the contract *while appearing to
reuse correctly*. The right precedent is ``ScannerCredential``, which persists
only ``token_hash``.

**This story goes further than that precedent, deliberately.** ``ScannerCredential``
receives a raw token and hashes it. A Connector's credential is never received at
all: it is registered by *fingerprint*, computed wherever the credential already
lives. A secret the platform accepts has existed in a request body, in process
memory, and in anything that traced or logged the request — hashing it on arrival
is too late to make the claim "credentials never reach the platform" true.

So the rule enforced here is structural rather than procedural: **no field on any
Connector schema or column may carry secret material**, asserted by a test that
inspects the shapes themselves rather than trusting a reviewer to notice.
"""

from enum import StrEnum


class AccessConnectorType(StrEnum):
    """The three Connector types the CA-07 checklist names."""

    # A restricted shell account — command-limited, not a general login.
    SSH_RESTRICTED = "ssh_restricted"
    # Read-only Docker inspection. Socket access needs its own explicit
    # approval per the contract's own rule; that approval is CA-07.3's
    # permission profile, not something this record grants.
    DOCKER_READONLY = "docker_readonly"
    # An application or platform API reached as a service principal.
    SERVICE = "service"


class ConnectorCredentialModel(StrEnum):
    """Where the credential actually lives — the organisation's decision, not ours.

    Set by CA-07.0's approved operating mode rather than chosen per Connector:
    Mode A (scheduled autonomous) has nobody present at run time, so the
    credential must be resident on the Collector; Mode B (process-triggered) has
    a person present and can supply one per run that is never stored anywhere.

    In **both** cases the platform holds no recoverable secret. In Mode A the
    Collector does; in Mode B nothing durable exists at all.
    """

    COLLECTOR_RESIDENT = "collector_resident"
    OPERATOR_SUPPLIED = "operator_supplied"


class AccessConnectorStatus(StrEnum):
    """The three withdrawal verbs are distinct, and the distinction is the point.

    CA-07.4's criterion is that pause, revoke and disconnect *behave* distinctly.
    They answer different questions and an operator needs to be able to tell
    which happened months later:

    - ``PAUSED`` — temporarily not in use. Resumable. The grant still stands.
    - ``REVOKED`` — the authorisation is withdrawn. A governance act, permanent,
      and **not deletion**: the record of what was granted survives it.
    - ``DISCONNECTED`` — the technical link is gone; the Collector no longer
      holds the credential. An operational act, which can happen without
      revocation (a rebuilt Collector) just as revocation can happen while the
      credential is still sitting on the Collector awaiting cleanup.
    """

    CONFIGURED = "configured"
    PAUSED = "paused"
    REVOKED = "revoked"
    DISCONNECTED = "disconnected"


# A Connector in any of these states must not be used. Enforcement reads this,
# so revoking actually stops access rather than only recording an intention.
ACCESS_CONNECTOR_INOPERABLE_STATUSES = (
    AccessConnectorStatus.PAUSED.value,
    AccessConnectorStatus.REVOKED.value,
    AccessConnectorStatus.DISCONNECTED.value,
)


# A fingerprint identifies *which* credential is in use without being one.
# Bounded so an oversized blob (a pasted private key, say) cannot masquerade as
# a fingerprint and get itself persisted.
CONNECTOR_FINGERPRINT_MIN_LENGTH = 16
CONNECTOR_FINGERPRINT_MAX_LENGTH = 128

# Field-name fragments that must never appear on a Connector schema or column.
# Checked structurally by test_access_connector.py against the real Pydantic
# models and the real SQLAlchemy table — a reviewer noticing is not a control.
CONNECTOR_FORBIDDEN_FIELD_FRAGMENTS = (
    "password",
    "passphrase",
    "secret",
    "private_key",
    "privatekey",
    "token",
    "credential_value",
    "raw_credential",
    "encrypted",
    "api_key",
)


# --- Audit events ---------------------------------------------------------

CONNECTOR_AUDIT_CREATED = "access_connector_created"
CONNECTOR_AUDIT_CREDENTIAL_REGISTERED = "access_connector_credential_registered"
CONNECTOR_AUDIT_CREDENTIAL_ROTATED = "access_connector_credential_rotated"
# CA-07.4. Separate events per verb, because a trail that recorded them all as
# "connector changed" would lose exactly the distinction the verbs exist to make.
CONNECTOR_AUDIT_PAUSED = "access_connector_paused"
CONNECTOR_AUDIT_RESUMED = "access_connector_resumed"
CONNECTOR_AUDIT_REVOKED = "access_connector_revoked"
CONNECTOR_AUDIT_DISCONNECTED = "access_connector_disconnected"


# --- Errors ---------------------------------------------------------------

CONNECTOR_ERROR_ADMIN_REQUIRED = (
    "Organisation administrator access is required to configure a Connector"
)
CONNECTOR_ERROR_NOT_FOUND = "Connector not found"
CONNECTOR_ERROR_SCANNER_NOT_FOUND = "Collector not found"
# CA-07.0 gates this story. An operating mode nobody approved cannot be inferred
# from the fact that somebody is configuring a Connector.
CONNECTOR_ERROR_NO_OPERATING_MODE = (
    "Your organisation has not decided how deeper access operates. That decision comes first, "
    "because it determines where the credential is allowed to live"
)
CONNECTOR_ERROR_MODE_A_REQUIRES_RESIDENT_CREDENTIAL = (
    "Scheduled autonomous access runs with nobody present, so an operator cannot supply a "
    "credential at run time — it must be resident on the Collector"
)
CONNECTOR_ERROR_FINGERPRINT_REQUIRED = (
    "A Collector-resident credential must be registered by fingerprint, so the platform can say "
    "which credential is in use without ever holding it"
)
CONNECTOR_ERROR_FINGERPRINT_NOT_PERMITTED = (
    "An operator-supplied credential is never stored, so there is no fingerprint to register"
)
CONNECTOR_ERROR_FINGERPRINT_MALFORMED = (
    f"A credential fingerprint must be {CONNECTOR_FINGERPRINT_MIN_LENGTH}-"
    f"{CONNECTOR_FINGERPRINT_MAX_LENGTH} characters of fingerprint text "
    "(hex, base64 or colon-separated), never the credential itself"
)
CONNECTOR_ERROR_TARGET_REQUIRED = "A Connector must say what it reaches"


# --- CA-07.4 lifecycle errors ---------------------------------------------

CONNECTOR_ERROR_NOT_CONFIGURED = "Only a configured Connector can be paused"
CONNECTOR_ERROR_NOT_PAUSED = "Only a paused Connector can be resumed"
# Revocation is permanent by design. Offering a way back would make it
# indistinguishable from pause, and the two mean very different things.
CONNECTOR_ERROR_ALREADY_REVOKED = "This Connector is already revoked"
CONNECTOR_ERROR_REVOKED_CANNOT_RESUME = (
    "A revoked Connector cannot be resumed — revocation is permanent. Configure a new Connector "
    "if access should be granted again"
)
CONNECTOR_ERROR_REVOCATION_REASON_REQUIRED = (
    "Revoking access is permanent, so it must say why — that reason is what an auditor reads "
    "years later, long after everyone involved has forgotten"
)
CONNECTOR_ERROR_ALREADY_DISCONNECTED = "This Connector is already disconnected"
CONNECTOR_ERROR_INOPERABLE = (
    "This Connector is {status} and may not be used"
)

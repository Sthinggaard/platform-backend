"""CA-07.3 — a named, bounded set of capabilities that a person approved.

The contract: *"Define/approve permission profiles… Docker socket access needs
explicit approval."*

**What already exists, and why none of it is this.** `permission_profile` on
`DiscoveryScopeProposal:49` is a JSONB `{"capabilities": [...]}` bag: a precedent,
not an approvable object, attached to a discovery proposal rather than to access,
and enforced by nothing. `PermissionPreset` (`assets_runtime.py`) is a cloud-asset
connection preset — a different concern entirely. Flat roles cover who may *use*
the platform, never what a Connector may *do*.

**This is Epic C4's model, landing here.** The programme roadmap owns
`PermissionProfile` under C4 — *"missing — no PermissionProfile model; only flat
roles today"*, rated High security, and described as defining *"what a
Collector/connector may do"*. D6 is blocked on it; C5 needs its approval
condition.

That matters because `discovery_scope_proposal_enums` already records a narrow
capability bag shipped under time pressure with the note *"when C4 lands it should
absorb this rather than sit beside it."* Building a second, connector-only profile
now would repeat that and leave three permission models to reconcile. So there is
**one** first-class model: C4's shape (defined, approved, versioned, enforced),
scoped in this story to one Connector. Widening the subject later is a migration,
not a rewrite.

The capability vocabulary here is deliberately **disjoint** from
`DiscoveryCapability`, which is discovery-run-shaped and maps one-to-one onto
`ScannerProfile`'s flags. These describe what deeper access may *read on a host* —
a different question, and merging them would blur two grants into one.
"""

from enum import StrEnum


class ConnectorCapability(StrEnum):
    """What deeper access may read — each answers something the network cannot.

    Every member is a **read**. There is deliberately no write, execute, or
    install capability: CA-07 grants the ability to look, and the product's own
    rule is that the system never fixes anything automatically.

    **The rule for joining this enum** (Søren, 2026-08-24, on admitting
    ``READ_LISTENING_SOCKET_OWNER``): *a member may only join if it answers a
    question no existing member answers.* A vocabulary that grows by one
    reasonable-looking member at a time ends at thirty, and every member is
    something a person must understand before approving a profile — an approval
    nobody understands is a rubber stamp. Adding a member is a review question,
    not a convenience.
    """

    # Answers "what is actually installed here?", which a port scan cannot.
    READ_INSTALLED_PACKAGES = "read_installed_packages"
    READ_OS_VERSION = "read_os_version"
    READ_RUNNING_PROCESSES = "read_running_processes"
    #: Which process holds a listening port — the read that answers #249, where
    #: 8080 reads `http-proxy` whether it is Plane, Jenkins or a coffee machine.
    #: Admitted because nothing above authorises it: a process list says what is
    #: running, never which process holds which port. It is also far narrower
    #: than READ_RUNNING_PROCESSES, whose output carries every command line on
    #: the host — and command lines routinely carry secrets. Once this answers
    #: identity, READ_RUNNING_PROCESSES becomes the exception somebody argues
    #: for rather than the default granted to get started.
    READ_LISTENING_SOCKET_OWNER = "read_listening_socket_owner"
    # Configuration as deployed, not as documented. Needs its own approval —
    # see SERVICE_CONFIG_CAPABILITIES and PROFILE_SERVICE_CONFIG_* below.
    READ_SERVICE_CONFIG = "read_service_config"
    # Docker, read-only. Socket access is a separate approval, not a capability —
    # see PROFILE_DOCKER_SOCKET_* below.
    LIST_CONTAINERS = "list_containers"
    INSPECT_CONTAINER = "inspect_container"
    READ_IMAGE_METADATA = "read_image_metadata"
    # Service connectors: what the API says it exposes.
    READ_API_INVENTORY = "read_api_inventory"


class PermissionSubjectKind(StrEnum):
    """What kind of thing a permission subject stands for.

    Descriptive rather than load-bearing: integrity comes from the foreign keys
    on either side of `permission_subjects`, not from this string. Adding a kind
    here plus a `permission_subject_id` on its table is the entire cost of
    permissioning a new kind of thing.
    """

    ACCESS_CONNECTOR = "access_connector"
    DISCOVERY_SCOPE_PROPOSAL = "discovery_scope_proposal"


class PermissionProfileStatus(StrEnum):
    """Same governance lifecycle as the rest of CA-07.

    A profile is not in force until a person approved it, and changing one means
    approving a new version rather than editing the old — otherwise "what was
    permitted, and who said so?" stops being answerable.
    """

    DRAFT = "draft"
    AWAITING_APPROVAL = "awaiting_approval"
    ACTIVE = "active"
    SUPERSEDED = "superseded"
    WITHDRAWN = "withdrawn"


PERMISSION_PROFILE_ACTIVE_STATUSES = (PermissionProfileStatus.ACTIVE.value,)


# --- Audit events ---------------------------------------------------------

PROFILE_AUDIT_DRAFTED = "permission_profile_drafted"
PROFILE_AUDIT_SUBMITTED = "permission_profile_submitted_for_approval"
PROFILE_AUDIT_APPROVED = "permission_profile_approved"
PROFILE_AUDIT_REJECTED = "permission_profile_rejected"
# Deliberately its own event. The contract makes Docker socket access a separate
# decision, and an audit trail that could not distinguish it from ordinary
# profile approval would lose exactly the distinction the rule exists to create.
PROFILE_AUDIT_DOCKER_SOCKET_APPROVED = "permission_profile_docker_socket_approved"
# Same reasoning as the Docker socket event, for the same reason (Søren,
# 2026-08-24): configuration as deployed is where credentials live, so granting
# it is its own decision and must be its own line in the audit trail.
PROFILE_AUDIT_SERVICE_CONFIG_APPROVED = "permission_profile_service_config_approved"
PROFILE_AUDIT_CAPABILITY_DENIED = "permission_profile_capability_denied"


# --- Errors ---------------------------------------------------------------

PROFILE_ERROR_ADMIN_REQUIRED = (
    "Organisation administrator access is required to prepare a permission profile"
)
PROFILE_ERROR_APPROVER_REQUIRED = (
    "Only the organisation's named leadership sponsor may approve a permission profile"
)
PROFILE_ERROR_NOT_FOUND = "Permission profile not found"
PROFILE_ERROR_SUBJECT_NOT_FOUND = "Permission subject not found"
PROFILE_ERROR_NO_CAPABILITIES = (
    "A permission profile must name at least one capability — an empty profile grants nothing "
    "and would be approved as though it granted something"
)
PROFILE_ERROR_UNKNOWN_CAPABILITY = "Unknown capability: {capability}"
PROFILE_ERROR_NOT_AWAITING_APPROVAL = "Only a profile awaiting approval can be approved or rejected"
PROFILE_ERROR_NOT_DRAFT = "Only a draft permission profile can be submitted"
PROFILE_ERROR_NO_ACTIVE_PROFILE = (
    "This Connector has no approved permission profile, so it may do nothing at all"
)
PROFILE_ERROR_CAPABILITY_NOT_PERMITTED = (
    "'{capability}' is outside this Connector's approved permission profile"
)
# The contract's own rule, and the one most likely to be lost in implementation:
# approving a Docker Connector's profile is not approving access to the socket.
PROFILE_ERROR_DOCKER_SOCKET_NOT_APPROVED = (
    "Docker socket access needs its own explicit approval — approving this Connector's "
    "permission profile did not grant it"
)
PROFILE_ERROR_DOCKER_SOCKET_NOT_REQUIRED = (
    "This Connector does not declare that it needs Docker socket access, so there is nothing "
    "to approve"
)

# Søren, 2026-08-24: read_service_config stays in CA-08's scope, under the same
# treatment the Docker socket already has. Configuration as deployed is where
# credentials live, and approving a profile must not hand that over by the same
# click that granted "read the OS version".
PROFILE_ERROR_SERVICE_CONFIG_NOT_APPROVED = (
    "Reading deployed configuration needs its own explicit approval — approving this "
    "Connector's permission profile did not grant it"
)

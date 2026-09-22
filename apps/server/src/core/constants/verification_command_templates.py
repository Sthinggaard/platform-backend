"""CA-08.3 (#291) — the one place that says what a capability actually runs.

Option C's registry: ``capability → platform → argv``. Nothing else in the
codebase may decide what an inspection executes, and nothing outside this module
constructs a command.

Three properties hold by construction, and each is load-bearing:

1. **Commands are argv tuples, never shell strings.** There is no shell, so
   there is no quoting to get wrong, no globbing, no ``;``, no ``$(…)``. A
   capability cannot be widened by a cleverly shaped parameter, because a
   parameter is one element of a list rather than text spliced into a sentence.
2. **Parameters are named, few, and pattern-checked** (``_PARAMETER_PATTERNS``).
   A template that takes free text would be an arbitrary-read capability wearing
   a bounded capability's name.
3. **No path ever comes from the caller.** ``read_service_config`` is the
   capability Søren singled out — deployed configuration is where credentials
   live — so it names *targets*, and the target names resolve to absolute paths
   held here. A caller asks for ``nginx``; it can never ask for
   ``/proc/self/environ``.

**``read_api_inventory`` deliberately has no template.** It is not read by
inspecting a host — it asks a service's own API what it exposes, over the
network, which is a different execution path with a different boundary. Leaving
it out means an attempt to inspect it through this path is refused rather than
quietly mapped onto some command that looked close enough. That refusal has its
own error (``…_ERROR_NOT_A_HOST_READ``) so the reason survives to whoever reads
the audit trail.
"""

from __future__ import annotations

import re

from src.core.constants.permission_profile_enums import ConnectorCapability
from src.core.constants.verification_inspection_enums import (
    PLATFORM_ANY,
    VerificationPlatform,
)

_DEBIAN = VerificationPlatform.DEBIAN.value
_RHEL = VerificationPlatform.RHEL.value
_ALPINE = VerificationPlatform.ALPINE.value


#: capability → platform → argv. ``PLATFORM_ANY`` means the command genuinely
#: does not differ; it is not a fallback for a platform we failed to determine.
COMMAND_TEMPLATES: dict[str, dict[str, tuple[str, ...]]] = {
    ConnectorCapability.READ_OS_VERSION.value: {
        PLATFORM_ANY: ("cat", "/etc/os-release"),
    },
    # The one capability where the platform genuinely decides the command, and
    # the reason option A was rejected: three package managers, three answers.
    ConnectorCapability.READ_INSTALLED_PACKAGES.value: {
        _DEBIAN: ("dpkg-query", "-W", "-f=${Package}\t${Version}\n"),
        _RHEL: ("rpm", "-qa", "--qf", "%{NAME}\t%{VERSION}\n"),
        _ALPINE: ("apk", "info", "-v"),
    },
    # `comm` and not `args`, deliberately. The full command line is what makes
    # this capability dangerous — anything started with `--password=…` is
    # visible to whoever can read the process table — and the identifying
    # information is the executable name. A capability that returns secrets it
    # did not need is a capability that will one day leak them.
    ConnectorCapability.READ_RUNNING_PROCESSES.value: {
        PLATFORM_ANY: ("ps", "-eo", "pid,ppid,comm"),
    },
    # #249's answer: which process holds the listening port. `-H` drops the
    # header so the output is data rather than a table to parse around.
    ConnectorCapability.READ_LISTENING_SOCKET_OWNER.value: {
        PLATFORM_ANY: ("ss", "-ltnpH"),
    },
    ConnectorCapability.LIST_CONTAINERS.value: {
        PLATFORM_ANY: (
            "docker",
            "ps",
            "--no-trunc",
            "--format",
            "{{.ID}}\t{{.Image}}\t{{.Names}}\t{{.Ports}}",
        ),
    },
    ConnectorCapability.INSPECT_CONTAINER.value: {
        PLATFORM_ANY: ("docker", "container", "inspect", "{container_id}"),
    },
    ConnectorCapability.READ_IMAGE_METADATA.value: {
        PLATFORM_ANY: ("docker", "image", "inspect", "{image_id}"),
    },
    ConnectorCapability.READ_SERVICE_CONFIG.value: {
        PLATFORM_ANY: ("cat", "{config_path}"),
    },
}


#: Capabilities that exist, and are deliberately not readable through host
#: inspection. Named rather than merely absent, so the refusal can say *why*
#: instead of "no template" — see the module docstring.
NOT_A_HOST_READ: frozenset[str] = frozenset(
    {ConnectorCapability.READ_API_INVENTORY.value}
)


#: The approved configuration files, by the name a caller may ask for. This is
#: the whole of what ``read_service_config`` can reach. Growing it is a review
#: question — each entry hands the platform a file that may contain a
#: credential, which is why #296 exists.
SERVICE_CONFIG_TARGETS: dict[str, str] = {
    "nginx": "/etc/nginx/nginx.conf",
    "apache": "/etc/apache2/apache2.conf",
    "postgresql": "/etc/postgresql/postgresql.conf",
    "docker-daemon": "/etc/docker/daemon.json",
    "systemd-resolved": "/etc/systemd/resolved.conf",
}


#: Capabilities whose output may be carried back to the platform.
#:
#: An **allow**-list, not a deny-list: a capability added later carries nothing
#: until somebody looks at what it returns and adds it here on purpose.
#:
#: ``read_service_config`` joined it when #296 landed. Its output is redacted on
#: the Collector — ``scanner_agent/config_redaction.py`` — so what crosses the
#: wire holds no credential, and what was there is reported as a finding about
#: the *shape*. It is the only member that needs redacting to qualify, and the
#: only one whose entry here depends on code running somewhere else.
#:
#: ``read_running_processes`` is still absent, and that is not an oversight.
#: ``ps`` output carries full command lines, and anything started with
#: ``--password=…`` is visible to whoever can read the process table. Redacting
#: a command line is not the decidable key-based problem a config file is.
OUTPUT_SAFE_BEFORE_REDACTION: frozenset[str] = frozenset(
    {
        ConnectorCapability.READ_OS_VERSION.value,
        ConnectorCapability.READ_LISTENING_SOCKET_OWNER.value,
        ConnectorCapability.LIST_CONTAINERS.value,
        ConnectorCapability.INSPECT_CONTAINER.value,
        ConnectorCapability.READ_IMAGE_METADATA.value,
        ConnectorCapability.READ_INSTALLED_PACKAGES.value,
        ConnectorCapability.READ_SERVICE_CONFIG.value,
    }
)


#: What each named parameter may look like. A parameter with no pattern here
#: cannot be substituted at all — the default is refusal, not acceptance.
_PARAMETER_PATTERNS: dict[str, re.Pattern[str]] = {
    # Docker ids are hex, short or full. Anchored, so nothing rides along.
    "container_id": re.compile(r"\A[0-9a-f]{12,64}\Z"),
    "image_id": re.compile(r"\A(sha256:)?[0-9a-f]{12,64}\Z"),
    # Never a path from the caller: the caller names a target, and the resolved
    # absolute path is substituted here. The pattern still anchors what may be
    # produced, so an entry added carelessly to SERVICE_CONFIG_TARGETS cannot
    # introduce a relative path or a traversal.
    "config_path": re.compile(r"\A/[A-Za-z0-9._/-]+\Z"),
}


def parameter_names(argv: tuple[str, ...]) -> tuple[str, ...]:
    """The ``{named}`` placeholders in a template, in the order they appear."""
    found: list[str] = []
    for element in argv:
        match = re.fullmatch(r"\{([a-z_]+)\}", element)
        if match and match.group(1) not in found:
            found.append(match.group(1))
    return tuple(found)


def parameter_pattern(name: str) -> re.Pattern[str] | None:
    """The shape a parameter must match, or ``None`` if it may not be used."""
    return _PARAMETER_PATTERNS.get(name)

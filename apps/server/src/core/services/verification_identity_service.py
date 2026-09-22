"""CA-08.4 (#292) — reading a name out of what deep verification returned.

The gap #249 names, in one line from a real discovery run::

    192.168.1.33 · Web service · Application · http, http-alt, http-proxy, ssh

Those are nmap's port-number nicknames. Port 8080 reads ``http-proxy`` whether
it is Plane, Jenkins or a coffee machine, so a Plane instance and a monitoring
dashboard on adjacent addresses render identically. CA-07.1 got as far as
*saying so honestly*; this is the capability that answers it.

**It produces evidence, and decides nothing else.** Reconciliation — "are these
two the same artefact?" — stays with ``artefact_reconciliation_service``, and
what an artefact is *for* is never inferred here (Søren, 2026-08-18: business
purpose arrives through process → service → slot and must not migrate onto the
artefact). This module answers "what is it?" and stops.

**Why the parsing lives here and not in
``artefact_identity_evidence_service``.** That module reads an nmap host record;
this reads the stdout of a command executed inside a host. Different input,
different failure modes. They share the thing that matters — ``DeterminedIdentity``
and ``IDENTITY_BASIS_PRECEDENCE`` — so there is still exactly one vocabulary of
what may name an artefact, and one rule for which evidence wins.
"""

from __future__ import annotations

import json
import re
import shlex

from src.core.constants.artefact_identity_evidence_enums import (
    ArtefactIdentityBasis,
    ArtefactIdentityUndetermined,
)
from src.core.constants.permission_profile_enums import ConnectorCapability
from src.core.services.artefact_identity_evidence_service import DeterminedIdentity

#: Longest name we will record. Output arrives from a customer's host; an
#: unbounded value is somewhere a very large string can quietly land.
_MAX_NAME_LENGTH = 200

#: Process names that hold a port without saying what the artefact *is*.
#:
#: Two kinds, and the second was found by running this against a real host
#: (2026-08-24). It identified a machine running Plane, Immich and Grafana as
#: **"java"** — true, and useless. A language runtime names the interpreter, not
#: the application, and "java" is exactly as informative as the ``http-proxy``
#: that #249 was raised about.
#:
#: Rejecting them matters more than it looks: ``LISTENING_PROCESS`` outranks
#: ``OS_RELEASE``, so accepting "java" *replaced* a perfectly good
#: "Debian GNU/Linux 13 (trixie)" with something worse. Precedence ranks classes
#: of evidence; it cannot rank how informative one instance happens to be, so
#: the uninformative ones must not enter as answers at all.
_UNINFORMATIVE_PROCESSES = frozenset(
    {
        # Holds the port for something else.
        "docker-proxy", "systemd", "init", "sshd", "xinetd", "inetd", "socat",
        # Names a runtime, not an application.
        "java", "python", "python2", "python3", "node", "nodejs", "ruby",
        "perl", "php", "php-fpm", "dotnet", "mono", "erlang", "beam", "beam.smp",
        "sh", "bash", "dash", "zsh", "gunicorn", "uwsgi", "supervisord",
    }
)


def identity_from_inspection(*, capability: str, stdout: str) -> DeterminedIdentity:
    """What this inspection established about the artefact, if anything.

    An empty or unreadable result is **not** an error. CA-08.4's criterion is
    explicit: *verification that establishes nothing says so; an empty result is
    a finding, not a gap.* So every path returns a ``DeterminedIdentity``, and
    the undetermined ones carry ``VERIFIED_NOTHING_IDENTIFYING`` — the reason
    that means "we went inside, with approval, and it still would not say".
    """
    text = (stdout or "").strip()
    if not text:
        return _undetermined()

    if capability == ConnectorCapability.INSPECT_CONTAINER.value:
        return _from_container_inspect(text)
    if capability == ConnectorCapability.LIST_CONTAINERS.value:
        return _from_container_list(text)
    if capability == ConnectorCapability.READ_LISTENING_SOCKET_OWNER.value:
        return _from_listening_sockets(text)
    if capability == ConnectorCapability.READ_OS_VERSION.value:
        return _from_os_release(text)

    # A capability that reads something real but names nothing — the package
    # list, the process table. Not a failure; simply not identifying.
    return _undetermined()


def _from_container_inspect(text: str) -> DeterminedIdentity:
    """``docker container inspect`` — the image is the answer."""
    try:
        parsed = json.loads(text)
    except json.JSONDecodeError:
        return _undetermined()

    entries = parsed if isinstance(parsed, list) else [parsed]
    for entry in entries:
        if not isinstance(entry, dict):
            continue
        config = entry.get("Config")
        image = config.get("Image") if isinstance(config, dict) else None
        image = image or entry.get("Image")
        name = _clean(image)
        if name and not _looks_like_a_digest(name):
            return _determined(ArtefactIdentityBasis.CONTAINER_IMAGE, name, name)
    return _undetermined()


def _from_container_list(text: str) -> DeterminedIdentity:
    """``docker ps`` — tab-separated id, image, names, ports.

    Uses the first container's image. Where a host runs several, this names one
    of them rather than the host, which is why ``list_containers`` is weaker
    evidence than inspecting the container actually holding the port.
    """
    for line in text.splitlines():
        parts = line.split("\t")
        if len(parts) < 2:
            continue
        name = _clean(parts[1])
        if name and not _looks_like_a_digest(name):
            return _determined(ArtefactIdentityBasis.CONTAINER_IMAGE, name, line.strip())
    return _undetermined()


def _from_listening_sockets(text: str) -> DeterminedIdentity:
    """``ss -ltnpH`` — the executable holding a listening port.

    The line ends with ``users:(("nginx",pid=1234,fd=6))``. Proxies, supervisors
    and language runtimes are skipped — see ``_UNINFORMATIVE_PROCESSES``. An
    artefact named "docker-proxy" or "java" reads like an answer while telling a
    person nothing, and this capability exists precisely to stop that happening.

    Lines are taken in order, so the first *informative* process wins. On a host
    running several services this names one of them rather than the host, which
    is why inspecting the container that actually holds the port is stronger
    evidence still.
    """
    for line in text.splitlines():
        match = re.search(r'users:\(\("([^"]+)"', line)
        if not match:
            continue
        process = _clean(match.group(1))
        if process and process.lower() not in _UNINFORMATIVE_PROCESSES:
            return _determined(ArtefactIdentityBasis.LISTENING_PROCESS, process, line.strip())
    return _undetermined()


def _from_os_release(text: str) -> DeterminedIdentity:
    """``/etc/os-release`` — ``PRETTY_NAME`` first, then ``NAME``."""
    values: dict[str, str] = {}
    for line in text.splitlines():
        if "=" not in line or line.startswith("#"):
            continue
        key, _, raw = line.partition("=")
        # shlex, because the file quotes values and a naive strip('"') leaves
        # escapes behind.
        try:
            unquoted = next(iter(shlex.split(raw)), "")
        except ValueError:
            unquoted = raw.strip().strip('"')
        values[key.strip()] = unquoted

    for key in ("PRETTY_NAME", "NAME"):
        name = _clean(values.get(key))
        if name:
            return _determined(ArtefactIdentityBasis.OS_RELEASE, name, name)
    return _undetermined()


def _determined(
    basis: ArtefactIdentityBasis, name: str, evidence: str
) -> DeterminedIdentity:
    return DeterminedIdentity(
        name=name,
        basis=basis.value,
        evidence=evidence[:_MAX_NAME_LENGTH],
        undetermined_reason=None,
    )


def _undetermined() -> DeterminedIdentity:
    return DeterminedIdentity(
        name=None,
        basis=None,
        evidence=None,
        undetermined_reason=ArtefactIdentityUndetermined.VERIFIED_NOTHING_IDENTIFYING.value,
    )


def _clean(value: object) -> str | None:
    if not isinstance(value, str):
        return None
    collapsed = " ".join(value.split()).strip()
    return collapsed[:_MAX_NAME_LENGTH] or None


def _looks_like_a_digest(value: str) -> bool:
    """``sha256:ab12…`` names nothing a person can read.

    Docker reports a bare digest when an image has no tag. Recording it would
    satisfy "we determined an identity" while leaving the reader exactly where
    they started, which is the failure #249 is about.
    """
    return bool(re.fullmatch(r"(sha256:)?[0-9a-f]{12,64}", value))

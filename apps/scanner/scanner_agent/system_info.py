"""System identity — what CA-02's heartbeat reports about the host this
agent runs on. Read fresh on every call, not cached at import time, since
this module has no way to know whether the process will be rescheduled
onto different hardware between heartbeats (e.g. a rescheduled container).
"""

from __future__ import annotations

import platform
from dataclasses import dataclass
from pathlib import Path

_OS_RELEASE_PATH = Path("/etc/os-release")
_DOCKER_ENV_PATH = Path("/.dockerenv")
_CGROUP_PATH = Path("/proc/1/cgroup")
_CONTAINER_CGROUP_MARKERS = ("docker", "containerd", "kubepods", "podman")


@dataclass(frozen=True)
class HostIdentity:
    """What this Collector can *truthfully* say about the machine it runs on.

    CA-02.3 slice 3. The distinction exists because ``detect_os()`` reads
    ``/etc/os-release``, which inside a container describes the **image**, not
    the host — and the platform stored that as the machine's OS with nothing
    recording which it was. On Søren's Pi it read ``Debian GNU/Linux``, which is
    also what the host runs, so it looked right; on an Ubuntu or RHEL host
    running the same image it would have been simply wrong, and nothing
    downstream could have told.

    The split is not a guess. Verified on the real Pi: from inside the
    container ``platform.release()`` returns ``6.18.34+rpt-rpi-v8``,
    byte-identical to the host's ``uname -r``, because containers share the
    host's kernel. So:

    * ``kernel_release`` and ``architecture`` are **real host facts**, readable
      from inside a container.
    * ``distribution_name``/``version`` are the host's **only when not
      containerised**. Inside a container they are left ``None`` rather than
      filled with the image's values — an unverifiable claim must not be
      presented as a measurement, which is this whole story's premise.
    * ``runtime_*`` describe the container itself, kept separately so the view
      can say what the Collector is running *in* without implying it is the
      machine.
    """

    kernel_release: str
    architecture: str
    distribution_name: str | None
    distribution_version: str | None
    container_runtime: str | None
    runtime_distribution_name: str | None
    runtime_distribution_version: str | None

    @property
    def is_containerised(self) -> bool:
        return self.container_runtime is not None


def detect_architecture() -> str:
    return platform.machine() or "unknown"


def detect_os() -> tuple[str, str]:
    """Returns (os_name, os_version). Prefers /etc/os-release's NAME/
    VERSION_ID on Linux (e.g. ("Ubuntu", "22.04")); falls back to
    platform.system()/platform.release() everywhere else, or when
    /etc/os-release is missing (minimal containers, non-Linux hosts)."""
    if platform.system() == "Linux":
        parsed = _read_os_release()
        if parsed:
            return parsed
    return platform.system(), platform.release()


def _read_os_release() -> tuple[str, str] | None:
    if not _OS_RELEASE_PATH.exists():
        return None
    values: dict[str, str] = {}
    for line in _OS_RELEASE_PATH.read_text().splitlines():
        if "=" not in line:
            continue
        key, _, value = line.partition("=")
        values[key.strip()] = value.strip().strip('"')
    name = values.get("NAME")
    version = values.get("VERSION_ID")
    if not name:
        return None
    return name, version or ""


def detect_container_runtime() -> str | None:
    """Which container runtime this process is inside, or ``None`` on a host.

    Two independent signals because either alone is defeatable: ``/.dockerenv``
    is absent under podman and some rootless setups, and the cgroup path is
    empty on cgroup v2 hosts with a private namespace. A false *negative* here
    is the dangerous direction — it would let the image's own os-release be
    reported as the machine's OS, which is exactly what this replaces.
    """
    if _DOCKER_ENV_PATH.exists():
        return "docker"
    try:
        cgroup = _CGROUP_PATH.read_text()
    except OSError:
        return None
    for marker in _CONTAINER_CGROUP_MARKERS:
        if marker in cgroup:
            return "docker" if marker == "docker" else marker
    return None


def describe_host() -> HostIdentity:
    """The Collector's own, honestly-scoped view of where it is running."""
    runtime = detect_container_runtime()
    os_release = _read_os_release() if platform.system() == "Linux" else None
    name = os_release[0] if os_release else None
    version = os_release[1] or None if os_release else None

    return HostIdentity(
        # Shared with the host even inside a container — verified on the Pi.
        kernel_release=platform.release() or "unknown",
        architecture=detect_architecture(),
        # Only claimed as the host's when nothing is standing in between.
        distribution_name=None if runtime else (name or platform.system() or None),
        distribution_version=None if runtime else version,
        container_runtime=runtime,
        runtime_distribution_name=name if runtime else None,
        runtime_distribution_version=version if runtime else None,
    )

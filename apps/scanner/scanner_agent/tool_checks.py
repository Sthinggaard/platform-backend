"""Detects the real scanning binaries the Risklence Scanner depends on
(Nmap, Subfinder, Nuclei) — never assumed present, always probed on the
machine the agent actually runs on. Tool names here must match
``ScannerToolName`` in apps/server/src/core/constants/evidence_scanner_enums.py.
"""

from __future__ import annotations

import shutil
import socket
import subprocess
from dataclasses import dataclass
from pathlib import Path

TOOL_VERSION_COMMANDS: dict[str, list[str]] = {
    "nmap": ["nmap", "--version"],
    "subfinder": ["subfinder", "-version"],
    "nuclei": ["nuclei", "-version"],
}

# Where the Docker image bakes in a pinned, reviewed Nuclei template pack at
# build time (CA-03.2) — never populated by `nuclei -update-templates` at
# runtime, which would pull an arbitrary, unreviewed upstream snapshot.
NUCLEI_TEMPLATES_DIR = Path.home() / "nuclei-templates"
_TEMPLATE_VERSION_MARKER = ".risklence-template-version"


@dataclass(frozen=True)
class ToolCheckResult:
    tool: str
    available: bool
    version: str | None
    binary_path: str | None


def _probe_version(command: list[str]) -> str | None:
    try:
        result = subprocess.run(command, capture_output=True, text=True, timeout=10)
    except (OSError, subprocess.TimeoutExpired):
        return None
    output = (result.stdout or "") + (result.stderr or "")
    lines = output.strip().splitlines()
    return lines[0] if lines else None


def check_tool(tool: str) -> ToolCheckResult:
    command = TOOL_VERSION_COMMANDS[tool]
    binary_path = shutil.which(command[0])
    if binary_path is None:
        return ToolCheckResult(tool=tool, available=False, version=None, binary_path=None)
    return ToolCheckResult(tool=tool, available=True, version=_probe_version(command), binary_path=binary_path)


def check_nuclei_templates(templates_dir: Path = NUCLEI_TEMPLATES_DIR) -> ToolCheckResult:
    available = templates_dir.is_dir() and any(templates_dir.iterdir())
    version = None
    if available:
        marker = templates_dir / _TEMPLATE_VERSION_MARKER
        if marker.is_file():
            version = marker.read_text().strip() or None
    return ToolCheckResult(
        tool="nuclei_templates",
        available=available,
        version=version,
        binary_path=str(templates_dir) if available else None,
    )


#: Reported alongside the tools, and deliberately **not** one of them.
#: A missing binary is something an operator installs; this is a privilege the
#: container was or was not granted, and describing it as a missing tool would
#: send somebody looking for something to install. Must match
#: ``CollectorCapability.RAW_PACKET_ACCESS`` on the platform side.
RAW_PACKET_CAPABILITY = "raw_packet_access"


def check_raw_packet_capability() -> ToolCheckResult:
    """Whether this Collector may send raw packets.

    **Why the platform needs to be told.** Without it nmap cannot ARP the local
    segment, so it reports no MAC address and no hardware vendor — and
    ``HARDWARE_VENDOR`` is the only basis that can name a device with nothing
    listening. The absence of a MAC then means one of two entirely different
    things: *there is no device here*, or *we were never able to look*. The
    platform cannot tell them apart from the evidence, and guessing is how 242
    echoes became artefacts (#175).

    Tested by opening a raw socket rather than by checking for root. The two are
    not the same — a container can hold ``NET_RAW`` without being root, and
    root in a container without the capability still cannot send — and it is the
    socket, not the uid, that nmap actually needs.
    """
    try:
        raw = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
    except (OSError, AttributeError, PermissionError) as exc:
        return ToolCheckResult(
            tool=RAW_PACKET_CAPABILITY, available=False, version=None, binary_path=type(exc).__name__
        )
    raw.close()
    return ToolCheckResult(tool=RAW_PACKET_CAPABILITY, available=True, version=None, binary_path=None)


def check_all_tools() -> list[ToolCheckResult]:
    return (
        [check_tool(tool) for tool in TOOL_VERSION_COMMANDS]
        + [check_nuclei_templates()]
        + [check_raw_packet_capability()]
    )

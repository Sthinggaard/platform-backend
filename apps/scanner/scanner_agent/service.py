"""CA-02 — persistent systemd (--user) service lifecycle for the scanner
agent. Deliberately user-level, not system-level: it needs no root/sudo to
install or remove, matching the rest of this CLI's self-service model
(credentials also live under the invoking user's own home directory).

The Docker installation method doesn't need any of this — a container's
own restart policy and `docker stop`/`docker rm` already are its pause/
uninstall equivalent once `run` (below) is the image's long-running
process; this module is only for the `local_cli`/`server` installation
methods, where there is no container runtime doing that job already.
"""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

SERVICE_NAME = "risklence-scanner.service"
_UNIT_DIR = Path.home() / ".config" / "systemd" / "user"

_UNIT_TEMPLATE = """[Unit]
Description=Risklence Scanner Agent
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart={exec_path} run
Restart=on-failure
RestartSec=10

[Install]
WantedBy=default.target
"""


class ServiceError(RuntimeError):
    """Raised when systemd unit install/removal can't complete."""


def _executable_path() -> str:
    resolved = shutil.which("risklence-scanner")
    if resolved is None:
        raise ServiceError(
            "Could not find the `risklence-scanner` executable on PATH — install it (e.g. `pip install .`) before "
            "installing the service."
        )
    return resolved


def _run_systemctl(*args: str) -> None:
    try:
        subprocess.run(["systemctl", "--user", *args], check=True, capture_output=True, text=True)
    except FileNotFoundError as exc:
        raise ServiceError("systemctl not found — service install/uninstall requires a systemd host.") from exc
    except subprocess.CalledProcessError as exc:
        raise ServiceError(f"systemctl {' '.join(args)} failed: {exc.stderr.strip()}") from exc


def unit_path(unit_dir: Path = _UNIT_DIR) -> Path:
    return unit_dir / SERVICE_NAME


def install_service(unit_dir: Path = _UNIT_DIR) -> Path:
    """Write the unit file and enable+start it as the invoking user's own
    systemd instance. Idempotent — reinstalling just rewrites the same
    file and restarts the service."""
    exec_path = _executable_path()
    unit_dir.mkdir(parents=True, exist_ok=True)
    path = unit_path(unit_dir)
    path.write_text(_UNIT_TEMPLATE.format(exec_path=exec_path))
    _run_systemctl("daemon-reload")
    _run_systemctl("enable", "--now", SERVICE_NAME)
    return path


def uninstall_service(unit_dir: Path = _UNIT_DIR) -> None:
    """Stop, disable, and remove the unit. Safe to call even if the
    service was never installed — systemctl no-ops on an unknown unit
    rather than erroring in a way that should block cleanup."""
    path = unit_path(unit_dir)
    if path.exists():
        _run_systemctl("disable", "--now", SERVICE_NAME)
        path.unlink()
        _run_systemctl("daemon-reload")

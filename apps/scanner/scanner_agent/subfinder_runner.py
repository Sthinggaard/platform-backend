"""CA-04.3 — executes a real Subfinder subdomain enumeration against the
command's own approved domain targets.

Deliberately narrow: plain-text output (``-silent``, one discovered
subdomain per line) against a single operator-supplied domain — no
Subfinder JSON (``-oJ``) parsing, no active resolution/brute-forcing
flags. Mirrors ``nmap_runner.py``'s own scope and style exactly.
"""

from __future__ import annotations

import shutil
import subprocess
from dataclasses import dataclass


class SubfinderNotAvailableError(RuntimeError):
    """Raised when the subfinder binary cannot be found on PATH."""


class SubfinderScanError(RuntimeError):
    """Raised when the subfinder process fails or times out."""


@dataclass(frozen=True)
class SubfinderScanResult:
    domain: str
    subdomains: list[str]
    raw_output: str


def run_subfinder_scan(domain: str, *, timeout: float = 60.0) -> SubfinderScanResult:
    if shutil.which("subfinder") is None:
        raise SubfinderNotAvailableError("subfinder is not installed or not on PATH.")

    command = ["subfinder", "-d", domain, "-silent"]
    try:
        result = subprocess.run(command, capture_output=True, text=True, timeout=timeout)
    except subprocess.TimeoutExpired as exc:
        raise SubfinderScanError(f"subfinder scan of {domain} timed out after {timeout}s.") from exc

    if result.returncode != 0:
        raise SubfinderScanError(f"subfinder exited with code {result.returncode}: {result.stderr.strip()}")

    subdomains = [line.strip() for line in result.stdout.splitlines() if line.strip()]
    return SubfinderScanResult(domain=domain, subdomains=subdomains, raw_output=result.stdout)


def run_subfinder_discovery(domains: list[str], *, timeout: float = 60.0) -> list[SubfinderScanResult]:
    """Every approved domain target this command actually covers — one
    target failing (a transient resolver issue, an unreachable domain)
    does not abort the batch; a partial result is still a real result."""
    results: list[SubfinderScanResult] = []
    for domain in domains:
        try:
            results.append(run_subfinder_scan(domain, timeout=timeout))
        except SubfinderScanError:
            if not shutil.which("subfinder"):
                raise
            results.append(SubfinderScanResult(domain=domain, subdomains=[], raw_output=""))
    return results

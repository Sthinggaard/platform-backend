"""Executes a real, safe Nmap scan against an approved test-lab target.

Deliberately narrow: a TCP-connect scan of the top 50 ports
(``-sT -T4 --top-ports 50``) against a single operator-supplied host — no
OS fingerprinting, no aggressive/vuln scripts. This is the "does the
agent's Nmap actually reach and read something" check behind the CLI's
``test-scan`` command, not a general-purpose scan engine.
"""

from __future__ import annotations

import shutil
import subprocess
from dataclasses import dataclass

# Uses ``defusedxml`` rather than the stdlib ``xml.etree.ElementTree``, matching
# the server-side evidence adapter's own choice (A1 security remediation,
# Semgrep ``use-defused-xml``). The Collector produces this XML, but it does not
# author its content: hostnames, service banners and script output inside an
# nmap document come from whatever is answering on the scanned network. The
# stdlib parser resolves external entities and expands nested entities, so a
# hostile host on a customer's own network could reach the Collector process
# through its scan results. defusedxml disables both by default.
import defusedxml.ElementTree as ET
from defusedxml.common import DefusedXmlException

# defusedxml raises its own ``DefusedXmlException`` family (DTDForbidden,
# EntitiesForbidden, ExternalReferenceForbidden) for a hostile document — those
# are ValueError subclasses, *not* ``ET.ParseError``, so every ``except
# ParseError`` below must name them explicitly or a blocked attack would crash
# the scan instead of degrading it.
_XML_REJECTED = (ET.ParseError, DefusedXmlException)


class NmapNotAvailableError(RuntimeError):
    """Raised when the nmap binary cannot be found on PATH."""


class NmapScanError(RuntimeError):
    """Raised when the nmap scan process fails or times out."""


@dataclass(frozen=True)
class NmapScanResult:
    target: str
    open_ports: list[int]
    raw_output: str


# The scan every run performs: a TCP-connect sweep of the top 50 ports. It
# establishes that something is answering and on which ports — nothing about
# what that something *is*. Without version detection nmap fills `<service
# name=…>` from its port-number table alone, so port 8080 reads "http-proxy"
# whether it is Plane, Jenkins, or a coffee machine.
_BASE_FLAGS = ["-sT", "-T4", "--top-ports", "50"]

# What turns an open port into an identified thing, run only under an approved
# `allowsFingerprinting` profile (CA-07.1 slice 1).
#
# `-sV` populates the `product`/`version` attributes that are empty by
# construction without it. The two scripts are nmap's `default`/`safe`
# categories — `http-title` is one GET reading `<title>`, `ssl-cert` reads the
# certificate already presented on connect. Neither authenticates, exploits, or
# writes; both are the cheapest evidence that names a self-hosted application,
# and they are what makes "we could not determine this" an honest statement
# rather than an artefact of never having looked.
_FINGERPRINT_FLAGS = ["-sV", "--script", "http-title,ssl-cert"]


def build_scan_command(target: str, *, fingerprint: bool) -> list[str]:
    """The exact argv for one target, so the flags are readable in one place
    and assertable in a test rather than inlined at the call site.

    `-oX -` emits the XML the platform's evidence adapter parses
    (`_parse_nmap_xml`). Without it the scan ran, found real ports, and had
    nothing to attach as evidence, so nothing became an asset.
    """
    flags = list(_BASE_FLAGS)
    if fingerprint:
        flags += _FINGERPRINT_FLAGS
    return ["nmap", *flags, "-oX", "-", target]


def run_safe_test_scan(target: str, *, timeout: float = 60.0, fingerprint: bool = False) -> NmapScanResult:
    if shutil.which("nmap") is None:
        raise NmapNotAvailableError("nmap is not installed or not on PATH.")

    # Defaults to False: the CLI's own `test-scan` is a reachability check
    # against an operator-supplied host, which carries no approved profile to
    # authorise anything deeper. Only a delegated command passes True, and only
    # when its envelope says the organisation approved fingerprinting.
    command = build_scan_command(target, fingerprint=fingerprint)
    try:
        result = subprocess.run(command, capture_output=True, text=True, timeout=timeout)
    except subprocess.TimeoutExpired as exc:
        raise NmapScanError(f"nmap scan of {target} timed out after {timeout}s.") from exc

    if result.returncode != 0:
        raise NmapScanError(f"nmap exited with code {result.returncode}: {result.stderr.strip()}")

    return NmapScanResult(target=target, open_ports=_parse_open_ports(result.stdout), raw_output=result.stdout)


#: Version detection and two scripts probe each open port rather than only
#: completing a handshake, so a fingerprinting scan legitimately takes longer
#: than a connect sweep. Timing out mid-probe would report a partial result as
#: a whole one — the failure that makes "nothing was determined" indistinguishable
#: from "we stopped looking".
FINGERPRINT_TIMEOUT_SECONDS = 300.0


def run_discovery_scan(
    targets: list[str], *, timeout: float | None = None, fingerprint: bool = False
) -> list[NmapScanResult]:
    """CA-04.1 — the real scan an acknowledged, verified discovery command
    actually runs, against each of the command's own approved targets
    (``target["approvedValue"]`` from the run's target_snapshot) rather than
    a single hardcoded test-lab host. Subfinder/Nuclei are separate runner
    modules (CA-04.3/04.4), not this one. One target failing does not abort the
    batch — a partial result is still a real result, and the caller reports
    whatever this returns either way.

    ``fingerprint`` comes from the command envelope's own
    ``profile.allowsFingerprinting`` — the organisation's approved scan profile,
    not a local setting. CA-07.1 slice 1: the platform already plans a
    ``service_fingerprinting`` stage and authorises it, and this is where that
    authorisation stops being ignored. Still no OS fingerprinting and no
    aggressive or vulnerability scripts; those remain Nuclei's own, separately
    approved, territory.
    """
    effective_timeout = timeout if timeout is not None else (FINGERPRINT_TIMEOUT_SECONDS if fingerprint else 60.0)
    results: list[NmapScanResult] = []
    for target in targets:
        try:
            results.append(run_safe_test_scan(target, timeout=effective_timeout, fingerprint=fingerprint))
        except (NmapNotAvailableError, NmapScanError):
            # NmapNotAvailableError would repeat identically for every
            # remaining target — re-raise so the caller can report one
            # clear failure instead of N identical ones.
            if not shutil.which("nmap"):
                raise
            results.append(NmapScanResult(target=target, open_ports=[], raw_output=""))
    return results


def _parse_open_ports(nmap_output: str) -> list[int]:
    """Open TCP ports from nmap's XML output.

    The scan now runs with ``-oX -`` so the platform receives real NMAP_XML
    evidence, which means stdout is XML rather than the human-readable table
    this used to scrape. Parsed here only for the Collector's own console
    summary — the authoritative parse happens server-side in the evidence
    adapter against the same XML.
    """
    try:
        root = ET.fromstring(nmap_output)
    except _XML_REJECTED:
        # Never let a summary line break a scan that actually ran; the raw
        # output is still attached as evidence regardless. This covers a
        # document defusedxml refuses as well as one that is merely malformed —
        # the console summary degrades to "no ports listed" either way.
        return []

    open_ports: list[int] = []
    for port_el in root.findall(".//ports/port"):
        if port_el.get("protocol") != "tcp":
            continue
        state_el = port_el.find("state")
        if state_el is None or state_el.get("state") != "open":
            continue
        port_id = port_el.get("portid")
        if port_id and port_id.isdigit():
            open_ports.append(int(port_id))
    return open_ports


def merge_scan_xml(results: list["NmapScanResult"]) -> str:
    """Combine per-target nmap XML into one valid document.

    A command may carry several approved targets but produces a single evidence
    package, and concatenating XML documents yields something no parser can
    read. This keeps the first document's ``<nmaprun>`` envelope and moves every
    other document's ``<host>`` elements into it, so the result is real NMAP_XML
    the server's adapter can parse.
    """
    documents = [r.raw_output for r in results if r.raw_output]
    if not documents:
        return ""
    if len(documents) == 1:
        return documents[0]

    merged_root = None
    for document in documents:
        try:
            root = ET.fromstring(document)
        except _XML_REJECTED:
            # One unreadable or rejected document must not discard the evidence
            # from every other target in the same command.
            continue
        if merged_root is None:
            merged_root = root
            continue
        for host_el in root.findall("host"):
            merged_root.append(host_el)

    if merged_root is None:
        return ""
    return ET.tostring(merged_root, encoding="unicode")

"""CA-09V — choosing which nuclei templates a host is worth running.

Narrowing the *targets* (``discovery_target_narrowing``) took a nuclei command
from 256 blind addresses to the 13 hosts discovery had actually found. It was
correct and it was not enough: the run on 2026-09-07 07:12:52 still took **606
seconds** and returned **0 bytes** — the integrity hash on that evidence package
is ``e3b0c442…b855``, the SHA-256 of the empty string. Thirteen hosts against
13,510 templates does not fit any budget a person will wait for.

**The pack is one tree and a rounding error.** Counted on the live Collector's
pinned ``v10.4.7`` pack, 2026-09-07:

    http  11137  │  cloud 663  code 303  dast 251  file 447  headless  24
                 │  network 280  ssl 38  dns 31  javascript 129

``http`` is 82% of everything. Every other protocol tree put together is 478
templates, which is cheap enough that scoping *them* would add a decision
without buying time. So this module makes exactly one judgement — **does this
host speak HTTP?** — and everything else follows a fixed rule.

Søren ruled on 2026-09-07: *scope by fingerprinted service*, so that every
skipped template is justified by evidence rather than by a guess. The accepted
cost is that coverage becomes conditional on fingerprint quality, and the
mitigation is that this module never skips silently — every scope it returns
carries the reason it chose, which travels with the command and onto the scan
result.

This module names **trees**, never paths. Where the pinned pack lives is the
Collector's own business, and a server that sent filesystem paths would both
encode another machine's layout and hand a scanner an arbitrary ``-t`` argument.
``nuclei_runner`` resolves a tree name against its own pack root and refuses any
name it does not recognise.

Pure by construction (AGENTS.md §19.7): it takes observed services and returns a
scope, performing no I/O, so the rule is testable without a database. The
queries that feed it live in ``discovery_command_service.py``.
"""

from __future__ import annotations

from dataclasses import dataclass

#: Trees a remote network scan of a host can never match, excluded on protocol
#: grounds rather than on evidence — so this is not a coverage decision and does
#: not depend on the fingerprint being any good.
#:
#: ``cloud`` reads cloud-provider APIs and needs credentials this scan does not
#: carry; ``code`` and ``dast`` are analysis modes, not host checks; ``file``
#: scans a local filesystem; ``headless`` only runs when nuclei is invoked with
#: ``-headless``, which the Collector never passes, so those templates are
#: loaded and skipped today. 1,688 templates that cost time for no reachable
#: match.
UNREACHABLE_TREES: tuple[str, ...] = ("cloud", "code", "dast", "file", "headless")

#: Always run. 478 templates between them — small enough that making them
#: conditional would trade real coverage for no measurable time.
BASELINE_TREES: tuple[str, ...] = ("network", "ssl", "dns", "javascript")

#: The one tree worth a decision.
HTTP_TREE = "http"

#: An nmap service name containing any of these speaks HTTP. Substring rather
#: than an exact set because nmap's own vocabulary is open — ``http``,
#: ``https``, ``http-proxy``, ``https-alt``, ``http-alt`` and
#: ``ssl/http`` all appear in this organisation's own scan data.
_HTTP_SERVICE_MARKERS: tuple[str, ...] = ("http", "www")

#: Ports that carry HTTP often enough that an unnamed service on one is treated
#: as HTTP. This is the deliberate widening of the rule: a port nmap could not
#: name is not evidence of *absence*, and these are where a web server actually
#: lives.
_HTTP_PORTS: frozenset[int] = frozenset(
    {80, 81, 443, 591, 3000, 5000, 7001, 8000, 8008, 8080, 8081, 8088, 8443, 8888, 9090, 9443}
)


@dataclass(frozen=True)
class TemplateScope:
    """The trees to run, and why — the reason is not decoration.

    A scope that quietly dropped 82% of the pack would be indistinguishable
    from a clean scan of the whole pack, which is the same class of defect as a
    timeout reading as "found nothing". ``reason`` travels onto the command and
    into the scan result so a reader can always see what was not run.
    """

    trees: tuple[str, ...]
    reason: str
    http_included: bool


def _service_names(services: list[dict]) -> list[str]:
    names = []
    for service in services:
        if not isinstance(service, dict):
            continue
        name = service.get("service")
        if isinstance(name, str) and name.strip():
            names.append(name.strip().lower())
    return names


def _ports(services: list[dict]) -> list[int]:
    ports = []
    for service in services:
        if not isinstance(service, dict):
            continue
        port = service.get("port")
        if isinstance(port, bool):
            continue
        if isinstance(port, int):
            ports.append(port)
        elif isinstance(port, str) and port.strip().isdigit():
            ports.append(int(port.strip()))
    return ports


def _http_evidence(services: list[dict]) -> str | None:
    """The named service or port that says this host speaks HTTP, if any."""
    for name in _service_names(services):
        if any(marker in name for marker in _HTTP_SERVICE_MARKERS):
            return f"service {name!r}"
    for port in _ports(services):
        if port in _HTTP_PORTS:
            return f"port {port}"
    return None


def scope_templates_for_host(services: list[dict] | None) -> TemplateScope:
    """Which template trees are worth running against a host, and why.

    ``services`` is the fingerprint this platform already holds for the host —
    the ``host.services`` list nmap normalisation stores on an evidence signal,
    each entry carrying at least ``port`` and usually ``service``.

    Four outcomes, and the distinction between the first two is the one that
    matters most:

    * **Never fingerprinted** (``None``). Nothing is known, and an absence of
      evidence is not evidence of absence — so ``http`` is included. Scoping
      down here would be a guess, which is exactly what the ruling forbids.
    * **Fingerprinted, nothing open** (``[]``). This is *not* the same thing,
      and treating it as such is what this rule got wrong first time round.
      An empty service list is a positive observation: nmap looked and found no
      open port. Nuclei has nothing to connect to, so **no template can match**
      and the host is scoped to nothing. Measured on this organisation, 263 of
      269 hosts are in this state — the entire ``192.168.1.0/24`` holds an
      artefact per address, network and broadcast addresses included — so this
      branch, not the HTTP rule, is where almost all of the runtime goes.
    * **Fingerprinted, HTTP found.** Everything reachable runs.
    * **Fingerprinted, no HTTP found.** ``http`` is skipped and the reason says
      what was seen instead. This is where the 82% is saved on a host that is
      genuinely up.

    ⚠️ **A port nmap could not identify counts as *seen but unnamed*, not as
    HTTP.** A host answering only ``tcpwrapped`` therefore skips the http tree
    unless one of those ports is a known HTTP port. Four of this organisation's
    fourteen fingerprinted hosts are in exactly that state, so the choice is not
    hypothetical — it is called out here because it is the one place a real web
    server could hide from this rule, and the reason string is what makes that
    visible to whoever reads the scan.
    """
    reachable = BASELINE_TREES

    if services is None:
        return TemplateScope(
            trees=(HTTP_TREE, *reachable),
            reason=(
                "No service fingerprint is held for this host, so no template tree could be "
                "ruled out on evidence. The full reachable pack was run."
            ),
            http_included=True,
        )

    if not services:
        # Fingerprinted and found to expose nothing. Not the same as unknown:
        # nuclei connects to ports, so with none open no template can match and
        # running the pack buys a guaranteed-empty result at full price.
        return TemplateScope(
            trees=(),
            reason=(
                "No templates were run: service fingerprinting found no open port on this "
                "host, so there is nothing for a vulnerability template to connect to."
            ),
            http_included=False,
        )

    evidence = _http_evidence(services)
    if evidence is not None:
        return TemplateScope(
            trees=(HTTP_TREE, *reachable),
            reason=f"HTTP templates were run: {evidence} was fingerprinted on this host.",
            http_included=True,
        )

    observed = sorted(set(_service_names(services))) or sorted({str(port) for port in _ports(services)})
    seen = ", ".join(observed) if observed else "nothing identifiable"
    return TemplateScope(
        trees=reachable,
        reason=(
            f"HTTP templates were not run: no HTTP service or port was fingerprinted on this "
            f"host (observed: {seen}). Re-run service fingerprinting if a web server is "
            "expected here."
        ),
        http_included=False,
    )


__all__ = [
    "BASELINE_TREES",
    "HTTP_TREE",
    "UNREACHABLE_TREES",
    "TemplateScope",
    "scope_templates_for_host",
]

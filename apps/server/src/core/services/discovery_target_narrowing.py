"""CA-09V — narrowing an approved scope to the hosts discovery already found.

A vulnerability check is not a discovery sweep. Nmap's job is to answer *what
is out there*; Nuclei's job is to answer *what is wrong with the things we
found*. Handing Nuclei the run's approved ``192.168.50.0/24`` made it re-answer
the first question — 256 addresses, blind — and it was killed at its timeout
every time, on every run since 2026-08-27, reporting a clean empty scan.

The platform already holds the answer: ``asset_identifiers`` carries the IP of
every artefact discovery has observed. Thirteen of those addresses are inside
that ``/24``. This module turns the approved scope into those thirteen.

**Narrowing can only ever remove.** Every host returned here is proven to fall
inside a live-approved target before it is emitted, and a discovered address
that falls in no approved target is dropped rather than scanned. That direction
is the whole safety argument, and ``test_discovery_target_narrowing.py`` asserts
it rather than trusting it: the customer approved a range, and nothing outside
what they approved may ever reach a scanner because an artefact happened to be
observed elsewhere.

Pure by construction (AGENTS.md §19.7) — it takes the snapshot and the observed
addresses as arguments and performs no I/O, so the containment rule is testable
without a database. The queries that feed it live in
``discovery_command_service.py``.
"""

from __future__ import annotations

from ipaddress import AddressValueError, IPv4Address, IPv4Network, NetmaskValueError

from src.core.constants.discovery_run_enums import DiscoveryTargetType

#: Keys carried unchanged from the approved target onto each host derived from
#: it. A narrowed target is still *that* approved target's scope — who approved
#: it and when is the provenance an auditor reads, and it must not be
#: manufactured here.
_INHERITED_APPROVAL_KEYS = (
    "targetId",
    "targetType",
    "networkType",
    "approvedAt",
    "approvedByUserId",
)


def _parse_network(value: str) -> IPv4Network | None:
    """A snapshot value that is not a parseable IPv4 network is not narrowed
    and not guessed at — the caller keeps the target as approved."""
    try:
        return IPv4Network(value.strip(), strict=False)
    except (AddressValueError, NetmaskValueError, ValueError):
        return None


def _parse_address(value: str) -> IPv4Address | None:
    try:
        return IPv4Address(value.strip())
    except (AddressValueError, ValueError):
        return None


def _host_target(parent: dict, address: IPv4Address) -> dict:
    host = {key: parent[key] for key in _INHERITED_APPROVAL_KEYS if key in parent}
    host["approvedValue"] = str(address)
    # The parent's own display name plus the address, so an operator reading the
    # Collector console can still see which approved range this host came from.
    host[
        "displayName"
    ] = f"{parent.get('displayName', parent.get('approvedValue', ''))} · {address}"
    return host


def narrow_targets_to_discovered_hosts(
    targets: list[dict], discovered_addresses: list[str]
) -> list[dict]:
    """Replace each approved network range with the discovered hosts inside it.

    ``targets`` is a live target snapshot (``get_live_target_snapshot``), already
    re-validated against current approval state. ``discovered_addresses`` is
    every IP this organisation's artefacts have been observed under.

    A ``DOMAIN`` target passes through unchanged: a domain is a name, not a
    range, and there is nothing to narrow it to. A ``NETWORK_RANGE`` contributes
    one target per discovered host inside it — and **nothing at all** when no
    discovered host falls inside it, because scanning a range no discovery has
    ever seen a host in is the sweep this module exists to stop.
    """
    addresses = sorted(
        {
            parsed
            for parsed in (_parse_address(value) for value in discovered_addresses)
            if parsed is not None
        }
    )

    narrowed: list[dict] = []
    for target in targets:
        if target.get("targetType") != DiscoveryTargetType.NETWORK_RANGE.value:
            narrowed.append(target)
            continue

        network = _parse_network(str(target.get("approvedValue") or ""))
        if network is None:
            # Unparseable approved scope is left exactly as the customer
            # approved it. Dropping it would silently stop scanning something
            # they asked for; widening it is not on the table.
            narrowed.append(target)
            continue

        narrowed.extend(
            _host_target(target, address) for address in addresses if address in network
        )

    return narrowed

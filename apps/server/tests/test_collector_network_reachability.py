"""#320 — the capability question asked about reachability, not privilege."""

from src.core.constants.evidence_scanner_enums import (
    CollectorCapability,
    CollectorComponentStatus,
    CollectorReadinessStatus,
)
from src.core.services.collector_readiness_service import (
    CollectorReadiness,
    ComponentReadiness,
    collector_can_see_hardware_addresses_for,
)


def _readiness(*, raw_packet: bool) -> CollectorReadiness:
    """Built directly rather than through `readiness_from_tool_statuses`, which
    only iterates `ScannerToolName` — `raw_packet_access` is deliberately a
    *capability*, not a tool, because a missing binary is something an operator
    installs and a missing privilege is not."""
    return CollectorReadiness(
        status=CollectorReadinessStatus.READY.value,
        components=(
            ComponentReadiness(
                component_key=CollectorCapability.RAW_PACKET_ACCESS.value,
                status=(
                    CollectorComponentStatus.READY.value
                    if raw_packet
                    else CollectorComponentStatus.UNAVAILABLE.value
                ),
                version=None,
                reason_code=None,
            ),
        ),
        platform_connectivity_status="unknown",
        evidence_storage_status="unknown",
        collector_version=None,
        template_pack_version=None,
        reported_at=None,
    )


def _on(*networks: str) -> list[dict]:
    return [{"interface": "eth0", "address": n.split("/")[0], "network": n} for n in networks]


def test_a_collector_on_the_estate_can_see_its_hardware_addresses():
    assert collector_can_see_hardware_addresses_for(
        _readiness(raw_packet=True),
        network_segments=_on("192.168.50.0/24"),
        target="192.168.50.0/24",
    )


def test_docker_desktop_reports_the_privilege_and_still_cannot_reach_the_estate():
    """The exact case that made the platform confidently wrong, measured on
    Søren's Mac 2026-08-27: with `--cap-add=NET_RAW --network host` the raw
    socket opens, so the capability reads True — and the container sees only
    Docker's own bridges. The Mac's own LAN address 192.168.50.191 is absent
    entirely, because Docker Desktop's "host" network is the Linux VM's.

    Answered True, the platform would find no MAC anywhere and record every
    silent address as "nothing answered on this address" — worse than the
    honest "we were not able to look" it replaced."""
    assert not collector_can_see_hardware_addresses_for(
        _readiness(raw_packet=True),
        network_segments=_on("172.17.0.0/16", "172.20.0.0/16"),
        target="192.168.50.0/24",
    )


def test_a_collector_that_has_never_said_where_it_is_is_not_given_the_benefit():
    """`None` is silence, not a claim. Answering True on it is the unearned yes
    this function exists to stop."""
    assert not collector_can_see_hardware_addresses_for(
        _readiness(raw_packet=True), network_segments=None, target="192.168.50.0/24"
    )


def test_a_collector_that_found_no_segment_cannot_reach_anything():
    assert not collector_can_see_hardware_addresses_for(
        _readiness(raw_packet=True), network_segments=[], target="192.168.50.0/24"
    )


def test_the_privilege_is_still_required():
    """Position is what varies, but a Collector that genuinely cannot send raw
    packets still cannot ARP. Both have to hold."""
    assert not collector_can_see_hardware_addresses_for(
        _readiness(raw_packet=False),
        network_segments=_on("192.168.50.0/24"),
        target="192.168.50.0/24",
    )


def test_a_single_address_target_is_understood():
    """An approved target is written either as a range or as one host."""
    assert collector_can_see_hardware_addresses_for(
        _readiness(raw_packet=True),
        network_segments=_on("192.168.50.0/24"),
        target="192.168.50.1",
    )


def test_a_renumbered_network_is_not_reachable():
    """The live failure: the estate was approved for 192.168.1.0/24 and the
    network had moved to 192.168.50.0/24. Nothing in the product could say so."""
    assert not collector_can_see_hardware_addresses_for(
        _readiness(raw_packet=True),
        network_segments=_on("192.168.50.0/24"),
        target="192.168.1.0/24",
    )


def test_partial_overlap_counts_as_reachable():
    """A target wider than the Collector's own segment is partly reachable, and
    reporting that as none would send somebody hunting a permission problem
    that is really a scope one."""
    assert collector_can_see_hardware_addresses_for(
        _readiness(raw_packet=True),
        network_segments=_on("192.168.50.0/24"),
        target="192.168.0.0/16",
    )


def test_an_unparseable_target_reaches_nothing():
    assert not collector_can_see_hardware_addresses_for(
        _readiness(raw_packet=True),
        network_segments=_on("192.168.50.0/24"),
        target="not-an-address",
    )

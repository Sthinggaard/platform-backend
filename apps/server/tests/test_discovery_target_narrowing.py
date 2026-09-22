"""CA-09V — narrowing an approved scope to the hosts discovery already found.

The property under test is a safety one: **narrowing can only ever remove.**
Everything a scanner is handed must be provably inside something the customer
approved, whatever the artefact inventory happens to contain.
"""

from __future__ import annotations

from ipaddress import IPv4Address, IPv4Network

import pytest

from src.core.constants.discovery_run_enums import DiscoveryTargetType
from src.core.services.discovery_target_narrowing import narrow_targets_to_discovered_hosts


def _network_target(cidr: str, *, target_id: str = "net-1", name: str = "Network") -> dict:
    return {
        "targetId": target_id,
        "targetType": DiscoveryTargetType.NETWORK_RANGE.value,
        "displayName": name,
        "approvedValue": cidr,
        "networkType": "corporate",
        "approvedAt": "2026-08-27T09:53:32.802762",
        "approvedByUserId": 2,
    }


def _domain_target(domain: str) -> dict:
    return {
        "targetId": "dom-1",
        "targetType": DiscoveryTargetType.DOMAIN.value,
        "displayName": domain,
        "approvedValue": domain,
        "approvedAt": "2026-08-27T09:53:32.802762",
        "approvedByUserId": 2,
    }


# The live scope and inventory of org 7 on 2026-09-06: one approved /24 and the
# thirteen addresses nmap has actually observed inside it.
_ORG_7_RANGE = "192.168.50.0/24"
_ORG_7_DISCOVERED = [
    "192.168.50.1",
    "192.168.50.8",
    "192.168.50.96",
    "192.168.50.123",
    "192.168.50.129",
    "192.168.50.152",
    "192.168.50.176",
    "192.168.50.191",
    "192.168.50.197",
    "192.168.50.206",
    "192.168.50.226",
    "192.168.50.227",
    "192.168.50.236",
]


def test_a_range_becomes_the_hosts_discovery_found_inside_it():
    """The defect this exists for: nuclei was handed one /24, expanded it to
    256 addresses, and was killed at its time budget on every run."""
    narrowed = narrow_targets_to_discovered_hosts(
        [_network_target(_ORG_7_RANGE)], _ORG_7_DISCOVERED
    )

    assert [target["approvedValue"] for target in narrowed] == sorted(
        _ORG_7_DISCOVERED, key=IPv4Address
    )
    assert len(narrowed) == 13


def test_narrowing_never_emits_a_host_outside_the_approved_scope():
    """The safety property. An artefact observed on another network — a laptop
    seen at home, a cloud address, anything the inventory happens to hold — must
    never reach a scanner because it exists in the same organisation."""
    approved = _network_target(_ORG_7_RANGE)
    discovered = _ORG_7_DISCOVERED + [
        "10.20.0.5",  # a different approved range, not this command's
        "192.168.1.33",  # another org-approved range entirely
        "8.8.8.8",  # public internet
        "192.168.51.1",  # one bit outside the approved /24
    ]

    narrowed = narrow_targets_to_discovered_hosts([approved], discovered)

    network = IPv4Network(_ORG_7_RANGE)
    for target in narrowed:
        assert IPv4Address(target["approvedValue"]) in network


def test_a_range_with_no_discovered_host_contributes_nothing():
    """Not the range itself as a fallback — that is the blind sweep this
    replaces, and it is the one case where falling back would reintroduce the
    whole defect."""
    assert (
        narrow_targets_to_discovered_hosts([_network_target("10.99.0.0/24")], _ORG_7_DISCOVERED)
        == []
    )


def test_a_domain_target_passes_through_unchanged():
    """A domain is a name, not a range. There is nothing to narrow it to, and
    dropping it would stop scanning something the customer approved."""
    domain = _domain_target("risklence.com")

    assert narrow_targets_to_discovered_hosts([domain], _ORG_7_DISCOVERED) == [domain]


def test_approval_provenance_is_inherited_never_manufactured():
    """A narrowed host is still that approved target's scope. Who approved it
    and when is what an auditor reads, and it must come from the parent."""
    parent = _network_target(_ORG_7_RANGE)

    narrowed = narrow_targets_to_discovered_hosts([parent], ["192.168.50.152"])

    assert len(narrowed) == 1
    host = narrowed[0]
    assert host["targetId"] == parent["targetId"]
    assert host["approvedAt"] == parent["approvedAt"]
    assert host["approvedByUserId"] == parent["approvedByUserId"]
    assert host["networkType"] == parent["networkType"]
    assert host["targetType"] == DiscoveryTargetType.NETWORK_RANGE.value
    # The parent range stays legible in the console the operator watches.
    assert parent["displayName"] in host["displayName"]
    assert "192.168.50.152" in host["displayName"]


def test_an_unparseable_approved_value_is_left_exactly_as_approved():
    """Narrowing is an optimisation of an approved scope. It may remove hosts
    it can prove are outside; it must never drop a target it simply could not
    read, because that silently stops scanning something the customer asked
    for."""
    weird = _network_target("not-a-cidr")

    assert narrow_targets_to_discovered_hosts([weird], _ORG_7_DISCOVERED) == [weird]


def test_an_unparseable_discovered_address_is_ignored_not_scanned():
    narrowed = narrow_targets_to_discovered_hosts(
        [_network_target(_ORG_7_RANGE)], ["192.168.50.152", "", "not-an-ip", "::1"]
    )

    assert [target["approvedValue"] for target in narrowed] == ["192.168.50.152"]


def test_a_host_observed_twice_is_scanned_once():
    """`asset_identifiers` holds one row per artefact per identifier, so two
    artefacts sharing an address — or one re-observed — must not become two
    scans of the same host."""
    narrowed = narrow_targets_to_discovered_hosts(
        [_network_target(_ORG_7_RANGE)], ["192.168.50.176", "192.168.50.176"]
    )

    assert len(narrowed) == 1


def test_a_host_inside_two_approved_ranges_is_scanned_under_each():
    """Overlapping approved ranges are the customer's own configuration. Each
    keeps its own approval provenance, so neither is silently dropped."""
    narrowed = narrow_targets_to_discovered_hosts(
        [
            _network_target("192.168.50.0/24", target_id="net-a", name="A"),
            _network_target("192.168.50.128/25", target_id="net-b", name="B"),
        ],
        ["192.168.50.152"],
    )

    assert sorted(target["targetId"] for target in narrowed) == ["net-a", "net-b"]


@pytest.mark.parametrize("empty", [[], None])
def test_no_discovered_hosts_at_all_narrows_a_range_to_nothing(empty):
    """Before any discovery has run there is nothing to scan for
    vulnerabilities, and saying so is the truthful outcome — the Collector
    reports no coverage rather than a clean empty scan."""
    assert narrow_targets_to_discovered_hosts([_network_target(_ORG_7_RANGE)], empty or []) == []

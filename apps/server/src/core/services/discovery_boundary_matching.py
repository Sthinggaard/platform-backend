"""Does a value fall inside a set of domains or networks?

One definition, shared by environment detection and by the run-creation gate.
Two copies of this logic that drift apart would mean the boundary a human was
shown and the boundary actually enforced are different — the exact failure the
CA-05 contract is written to prevent.
"""

from __future__ import annotations

import ipaddress
import re


def matches_domain(value: str, domains: set[str]) -> bool:
    """Exact host match, or a subdomain of one of ``domains``.

    Suffix comparison is anchored on a dot so ``notexample.com`` never matches
    ``example.com`` — a bare ``endswith`` would silently pull a third party's
    host inside the boundary.
    """
    normalized = value.strip().lower()
    for domain in domains:
        candidate = domain.strip().lower()
        if not candidate:
            continue
        if normalized == candidate or normalized.endswith(f".{candidate}"):
            return True
    return False


def matches_network(value: str, networks: list) -> bool:
    try:
        address = ipaddress.ip_address(value.strip())
    except ValueError:
        return False
    return any(address in network for network in networks)


def parse_networks(cidrs) -> list:
    """Parse CIDRs, skipping malformed ones.

    Skipping fails closed for coverage checks (an unparseable range covers
    nothing) and fails closed for exclusion checks too, because an exclusion
    that cannot be parsed as a network is still compared as a literal string by
    the caller rather than being silently treated as matching nothing.
    """
    parsed = []
    for cidr in cidrs:
        try:
            parsed.append(ipaddress.ip_network(str(cidr).strip(), strict=False))
        except ValueError:
            continue
    return parsed


def is_within(value: str, patterns) -> bool:
    """True when ``value`` is caught by any of ``patterns``.

    A pattern may be a domain, a CIDR, or a literal host/address. Checked in
    that order so ``10.0.0.0/24`` catches ``10.0.0.15`` and ``example.com``
    catches ``api.example.com``, while anything else still matches literally.
    """
    normalized = value.strip().lower()
    pattern_list = [str(pattern).strip().lower() for pattern in patterns if str(pattern).strip()]
    if not pattern_list:
        return False

    if matches_domain(normalized, set(pattern_list)):
        return True
    if matches_network(normalized, parse_networks(pattern_list)):
        return True
    return normalized in set(pattern_list)


# A hostname label: letters/digits/hyphen, not starting or ending with a hyphen.
_HOSTNAME_LABEL = re.compile(r"^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$")


def is_scannable_identifier(value: str) -> bool:
    """Can this string actually be handed to a scanner as a target?

    True for IP addresses, CIDR ranges and dotted hostnames. False for business
    names like "Main firewall" or "AWS production", which is what the asset
    registry mostly holds — it has no hostname/IP column, only display_name.

    Proposing a business name as a discovery target would ask a human to
    approve scanning something that cannot be scanned, and would put a
    meaningless entry inside an approved boundary. Fails closed: anything not
    recognisably an address or hostname is rejected.
    """
    candidate = value.strip().lower()
    if not candidate or " " in candidate:
        return False

    try:
        ipaddress.ip_address(candidate)
        return True
    except ValueError:
        pass
    try:
        ipaddress.ip_network(candidate, strict=False)
        return True
    except ValueError:
        pass

    # Hostnames must be dotted — a bare single label ("firewall") is a name,
    # not something resolvable that a reviewer could sensibly approve.
    if "." not in candidate:
        return False
    labels = candidate.rstrip(".").split(".")
    return all(_HOSTNAME_LABEL.match(label) for label in labels)

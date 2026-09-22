"""#321 — the network this Collector is standing on.

**The fact nothing reported.** `describe_host()` sends architecture, kernel and
OS. It has never sent the Collector's own addresses, so the platform cannot ask
the one question that decides whether a scan can work at all: *is this Collector
attached to the network it is being asked to scan?*

Two failures followed from that, and both were live on 2026-08-27:

* The estate's approved target was ``192.168.1.0/24`` and the network had been
  renumbered to ``192.168.50.0/24``. Every artefact was an echo of a /24 that no
  longer existed, and nothing in the product was in a position to notice.
* ``check_raw_packet_capability()`` answers *may I send raw packets*, and Docker
  grants ``CAP_NET_RAW`` to root containers by default — so it answers **True
  almost everywhere**, including on Docker Desktop where the container sees only
  ``172.x`` bridges and can never ARP the estate. The platform was told it could
  see hardware addresses in exactly the case where it could not (#320).

**Reported, never interpreted here.** This module states what the Collector is
attached to. Whether that covers a given scan target is the platform's judgement,
because the platform is what holds the approved targets — and because a Collector
deciding it need not scan something would be a Collector deciding scope.
"""

from __future__ import annotations

import fcntl
import ipaddress
import socket
import struct
from dataclasses import dataclass

#: Interfaces that never say anything about reaching an estate. Loopback is the
#: container talking to itself; Docker's own bridges are the container talking to
#: its siblings — which is precisely the false positive on Docker Desktop, where
#: they are *all* a `--network host` container can see.
_IGNORED_PREFIXES = ("lo", "docker", "br-", "veth", "virbr", "cni", "flannel", "kube")


@dataclass(frozen=True)
class NetworkSegment:
    """One network this Collector has an address on."""

    interface: str
    address: str
    #: The segment in CIDR form, e.g. ``192.168.50.0/24`` — what a target has to
    #: fall inside for an ARP to be possible at all.
    network: str


def detect_network_segments() -> tuple[NetworkSegment, ...]:
    """Every non-container IPv4 segment this Collector is attached to.

    Read with ``ioctl`` on the interfaces the kernel lists, not by shelling out:
    the runtime image is ``python:3.11-slim`` and has **no ``iproute2``**, so an
    ``ip addr`` implementation silently found nothing and fell through to a
    weaker path — which is how a Docker bridge came to be reported as an estate
    segment in the first place. This bundle also ships three runtime
    dependencies on purpose (CA-03), so a library for this was never an option.

    Returns nothing when the interfaces cannot be read. **Not knowing where the
    Collector sits must read as "we cannot say", never as "nowhere" and never as
    a guess** — an unearned answer here is what tells the platform it can see
    hardware addresses when it cannot (#320).
    """
    #: `SIOCGIFADDR` / `SIOCGIFNETMASK` — the kernel's own answer for one
    #: interface. Stable Linux ABI constants; named rather than inlined so the
    #: two calls below cannot drift apart.
    SIOCGIFADDR = 0x8915
    SIOCGIFNETMASK = 0x891B

    try:
        interfaces = socket.if_nameindex()
    except OSError:
        return ()

    found: list[NetworkSegment] = []
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        for _, name in interfaces:
            if name.startswith(_IGNORED_PREFIXES):
                continue
            address = _ioctl_address(sock, SIOCGIFADDR, name)
            netmask = _ioctl_address(sock, SIOCGIFNETMASK, name)
            if address is None or netmask is None:
                # An interface that is up but unaddressed, or one the kernel
                # will not answer for. Skipped rather than half-reported.
                continue
            segment = _segment(name, f"{address}/{netmask}")
            if segment is not None:
                found.append(segment)
    return tuple(found)


def _ioctl_address(sock: socket.socket, request: int, interface: str) -> str | None:
    """One dotted-quad out of an interface ioctl, or None if it has none."""
    try:
        packed = fcntl.ioctl(
            sock.fileno(), request, struct.pack("256s", interface.encode()[:15])
        )
    except OSError:
        return None
    return socket.inet_ntoa(packed[20:24])


def _segment(interface: str, cidr: str) -> NetworkSegment | None:
    try:
        interface_address = ipaddress.ip_interface(cidr)
    except ValueError:
        return None
    address = interface_address.ip
    if address.is_loopback or address.is_link_local or address.is_multicast:
        return None
    return NetworkSegment(
        interface=interface,
        address=str(address),
        network=str(interface_address.network),
    )

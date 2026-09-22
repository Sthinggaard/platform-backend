"""What a discovered artefact actually is, derived from the evidence (BUG-DISC-15).

The previous rule inferred nothing at all. ``layer`` was "Application" if a host
had any open port and "Network" if it had none — so it recorded *whether the
scan found ports*, not what the thing is, and a router with 53/80/443/5060 open
became an "Application". ``type`` was worse: it read a key nmap never emits, so
**every** discovered artefact was a "Service" without exception.

That matters beyond a wrong label. Layer and type feed how an artefact is
presented, grouped and reasoned about downstream, and CA-06 is about to make
these rows *stable* and reconciled across runs — so a wrong class stops being a
per-run mistake and becomes a persistent one.

Two rules govern this module:

* **Only claim what the evidence supports.** Every classification below is
  reached from an observed service name. Where the evidence does not support a
  purpose, the answer is ``OBSERVED_HOST`` — something answered at this address
  and no more is claimed. The platform recommends and explains; it does not
  assert a class it cannot support.
* **A human outranks it.** ``artefact_review_service`` lets a reviewer correct
  both fields and marks the classification as theirs
  (``intent.classificationSetByHuman``), which normalisation checks before
  re-deriving. Where no person has classified a row, later runs *do* re-derive
  it: the platform's earlier guess carries no more authority than today's, so
  rows improve as this module does rather than being frozen at the first scan.

Layers are the canonical ``OSILayer`` ids from ``constants/osi.py`` — the same
vocabulary ``ALLOWED_LAYERS_BY_ARCHETYPE`` already maps every manually-created
asset onto. The free-text words this column also holds ("Application",
"Hardware", "Transfer") are legacy and are not extended here. The **id** is what
is stored; rendering it as a name is the reading side's job, via
``layer_short_label``.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from collections.abc import Sequence
from typing import Any

from src.core.constants.osi import OSILayer


class ArtefactType(StrEnum):
    WEB_SERVICE = "Web service"
    DATABASE = "Database"
    NETWORK_DEVICE = "Network device"
    IDENTITY_SERVICE = "Identity service"
    REMOTE_ACCESS = "Remote access"
    #: Something answered at this address and we cannot say more than that. Not
    #: "Unknown": a host that responded to a scan is a host, which is a fact
    #: rather than a guess, and telling a reviewer "Unknown · Unknown" for every
    #: row makes a real inventory look like a failed one.
    OBSERVED_HOST = "Observed host"


class ArtefactCandidacy(StrEnum):
    """Whether a business service could depend on this thing at all.

    Separate from *what* an artefact is and from *what a person decided about
    it*, because it answers a different question and changes for different
    reasons. It is the answer to the only question that makes a 500-row estate
    reviewable: a phone on the company WiFi is not a dependency of Checkout —
    not because it is a phone, but because nothing can call it.

    Deliberately not a device-type guess. We cannot tell a phone from a
    Raspberry Pi: the scan is an unprivileged TCP connect, and the host record
    holds an IP and a list of services and nothing else — no MAC, no OUI vendor,
    no DHCP hostname, no OS fingerprint (see BUG-DISC-19). Classifying by
    "can anything depend on this?" needs none of that, and stays true when the
    same physical device is used differently.
    """

    #: Something is listening that a business service could depend on.
    SERVICE_BEARING = "service_bearing"
    #: Present inside the approved boundary, exposing nothing depend-able.
    #: Recorded, never discarded — an auditor is entitled to see everything the
    #: scan found, and a warehouse handheld or a Pi running a door controller is
    #: an endpoint that may still matter.
    ENDPOINT = "endpoint"
    #: Something is listening but we have no grounds to call it either way.
    #: A real answer, and the safe one: calling this an endpoint could hide a
    #: genuine dependency behind a collapsed section.
    UNDETERMINED = "undetermined"


# Services that indicate a device someone uses, rather than one something
# depends on. Kept deliberately short: every entry here can hide a row from the
# default view, so it earns its place only where the service is characteristic
# of consumer/desktop equipment rather than of a server.
_ENDPOINT_SIGNATURE_SERVICES: frozenset[str] = frozenset(
    {
        # Printing
        "ipp",
        "printer",
        "jetdirect",
        # Consumer/desktop discovery and file sharing
        "mdns",
        "afpovertcp",
        "eppc",
        "netbios-ssn",
    }
)


@dataclass(frozen=True)
class ObservedService:
    """One thing heard on one port, and how well it is actually known."""

    #: nmap's own word for it, kept raw. Translating here would put business
    #: language in the wrong layer, and the raw value is what makes a chip
    #: traceable back to the scan that produced it.
    name: str
    port: int | None
    #: True when nmap *probed* the port and concluded this, false when it read
    #: the name out of its static port-number table. The distinction #249 exists
    #: for: a table entry carries no more information than the port number.
    probed: bool


@dataclass(frozen=True)
class ArtefactClassification:
    layer: str
    asset_type: str
    candidacy: str
    #: Every service name observed on the host, not only the ones that decided
    #: the class. This is what the reviewer actually needs when the class is
    #: generic — "Observed host · Infrastructure" says little, the same row with
    #: "http, domain, https" says plenty.
    observed: tuple[str, ...]
    #: The same services, with what is actually known about each. ``observed``
    #: above is a bare list of nmap's words, and those words are not all the
    #: same kind of claim: ``https`` on a probed port is an observation, while
    #: ``http-proxy`` on an unprobed one is nmap restating "port 8080" from its
    #: static table. Rendered identically — which is what a row of grey chips
    #: did — a guess is presented to an executive as a finding.
    #:
    #: Facts only, no phrasing. Which of these is worth a word, and what word,
    #: is the tenant's decision (see this module's own rule about business
    #: language belonging to the reading side).
    observed_evidence: tuple[ObservedService, ...] = ()


# Observed nmap service names, mapped to what they are evidence *of*. Kept small
# and explicit on purpose: a long list of clever inferences is how the previous
# version's guessing crept in. Anything absent here is not classified.
_SERVICE_EVIDENCE: dict[str, tuple[str, ArtefactType]] = {
    # Web and application runtimes
    "http": (OSILayer.L5_APPLICATION.value, ArtefactType.WEB_SERVICE),
    "https": (OSILayer.L5_APPLICATION.value, ArtefactType.WEB_SERVICE),
    "http-alt": (OSILayer.L5_APPLICATION.value, ArtefactType.WEB_SERVICE),
    "http-proxy": (OSILayer.L5_APPLICATION.value, ArtefactType.WEB_SERVICE),
    "https-alt": (OSILayer.L5_APPLICATION.value, ArtefactType.WEB_SERVICE),
    # Data stores
    "mysql": (OSILayer.L6_DATA.value, ArtefactType.DATABASE),
    "postgresql": (OSILayer.L6_DATA.value, ArtefactType.DATABASE),
    "ms-sql-s": (OSILayer.L6_DATA.value, ArtefactType.DATABASE),
    "mongodb": (OSILayer.L6_DATA.value, ArtefactType.DATABASE),
    "redis": (OSILayer.L6_DATA.value, ArtefactType.DATABASE),
    "oracle": (OSILayer.L6_DATA.value, ArtefactType.DATABASE),
    # Network infrastructure
    "domain": (OSILayer.L2_NETWORK.value, ArtefactType.NETWORK_DEVICE),
    "snmp": (OSILayer.L2_NETWORK.value, ArtefactType.NETWORK_DEVICE),
    "dhcps": (OSILayer.L2_NETWORK.value, ArtefactType.NETWORK_DEVICE),
    "bootps": (OSILayer.L2_NETWORK.value, ArtefactType.NETWORK_DEVICE),
    "upnp": (OSILayer.L2_NETWORK.value, ArtefactType.NETWORK_DEVICE),
    # Identity
    "ldap": (OSILayer.L7_GOVERNANCE.value, ArtefactType.IDENTITY_SERVICE),
    "ldaps": (OSILayer.L7_GOVERNANCE.value, ArtefactType.IDENTITY_SERVICE),
    "kerberos-sec": (OSILayer.L7_GOVERNANCE.value, ArtefactType.IDENTITY_SERVICE),
    # Remote access — deliberately its own type rather than folded into
    # "Application": an exposed management path is a different conversation
    # from a business service, and flattening them loses the distinction.
    "ssh": (OSILayer.L1_PHYSICAL.value, ArtefactType.REMOTE_ACCESS),
    "telnet": (OSILayer.L1_PHYSICAL.value, ArtefactType.REMOTE_ACCESS),
    "ms-wbt-server": (OSILayer.L1_PHYSICAL.value, ArtefactType.REMOTE_ACCESS),
}

# Administrative access paths (SSH, RDP, telnet) sit on almost everything and
# say very little about what a thing *is*. Treating them as evidence of purpose
# would classify a database server by the fact that someone can log into it, so
# they are set aside while deciding purpose and used only when nothing else was
# observed.
_ADMINISTRATIVE_TYPES: frozenset[ArtefactType] = frozenset({ArtefactType.REMOTE_ACCESS})

# Where several *purpose* services disagree, that disagreement is the finding.
# A host answering DNS and serving a web UI is genuinely ambiguous — a router
# with an admin page and a web server that also runs DNS look identical from
# outside — so it is reported as unknown rather than resolved by precedence.
# This is the exact case that produced "192.168.1.1 — Service · Application".


def service_artefact_type(service_name: str) -> ArtefactType | None:
    """What kind of thing a service name is evidence of, or ``None`` if unknown.

    The public way to read ``_SERVICE_EVIDENCE``. CA-09A.3 needs the same
    mapping to say what an artefact *does*, and a second copy of the table there
    would drift the first time a service was added to one and not the other.
    One definition, reached through a name rather than through an underscore.
    """
    return _SERVICE_EVIDENCE.get(service_name.strip().lower(), (None, None))[1]


def is_administrative(artefact_type: ArtefactType | None) -> bool:
    """Whether this type is a way *in* rather than a thing the business uses.

    Exposed for the same reason as above: an exposed management path is a
    different conversation from a business service, and every caller deciding
    purpose has to set it aside the same way.
    """
    return artefact_type in _ADMINISTRATIVE_TYPES


def derive_candidacy(observed: Sequence[str]) -> ArtefactCandidacy:
    """Can a business service depend on this?

    Defined over the observed service names alone, so it can be answered both
    while classifying a fresh host record and later from what was stored on the
    artefact — one definition, no drift between the two.

    ``ENDPOINT`` is only ever returned on positive grounds: nothing is
    listening, or what is listening is characteristic of equipment people use
    rather than depend on. Anything else that listens and is not recognised
    stays ``UNDETERMINED``, because a wrong ``ENDPOINT`` hides a real dependency
    behind a collapsed section, while a wrong ``UNDETERMINED`` only leaves a row
    in the list a moment longer.
    """
    names = [name.strip().lower() for name in observed if isinstance(name, str) and name.strip()]
    if not names:
        # Nothing is listening, so nothing can call it. This is the single
        # biggest reduction on a real estate — most of what a scan finds are
        # devices that answered and expose nothing at all.
        return ArtefactCandidacy.ENDPOINT

    purpose = [
        name
        for name in names
        if name in _SERVICE_EVIDENCE
        and _SERVICE_EVIDENCE[name][1] not in _ADMINISTRATIVE_TYPES
        and name not in _ENDPOINT_SIGNATURE_SERVICES
    ]
    if purpose:
        return ArtefactCandidacy.SERVICE_BEARING

    if all(name in _ENDPOINT_SIGNATURE_SERVICES for name in names):
        return ArtefactCandidacy.ENDPOINT

    # Only an administrative path, or something listening we do not recognise.
    # Both are real possibilities for a dependency — a jump host is reached over
    # SSH, and an unrecognised port is still a port — so neither is hidden.
    return ArtefactCandidacy.UNDETERMINED


#: The key normalisation writes the observed service names under on ``intent``.
#: Named once, because two surfaces read it back and a typo in either would
#: silently mean "nothing was listening" rather than failing.
OBSERVED_SERVICES_KEY = "observedServices"


def stored_service_names(intent: Any) -> tuple[str, ...]:
    """Read back the service names normalisation stored on an artefact.

    The counterpart to ``_observed_service_names`` below, which reads the raw
    scan record at ingest time — this reads what was kept. Both feed
    ``derive_candidacy``, so the answer is the same whether it is asked while
    classifying a fresh host or later from the stored artefact.

    Defensive throughout because ``intent`` is a JSON column that predates the
    key: an artefact ingested before it simply has none, and that must read as
    an empty list rather than raise.
    """
    if not isinstance(intent, dict):
        return ()
    observed = intent.get(OBSERVED_SERVICES_KEY)
    if not isinstance(observed, list):
        return ()
    return tuple(str(name) for name in observed if isinstance(name, str) and name.strip())


def _observed_service_names(host_record: dict[str, Any]) -> list[str]:
    services = host_record.get("services")
    if not isinstance(services, list):
        return []
    names: list[str] = []
    for service in services:
        if not isinstance(service, dict):
            continue
        name = service.get("service")
        if isinstance(name, str) and name.strip():
            names.append(name.strip().lower())
    return names


def _observed_service_evidence(host_record: dict[str, Any]) -> tuple[ObservedService, ...]:
    """Every open port, with what is actually known about it.

    Parallel to ``_observed_service_names`` rather than replacing it: the
    classification rules above are keyed on names and de-duplicated, while a
    reader needs one entry per *port* — two ports both called ``http`` are two
    things to look at, and collapsing them loses which port to go and check.

    ``method`` comes straight from nmap (#249). Absent — an older evidence
    document, or a scan that never recorded it — is reported as not probed,
    which is the same downward direction every other unknown in this domain
    takes: never claim a probe that cannot be shown to have happened.
    """
    services = host_record.get("services")
    if not isinstance(services, list):
        return ()
    evidence: list[ObservedService] = []
    for service in services:
        if not isinstance(service, dict):
            continue
        name = service.get("service")
        if not isinstance(name, str) or not name.strip():
            continue
        port = service.get("port")
        evidence.append(
            ObservedService(
                name=name.strip().lower(),
                port=port if isinstance(port, int) else None,
                probed=service.get("method") == "probed",
            )
        )
    return tuple(evidence)


def classify_host_record(host_record: dict[str, Any]) -> ArtefactClassification:
    """Say the most the evidence supports, and never less.

    The floor is deliberately not "Unknown". Something answered at this address,
    so it is a host — infrastructure — and that is observed rather than
    inferred. Above that floor, a recognised set of services names what the host
    is *for*, and genuinely conflicting evidence falls back to the floor rather
    than picking a winner.
    """
    observed = _observed_service_names(host_record)
    observed_tuple = tuple(sorted(set(observed)))
    evidence = _observed_service_evidence(host_record)

    # What is true of anything that answered: a host is there.
    candidacy = derive_candidacy(observed)
    floor = ArtefactClassification(
        layer=OSILayer.L1_PHYSICAL.value,
        asset_type=ArtefactType.OBSERVED_HOST.value,
        candidacy=candidacy.value,
        observed=observed_tuple,
        observed_evidence=evidence,
    )

    matched = [
        (name, _SERVICE_EVIDENCE[name]) for name in observed if name in _SERVICE_EVIDENCE
    ]
    if not matched:
        return floor

    purpose = [
        (name, layer, asset_type)
        for name, (layer, asset_type) in matched
        if asset_type not in _ADMINISTRATIVE_TYPES
    ]
    if not purpose:
        # Only an administrative path was observed — a real statement: something
        # is reachable and manageable.
        layer, asset_type = matched[0][1]
        return ArtefactClassification(
            layer=layer,
            asset_type=asset_type.value,
            candidacy=candidacy.value,
            observed=observed_tuple,
            observed_evidence=evidence,
        )

    distinct_layers = {layer for _, layer, _ in purpose}
    distinct_types = {asset_type for _, _, asset_type in purpose}
    if len(distinct_layers) > 1 or len(distinct_types) > 1:
        # A router with an admin page and a web server that also runs DNS look
        # identical from outside. Naming one would be a guess; the host itself
        # is not in doubt, and the observed services are on the row for a human
        # to read.
        return floor

    return ArtefactClassification(
        layer=next(iter(distinct_layers)),
        asset_type=next(iter(distinct_types)).value,
        candidacy=candidacy.value,
        observed=observed_tuple,
        observed_evidence=evidence,
    )

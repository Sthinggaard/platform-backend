"""CA-07.1 slice 1 — name an artefact from the evidence a scan already returned.

The problem this solves, in one line from a real discovery run:

    192.168.1.33 · Web service · Application · http, http-alt, http-proxy, ssh

Those are nmap's port-number nicknames, emitted from the port number alone. The
row says "ports 80, 8080, 8000 and 22 are open" and nothing else, so a Plane
instance and a monitoring dashboard on adjacent addresses render identically.
This module reads what version detection and the `http-title`/`ssl-cert` scripts
returned and produces the name — or records, precisely, why there isn't one.

Deliberately *not* here: what the artefact is **for**. Naming a host says nothing
about which business service depends on it; business purpose arrives through
process → service → slot and must not migrate onto the artefact
(Søren, 2026-08-18). This module answers "what is it?", never "does it matter?".
"""

from __future__ import annotations

import ipaddress

import re
from dataclasses import dataclass
from typing import Any, Sequence

from src.core.constants.artefact_identity_evidence_enums import (
    IDENTITY_BASIS_PRECEDENCE,
    IDENTITY_UNDETERMINED_EXPLANATION,
    ArtefactIdentityBasis,
    ArtefactIdentityUndetermined,
)

#: Titles that are a web server's state, not an application's name. A row
#: reading "502 Bad Gateway" would be worse than an unnamed one: it looks like
#: an identity and is actually a transient condition, and it would be wrong the
#: moment the service recovered. Matched case-insensitively as a whole title.
_NON_IDENTIFYING_TITLES: frozenset[str] = frozenset(
    {
        "400 bad request",
        "401 unauthorized",
        "403 forbidden",
        "404 not found",
        "500 internal server error",
        "502 bad gateway",
        "503 service unavailable",
        "504 gateway timeout",
        "site not found",
        "welcome to nginx!",
        "apache2 ubuntu default page: it works",
        "it works!",
        "test page for the apache http server",
        "index of /",
        "document moved",
        "moved permanently",
        "redirecting...",
        "loading...",
        "untitled",
    }
)

#: Titles that vary too much to list literally, because nmap builds them from
#: the response. `http-title` reports a page with no `<title>` as
#: "Site doesn't have a title (text/html; charset=utf-8)." — the content type
#: is interpolated, so no fixed-string set can ever catch them all.
#:
#: Found on a real inventory, 2026-08-25: two artefacts were **named**
#: "Site doesn't have a title (text/html)". That is nmap stating there is no
#: name, rendered as though it were one — the exact failure this module exists
#: to prevent, and worse than an unnamed row because it looks like an answer.
_NON_IDENTIFYING_TITLE_PATTERNS: tuple[re.Pattern[str], ...] = (
    re.compile(r"^site\s+doesn'?t\s+have\s+a\s+title\b", re.IGNORECASE),
    re.compile(r"^did\s+not\s+follow\s+redirect\b", re.IGNORECASE),
)
# Deliberately no "any three digits followed by words" rule for status lines:
# it would also swallow "404 Tech Blog", and dropping a real name is the one
# failure a filter here must not introduce. Literal statuses stay in the set
# above, where each entry is a decision rather than a side effect.

#: `ssl-cert` output is a multi-line block; the subject line carries the CN.
_CERT_SUBJECT_CN = re.compile(r"Subject:.*?\bcommonName=([^\n/,]+)", re.IGNORECASE | re.DOTALL)

#: A certificate CN that is an IP address names nothing a person did not already
#: see in the address column.
_IP_LIKE = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")


@dataclass(frozen=True)
class DeterminedIdentity:
    """What this artefact is, and how that was established.

    Exactly one of `name` / `undetermined_reason` is set. A caller never has to
    decide whether an empty name means "unknown" or "not looked at" — that
    distinction is carried explicitly, because it is the distinction CA-07.1
    exists to put in front of a person.
    """

    name: str | None
    basis: str | None
    evidence: str | None
    undetermined_reason: str | None
    #: Every basis that independently produced a name, strongest first —
    #: including the winning one. Søren, 2026-08-27: *"the title and the TLS
    #: certificate might make the mapping stronger."* He is right, and the
    #: winner alone cannot say so: two independent readings that agree are a
    #: better claim than either on its own, and that fact was being discarded
    #: the moment precedence picked one. Empty when nothing was determined.
    corroborating_bases: tuple[str, ...] = ()

    @property
    def determined(self) -> bool:
        return self.name is not None

    @property
    def explanation(self) -> str | None:
        """Why there is no name, in business language. None when there is one."""
        if self.undetermined_reason is None:
            return None
        return IDENTITY_UNDETERMINED_EXPLANATION.get(self.undetermined_reason)


def determine_identity(
    host_record: dict[str, Any],
    *,
    fingerprinting_ran: bool | None = None,
    hardware_addresses_visible: bool | None = None,
) -> DeterminedIdentity:
    """Read a name out of one host record's evidence.

    `fingerprinting_ran` says whether the scan that produced this record was
    authorised to run version detection. Passed explicitly rather than guessed,
    because the guess is exactly the thing that must not be wrong: a host that
    *was* probed and yielded nothing is a candidate for deeper access, and a
    host that was never probed is not. When the caller genuinely does not know,
    `None` infers it from whether any identifying evidence is present at all —
    conservative, and it can only ever under-claim.

    #249 slice 2 — that inference is now the *last* resort rather than the only
    one. The evidence adapter records what the scan actually did, read from
    nmap's own output, so a caller passing `None` normally gets a fact off the
    host record. The ladder is: what the caller was told, then what the scan
    recorded, then the guess.
    """
    if fingerprinting_ran is None:
        fingerprinting_ran = host_record.get("fingerprinting_ran")
    # CA-09A.2 — the same ladder, for the same reason. Whether the Collector
    # could see hardware addresses is a property of the Collector, not of a
    # host, and it is *reported* rather than inferred: absence of a MAC can
    # only ever be read as "we did not look", which is precisely the answer
    # that has to be earned. Deliberately **not** inferred from whether a MAC
    # turned up.
    if hardware_addresses_visible is None:
        hardware_addresses_visible = host_record.get("hardware_addresses_visible")
    services = _services(host_record)

    candidates: dict[ArtefactIdentityBasis, tuple[str, str]] = {}

    for service in services:
        scripts = service.get("scripts")
        if isinstance(scripts, dict):
            title = _clean_http_title(scripts.get("http-title"))
            if title and ArtefactIdentityBasis.HTTP_TITLE not in candidates:
                # #324 — the name loses the page's tagline; the evidence keeps
                # it. A reader has to be able to see exactly what was read off
                # the page in order to disagree with the conclusion drawn from
                # it, and "Plane" alone does not let them.
                candidates[ArtefactIdentityBasis.HTTP_TITLE] = (_without_tagline(title), title)
            cert_name = _certificate_common_name(scripts.get("ssl-cert"))
            if cert_name and ArtefactIdentityBasis.TLS_CERTIFICATE not in candidates:
                candidates[ArtefactIdentityBasis.TLS_CERTIFICATE] = (
                    _without_certificate_scaffolding(cert_name),
                    cert_name,
                )

        product = _clean(service.get("product"))
        if product and ArtefactIdentityBasis.SERVICE_PRODUCT not in candidates:
            version = _clean(service.get("version"))
            candidates[ArtefactIdentityBasis.SERVICE_PRODUCT] = (
                f"{product} {version}" if version else product,
                product,
            )

    vendor = _clean(host_record.get("vendor"))
    if vendor:
        candidates[ArtefactIdentityBasis.HARDWARE_VENDOR] = (vendor, vendor)


    ranked = [basis for basis in IDENTITY_BASIS_PRECEDENCE if basis in candidates]
    if ranked:
        winner = ranked[0]
        name, evidence = candidates[winner]
        return DeterminedIdentity(
            name=name,
            basis=winner.value,
            evidence=evidence,
            undetermined_reason=None,
            # Every basis that produced a name, not only the one that won.
            # Whether they *agree* is the reader's question and the matcher's,
            # and neither can ask it if only the winner survives this function.
            corroborating_bases=tuple(basis.value for basis in ranked),
        )

    return DeterminedIdentity(
        name=None,
        basis=None,
        evidence=None,
        undetermined_reason=_undetermined_reason(
            services,
            fingerprinting_ran=fingerprinting_ran,
            hardware_addresses_visible=hardware_addresses_visible,
        ),
    )


def _undetermined_reason(
    services: Sequence[dict[str, Any]],
    *,
    fingerprinting_ran: bool | None,
    hardware_addresses_visible: bool | None = None,
) -> str:
    if not services:
        # CA-09A.2 — "nothing is here" and "we were not allowed to look" are
        # opposite findings, and only one of them is a reason to stop. Reported
        # apart only when the Collector positively said it cannot see hardware
        # addresses; `None` means nobody told us, which is not the same as a no
        # and keeps the older, weaker answer.
        if hardware_addresses_visible is False:
            return ArtefactIdentityUndetermined.HARDWARE_NOT_VISIBLE.value
        return ArtefactIdentityUndetermined.NOTHING_LISTENING.value
    if fingerprinting_ran is None:
        # Inferred, and only ever downwards: version detection populates
        # `product` or script output on *something* it recognises, so their total
        # absence across every open port is consistent with never having probed.
        # Claiming "we probed and found nothing" on that basis would manufacture
        # an argument for deeper access, so the weaker answer is chosen.
        fingerprinting_ran = any(_clean(service.get("product")) or service.get("scripts") for service in services)
    if not fingerprinting_ran:
        return ArtefactIdentityUndetermined.NOT_PROBED.value
    return ArtefactIdentityUndetermined.PROBED_NOTHING_IDENTIFYING.value


def _services(host_record: dict[str, Any]) -> list[dict[str, Any]]:
    services = host_record.get("services")
    if not isinstance(services, list):
        return []
    return [service for service in services if isinstance(service, dict)]


def _clean(value: Any) -> str | None:
    if not isinstance(value, str):
        return None
    stripped = value.strip()
    return stripped or None


def _clean_http_title(value: Any) -> str | None:
    """The page title, unless it is a server state rather than a name.

    `http-title` appends its own note when the title came from a redirect
    target; that note is nmap's commentary, not part of the name.
    """
    title = _clean(value)
    if title is None:
        return None
    title = title.split("\n", 1)[0].strip()
    for suffix in ("(request redirected to", "Did not follow redirect to"):
        marker = title.find(suffix)
        if marker != -1:
            title = title[:marker].strip()
    title = title.strip(" .")
    if not title or title.lower() in _NON_IDENTIFYING_TITLES:
        return None
    if any(pattern.match(title) for pattern in _NON_IDENTIFYING_TITLE_PATTERNS):
        return None
    # Returned whole. The *name* is trimmed at the call site; the evidence is
    # what the page actually said, and the two are different questions.
    return title


#: Separators a page title conventionally puts between the product's name and
#: whatever the page wants to say about it. A browser tab is written to be read
#: at a glance, so the name comes first and the pitch follows.
_TAGLINE_SEPARATORS = (" | ", " – ", " — ", " · ", " :: ", " - ")

#: Below this, what follows a separator is more likely part of the name than a
#: description of it — "Grafana - Prod" should survive whole.
_TAGLINE_MIN_WORDS = 4


def _without_tagline(title: str) -> str:
    """The product's name, without the sentence the page appended to it.

    #324. On the live estate this read
    ``Plane | Simple, extensible, open-source project management tool`` — a
    browser tab written for a browser tab, standing in an inventory as the name
    of an asset. It makes a row read as marketing copy rather than a thing the
    organisation owns.

    **Conservative on purpose.** Only the leading segment is taken, and only
    when what follows is long enough to read as a *description* rather than as
    part of a name. ``Grafana - Prod`` and ``app-01 | eu-west`` survive whole;
    they are qualifiers, not pitches. The untrimmed string is still stored as
    the identity's ``evidence``, so the claim stays auditable and a reader can
    see exactly what was read off the page.
    """
    for separator in _TAGLINE_SEPARATORS:
        head, found, tail = title.partition(separator)
        if not found:
            continue
        head, tail = head.strip(), tail.strip()
        if head and len(tail.split()) >= _TAGLINE_MIN_WORDS:
            return head
    return title


def _certificate_common_name(value: Any) -> str | None:
    raw = _clean(value)
    if raw is None:
        return None
    match = _CERT_SUBJECT_CN.search(raw)
    if match is None:
        return None
    common_name = match.group(1).strip()
    # A wildcard or IP subject names nothing beyond what the address column
    # already showed.
    if not common_name or common_name.startswith("*") or _IP_LIKE.match(common_name):
        return None
    # Whole, for the same reason as the title above.
    return common_name


#: Words a certificate's subject carries *about the certificate*, which are no
#: part of what the thing is called. A router presenting a CN of
#: ``RT-BE50-D604 Server Certificate`` is called ``RT-BE50-D604``.
_CERTIFICATE_SCAFFOLDING = (
    " server certificate",
    " client certificate",
    " self-signed certificate",
    " ssl certificate",
    " tls certificate",
    " certificate",
)


def _without_certificate_scaffolding(common_name: str) -> str:
    """The subject, minus the words describing the certificate itself.

    #324. Stripped only from the **end**, and only as a whole trailing phrase:
    a CN that is genuinely a hostname must be left exactly as it is.
    ``www.asusrouter.com`` came back correct from the same scan and must not be
    touched by this.
    """
    lowered = common_name.lower()
    for suffix in _CERTIFICATE_SCAFFOLDING:
        if lowered.endswith(suffix):
            trimmed = common_name[: -len(suffix)].strip(" -–—,")
            # Never trim a subject away to nothing: a CN that is only the word
            # "Certificate" says nothing either way, and returning the original
            # at least keeps the evidence honest.
            return trimmed or common_name
    return common_name


def stored_identity(asset_intent: Any) -> dict[str, str | None]:
    """Read back what normalisation determined, from an artefact's ``intent``.

    One reader, because there are now two surfaces asking the same question —
    the standing inventory and the discovery review list — and an artefact that
    reads "Unidentified device" on one page and ``192.168.1.20`` on the other is
    the same record contradicting itself.

    Defensive by necessity: ``intent`` is a JSON column that predates the
    identity block, so every artefact ingested before CA-07.1 simply has no such
    key. Those report "not established" rather than raising, and the explanation
    is **not** recomposed here — it was written by ``DeterminedIdentity`` at
    ingestion, and rebuilding the sentence in a second place is how two versions
    of what the platform told somebody start to disagree.
    """
    intent = asset_intent if isinstance(asset_intent, dict) else {}
    identity = intent.get("identity")
    address = intent.get("networkAddress")
    resolved = {
        "network_address": address if isinstance(address, str) and address.strip() else None,
        "identity_name": None,
        "identity_basis": None,
        "identity_undetermined_reason": None,
        "identity_explanation": None,
    }
    if isinstance(identity, dict):
        resolved["identity_name"] = identity.get("name")
        resolved["identity_basis"] = identity.get("basis")
        resolved["identity_undetermined_reason"] = identity.get("undeterminedReason")
        resolved["identity_explanation"] = identity.get("explanation")
    return resolved



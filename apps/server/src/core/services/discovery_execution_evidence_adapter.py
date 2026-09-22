"""Step 4.2 Part 2 — DISC-32: DiscoveryExecutionEvidenceAdapter.

Plugs the execution pipeline's own ``EvidencePackage`` rows into the
existing, already-working Step 4.1A normalization boundary
(``discovery_normalization_service._ADAPTERS``) — the scanner-sourced
adapter that module's own docstring long flagged as a defined extension
point. Resolves the ``execution_id: int`` vs. UUID-string typing gap
flagged back at ``DISC-17`` (``CollectorOutputAdapter.normalize``'s
``execution_id`` is now ``int | str`` — see that module).

Reuses ``risk_intelligence_normalization_service.normalize_ingestion_batch``
— the real, already-tested asset-matching/signal/finding engine — rather
than duplicating it: this adapter's only real job is turning one
``EvidencePackage``'s stored evidence into the generic
``{"hosts": [...]}`` JSON shape that engine already knows how to consume,
wrapped in an ephemeral ``RiskIngestionBatch`` row (``source_name``
identifies it as execution-pipeline-sourced, not a real uploaded batch) so
the engine's own fingerprinting/asset-matching/audit logic runs
completely unmodified.

``EvidenceFormat.NMAP_XML`` (Nmap) and ``EvidenceFormat.TEXT`` (CA-04.3 —
Subfinder's newline-separated subdomain list) are the only formats parsed
today, dispatched by ``(evidence_format, provider_id)`` pair, not format
alone — a still-unhandled format/provider combination raises rather than
silently no-oping, since fabricating support for evidence nothing produces
yet would be dishonest. Deliberately produces zero findings from either:
Nmap here is asset/service discovery and Subfinder is passive subdomain
enumeration, neither is a vulnerability scan. Nuclei (CA-04.4) **does** now report
evidence here, and is the only parser that produces findings: it is a
vulnerability scan, and the other two are not. Inventing findings from
Nmap/Subfinder evidence would still not be honest — a port being open is
not a vulnerability.
Subfinder's own host records carry no ``ip`` (it resolves names, not
addresses) and no ``services`` (it never opens a connection to what it
finds) — a real, disclosed narrower shape than Nmap's, not a bug.

Disclosed limitation, not fabricated as newly discovered: a crash between
``normalize_ingestion_batch``'s own internal commit (an existing,
unmodified behavior of that function) and this adapter's own subsequent
``EvidencePackage.normalization_status`` update could leave a package
readable as still needing normalization, risking a duplicate pass on the
next sweep — the same class of gap ``DISC-34`` (``EvidencePackage``
idempotency key) already exists to close; genuinely deferred there, not
solved here.
"""

from __future__ import annotations

import hashlib
import json
from ipaddress import ip_address
from typing import Any

import defusedxml.ElementTree as ET
from defusedxml.common import DefusedXmlException
from sqlalchemy.orm import Session

from src.core.constants.discovery_execution_enums import (
    EVIDENCE_PACKAGE_AUDIT_NORMALIZATION_FAILED,
    EVIDENCE_PACKAGE_AUDIT_NORMALIZED,
    EvidenceFormat,
    EvidenceNormalizationStatus,
)
from src.core.constants.lifecycle_enums import LifecycleFamily, LifecycleTransitionSource
from src.core.model_defs.discovery_execution import EvidencePackage
from src.core.model_defs.discovery_run import DiscoveryRun
from src.core.model_defs.evidence_scanner import ScannerInstance
from src.core.model_defs.evidence_source import EvidenceSource
from src.core.model_defs.risk_intelligence_ingestion import (
    RiskIngestionBatch,
    RiskIngestionBatchStatus,
)
from src.core.models import AuditEvent
from src.core.services.collector_readiness_service import (
    collector_can_see_hardware_addresses_for,
    resolve_collector_readiness,
)
from src.core.services.evidence_source_service import record_collector_evidence
from src.core.services.evidence_package_lifecycle_service import (
    transition_evidence_package_normalization,
)
from src.core.services.evidence_storage_backend import (
    EvidenceStorageError,
    get_evidence_storage_backend,
)
from src.core.services.lifecycle_audit_service import (
    LifecycleAuditDetails,
    with_lifecycle_audit_metadata,
)
from src.core.services.risk_intelligence_normalization_service import (
    NormalizationResult,
    normalize_ingestion_batch,
)


class DiscoveryEvidenceNormalizationError(ValueError):
    """A package whose source_type IS supported still couldn't be
    normalized (evidence retrieval or XML parse failure) — distinct from
    the generic ValueError CollectorOutputAdapter callers raise for an
    unsupported source_type entirely. Already marked
    NORMALIZATION_FAILED and audited before this is raised."""


def _parse_nmap_xml(raw_bytes: bytes) -> list[dict[str, Any]]:
    """Real, minimal Nmap XML parser — extracts each scanned host's
    address/hostname and open TCP/UDP services into the generic
    host-record shape ``risk_intelligence_normalization_service`` already
    knows how to consume (``hostname``/``ip``/``findings`` keys). A host
    with no usable address or hostname is skipped rather than given a
    fabricated identity; an empty/malformed document raises
    ``ET.ParseError``, caught by the caller.

    Uses ``defusedxml`` rather than the stdlib ``xml.etree.ElementTree``
    (A1 security remediation — Semgrep static-analysis finding): this
    parses evidence submitted by scanner instances, which this codebase
    treats as channel-authenticated but not content-trusted (see the
    evidence-signing gap already tracked in the implementation risk
    register). The stdlib parser is vulnerable to entity-expansion and
    external-entity resolution on untrusted XML; defusedxml is a drop-in
    replacement that disables both by default.
    """
    root = ET.fromstring(raw_bytes)
    # #249 slice 2 — read once for the whole document, because it is a property
    # of the scan, not of a host: a scan that ran version detection ran it for
    # every host in the run, including the ones it learned nothing from.
    scan_probed = _version_detection_requested(root)
    host_records: list[dict[str, Any]] = []
    for host_el in root.findall("host"):
        # CA-07.1 — nmap emits one <address> per address *type*: ipv4, and on a
        # local segment with sufficient privilege, mac with a `vendor` OUI
        # string. Taking `find("address")` unconditionally read whichever came
        # first and called it the IP, so a MAC-first host would have been given
        # a MAC address as its `ip`. Selected by addrtype now, and the vendor —
        # the only thing that can name a host with nothing listening — is kept.
        ip_address = _address_of_type(host_el, "ipv4") or _address_of_type(host_el, "ipv6")
        mac_el = _address_element_of_type(host_el, "mac")
        hostname_el = host_el.find("hostnames/hostname")
        hostname = hostname_el.get("name") if hostname_el is not None else None
        if not ip_address and not hostname:
            continue  # no usable identity for this host entry — skip rather than fabricate one

        services: list[dict[str, Any]] = []
        for port_el in host_el.findall("ports/port"):
            state_el = port_el.find("state")
            if state_el is None or state_el.get("state") != "open":
                continue
            service_el = port_el.find("service")
            port_id = port_el.get("portid")
            services.append(
                {
                    "port": int(port_id) if port_id and port_id.isdigit() else None,
                    "protocol": port_el.get("protocol"),
                    "service": service_el.get("name") if service_el is not None else None,
                    "product": service_el.get("product") if service_el is not None else None,
                    "version": service_el.get("version") if service_el is not None else None,
                    # What -sV's own probes concluded the host is running, and
                    # what the scripts read off it. `http-title` is the name a
                    # self-hosted application gives itself; without these the
                    # `service` name above is nmap's port-number table and
                    # nothing more.
                    "extra_info": service_el.get("extrainfo") if service_el is not None else None,
                    # #249 slice 2 — nmap says, per service, how it reached the
                    # name above: `table` is its port-number lookup (port 8080 →
                    # "http-proxy", guessed), `probed` is what -sV actually
                    # elicited. Keeping it is what lets a reader be told which
                    # of the two they are looking at, instead of both arriving
                    # as if they were observations.
                    "method": service_el.get("method") if service_el is not None else None,
                    "scripts": _script_output(port_el),
                }
            )

        host_records.append(
            {
                "hostname": hostname,
                "ip": ip_address,
                "mac": mac_el.get("addr") if mac_el is not None else None,
                "vendor": mac_el.get("vendor") if mac_el is not None else None,
                "services": services,
                # #249 slice 2 — "was this actually probed?", recorded from the
                # scan's own evidence rather than inferred from whether it
                # happened to find anything. A service nmap marks `probed`
                # settles it outright; otherwise the scan's arguments do. Only
                # a document carrying neither leaves this None, and only then
                # does the reader fall back to guessing.
                "fingerprinting_ran": (
                    True
                    if any(service.get("method") == _SERVICE_METHOD_PROBED for service in services)
                    else scan_probed
                ),
                "findings": [],
            }
        )
    return host_records


#: What nmap calls a service name it obtained by probing, as against `table` —
#: its static port-number lookup. Named rather than inlined: two modules now
#: depend on the distinction, and a typo would silently mean "never probed".
_SERVICE_METHOD_PROBED = "probed"

#: Flags that turn a connect sweep into a scan that asks what is listening.
#: `-A` is nmap's aggregate and includes `-sV`.
_VERSION_DETECTION_FLAGS = frozenset({"-sV", "-A"})


def _version_detection_requested(root: Any) -> bool | None:
    """Whether the scan that produced this document ran version detection.

    Read from `<nmaprun args=…>`, which nmap writes as the command line it was
    invoked with. This is the honest answer to a question that was previously
    inferred from whether any identifying evidence turned up — an inference that
    cannot distinguish *"we did not look"* from *"we looked and it would not
    say"*, and so always resolved to the first.

    Returns None when the document carries no arguments to read, rather than
    guessing: an absent record is not evidence of absence, and the caller has a
    documented fallback for exactly that case.
    """
    args = root.get("args")
    if not args:
        return None
    return any(token in _VERSION_DETECTION_FLAGS for token in args.split())


def _address_element_of_type(host_el: Any, addrtype: str) -> Any | None:
    for address_el in host_el.findall("address"):
        if address_el.get("addrtype") == addrtype:
            return address_el
    return None


def _address_of_type(host_el: Any, addrtype: str) -> str | None:
    address_el = _address_element_of_type(host_el, addrtype)
    return address_el.get("addr") if address_el is not None else None


def _script_output(port_el: Any) -> dict[str, str]:
    """NSE script output for one port, keyed by script id.

    Kept as a flat id → output map rather than the raw elements: the two scripts
    this pipeline runs (`http-title`, `ssl-cert`) both answer in their `output`
    attribute, and a structure that mirrored nmap's XML would push nmap's shape
    further into the platform than it needs to go.
    """
    scripts: dict[str, str] = {}
    for script_el in port_el.findall("script"):
        script_id = script_el.get("id")
        output = script_el.get("output")
        if script_id and output:
            scripts[script_id] = output.strip()
    return scripts


def _parse_subfinder_text(raw_bytes: bytes) -> list[dict[str, Any]]:
    """CA-04.3 — real, minimal Subfinder parser: one discovered subdomain
    per non-blank line (the Collector's own ``subfinder_runner.py`` output
    shape — plain text, not Subfinder's optional ``-oJ`` JSON, matching
    this pipeline's existing preference for the simplest format that
    carries what's actually needed). Each line becomes a host record with
    only ``hostname`` set — no ``ip`` (Subfinder resolves names, not
    addresses) and no ``services`` (it never connects to what it finds),
    a real narrower shape than Nmap's, not a gap. A duplicate subdomain
    line is deduplicated rather than double-recorded."""
    seen: set[str] = set()
    host_records: list[dict[str, Any]] = []
    for raw_line in raw_bytes.decode("utf-8").splitlines():
        hostname = raw_line.strip()
        if not hostname or hostname in seen:
            continue
        seen.add(hostname)
        host_records.append({"hostname": hostname, "ip": None, "services": [], "findings": []})
    return host_records


def _with_process_context(metadata: dict, package: EvidencePackage) -> dict:
    """CA-04.8 — extracted from the package's own provenance_metadata
    (set once at package-creation time, CA-04.7), not a fresh query —
    this package is already fully self-describing for exactly this
    reason."""
    return {
        **metadata,
        "businessProcessId": package.provenance_metadata.get("businessProcessId"),
        "businessServiceId": package.provenance_metadata.get("businessServiceId"),
        "slotInstanceId": package.provenance_metadata.get("slotInstanceId"),
    }


def _record_on_evidence_source(
    db: Session,
    package: EvidencePackage,
    *,
    organization_id: int,
    record_count: int,
    succeeded: bool,
) -> None:
    """Tell the scanner's EvidenceSource that a Collector delivered evidence.

    BUG-DISC-13: nothing in the discovery pipeline referenced EvidenceSource, so
    a scanner source stayed ``draft`` forever and onboarding readiness never
    completed after a successful run. Recorded here rather than at storage time
    because "received" in this model has always meant *usable* — the CSV path
    sets it after the batch is processed, not when the file lands.

    Missing links are tolerated silently on purpose: an org-wide run created
    before scanner sources existed still has no source to update, and that must
    not fail a normalisation that otherwise succeeded.
    """
    run = db.query(DiscoveryRun).filter(DiscoveryRun.id == package.discovery_run_id).first()
    if run is None or run.evidence_source_id is None:
        return
    source = (
        db.query(EvidenceSource)
        .filter(EvidenceSource.id == run.evidence_source_id)
        .filter(EvidenceSource.organization_id == organization_id)
        .first()
    )
    if source is None:
        return
    record_collector_evidence(
        db,
        source,
        record_count=record_count,
        succeeded=succeeded,
        validation_summary={"evidencePackageId": package.id, "providerId": package.provider_id},
    )


def _mark_normalization_failed(
    db: Session,
    package: EvidencePackage,
    *,
    organization_id: int,
    actor_user_id: int | None,
    error: str,
) -> None:
    previous_state = package.normalization_status
    transition_evidence_package_normalization(
        package, EvidenceNormalizationStatus.NORMALIZATION_FAILED.value
    )
    db.add(package)
    _record_on_evidence_source(
        db, package, organization_id=organization_id, record_count=0, succeeded=False
    )
    db.add(
        AuditEvent(
            organization_id=organization_id,
            actor_user_id=actor_user_id,
            event_type=EVIDENCE_PACKAGE_AUDIT_NORMALIZATION_FAILED,
            metadata_json=with_lifecycle_audit_metadata(
                _with_process_context({"evidencePackageId": package.id, "error": error}, package),
                LifecycleAuditDetails(
                    object_type="evidence_package",
                    object_id=package.id,
                    family=LifecycleFamily.EVIDENCE,
                    source=LifecycleTransitionSource.SYSTEM_EXECUTED,
                    previous_state=previous_state,
                    current_state=package.normalization_status,
                ),
            ),
        )
    )


def _parse_nuclei_jsonl(raw_bytes: bytes) -> list[dict[str, Any]]:
    """The first parser that produces a **vulnerability**, not an artefact.

    Nuclei emits one JSON object per line (``-jsonl``, see the Collector's
    ``nuclei_runner.py``). Until now nothing read it: the scan genuinely ran
    against the pinned template pack and the Collector's own CLI said so —
    *"no evidence is attached. The job still completes for real."* — so the
    platform held 69 evidence packages and **zero findings**, while CA-09V,
    which is built on vulnerability input, had none.

    Lines are grouped into host records because the pipeline is host-shaped and
    the normalisation service already reads a host record's ``findings`` list
    (``_FINDING_KEYS``). Nothing downstream needed building; only this.

    ⚠️ **Nothing is inferred.** Severity is nuclei's own word — its vocabulary
    (critical/high/medium/low/info) is already the platform's — and a line
    without one is left to the normaliser's default rather than guessed at here.
    A malformed line is skipped, not fatal: one bad line in a long scan must not
    discard every real finding beside it.
    """
    host_records: dict[str, dict[str, Any]] = {}
    seen: set[tuple[str, str, str]] = set()

    for raw_line in raw_bytes.decode("utf-8").splitlines():
        line = raw_line.strip()
        if not line:
            continue
        try:
            entry = json.loads(line)
        except json.JSONDecodeError:
            continue
        if not isinstance(entry, dict):
            continue

        info = entry.get("info") if isinstance(entry.get("info"), dict) else {}
        template_id = entry.get("template-id") or entry.get("templateID") or ""

        # Nuclei reports a *target*, which for an http template is a URL. The
        # scheme and path belong to the finding, not to the host's identity —
        # `https://x/a` and `https://x/b` are one host, and storing the URL as a
        # hostname is how a name that is not a name gets into the inventory.
        raw_host = str(entry.get("host") or entry.get("matched-at") or "").strip()
        host = _host_from_target(raw_host)
        ip = entry.get("ip") if isinstance(entry.get("ip"), str) and entry.get("ip") else None

        # 🐞 An address is not a name, and putting one in the hostname slot is
        # what made every scan create a duplicate artefact.
        #
        # This module already warned about the URL case — "storing the URL as a
        # hostname is how a name that is not a name gets into the inventory" —
        # and then did exactly that with a bare IP. `192.168.50.152` became a
        # *strong* HOSTNAME identifier, which no existing artefact carried, so
        # identity resolution found nothing at step 1 and never reached step 4,
        # the weak address match that would have found `pi-local` immediately.
        # Result: a fresh artefact and a conflict for a person, per host, per
        # scan. Søren resolved six by hand after one scan of one small network.
        if _is_ip_address(host):
            # Unbracketed: `[2001:db8::1]` is how an IPv6 address is written
            # *inside a URL*, and the brackets are that syntax rather than part
            # of the address. Storing them would make the same host fail to
            # match itself when nmap reports it plainly.
            ip = ip or host.strip("[]")
            hostname = None
        else:
            hostname = host or None

        key = host or ip or ""
        if not key:
            continue

        # The same template matching twice at the same place is one finding
        # reported twice; matching at two places is two.
        matched_at = str(entry.get("matched-at") or "")
        identity = (key, str(template_id), matched_at)
        if identity in seen:
            continue
        seen.add(identity)

        record = host_records.setdefault(
            key,
            {
                "hostname": hostname,
                "ip": ip,
                "services": [],
                "findings": [],
                # A vulnerability scan never discovers a host — it is pointed at
                # hosts discovery already found (`targets_discovered_hosts`), and
                # its target list is built from `asset_identifiers`. So this
                # observation cannot establish that something exists; it can only
                # say what is wrong with something already on record.
                #
                # Normalisation reads this and refuses to create an artefact from
                # it. Inventing inventory from a vulnerability match is the same
                # fabrication BUG-DISC-14 removed from two other paths.
                "establishesIdentity": False,
            },
        )
        if record["ip"] is None and ip:
            record["ip"] = ip

        finding: dict[str, Any] = {
            # `id` is read by the normaliser's title fallback, so a template
            # without a human name still says which template fired.
            "id": template_id or None,
            "name": info.get("name") or None,
            "description": info.get("description") or None,
            "matched_at": matched_at or None,
            "template_id": template_id or None,
            "type": entry.get("type") or None,
        }
        severity = info.get("severity")
        if isinstance(severity, str) and severity.strip():
            finding["severity"] = severity.strip().lower()

        classification = info.get("classification")
        if isinstance(classification, dict):
            # Carried through, never combined: CA-09V evaluates findings across
            # separate explainable dimensions and forbids one opaque score, so
            # CVE ids and CVSS stay beside each other as facts the source gave.
            cve_ids = classification.get("cve-id")
            if isinstance(cve_ids, list) and cve_ids:
                finding["cve_ids"] = [str(cve) for cve in cve_ids]
            cvss = classification.get("cvss-score")
            if isinstance(cvss, (int, float)):
                finding["cvss_score"] = float(cvss)

        record["findings"].append({k: v for k, v in finding.items() if v is not None})

    return list(host_records.values())


def _is_ip_address(value: str) -> bool:
    """Whether this is an address rather than a name.

    IPv6 literals arrive from ``_host_from_target`` still bracketed, because that
    is how they appear in a target; the brackets are URL syntax, not part of the
    address, so they come off before parsing.
    """
    if not value:
        return False
    candidate = value[1:-1] if value.startswith("[") and value.endswith("]") else value
    try:
        ip_address(candidate)
    except ValueError:
        return False
    return True


def _host_from_target(target: str) -> str:
    """The host out of a nuclei target, which may be a URL, host:port or a name."""
    if not target:
        return ""
    without_scheme = target.split("://", 1)[-1]
    host = without_scheme.split("/", 1)[0]
    # An IPv6 literal keeps its brackets; a trailing :port is dropped.
    if host.startswith("["):
        return host.split("]", 1)[0] + "]" if "]" in host else host
    return host.rsplit(":", 1)[0] if host.count(":") == 1 else host


# CA-04.3 — dispatched by (evidence_format, provider_id) pair, not format
# alone: a format shared by a future provider (e.g. TEXT) must not silently
# be parsed by the wrong provider's parser.
_PARSERS_BY_FORMAT_AND_PROVIDER = {
    (EvidenceFormat.NMAP_XML.value, "nmap"): _parse_nmap_xml,
    (EvidenceFormat.TEXT.value, "subfinder"): _parse_subfinder_text,
    (EvidenceFormat.JSON.value, "nuclei"): _parse_nuclei_jsonl,
}


# The (format, provider) pairs this adapter can actually parse. Exported so the
# normalisation hand-off selects exactly what is parseable rather than keeping
# its own hardcoded list, which is how a registered Subfinder parser sat unused
# while every Subfinder package stayed pending forever.
SUPPORTED_EVIDENCE_PARSER_KEYS = frozenset(_PARSERS_BY_FORMAT_AND_PROVIDER)


def _hardware_addresses_visible(
    db: Session, package: EvidencePackage, *, organization_id: int
) -> bool | None:
    """Whether the Collector behind this package could see hardware addresses.

    ``None`` when the question cannot be answered — no run, no Collector, or a
    Collector that has never reported. That is a third answer and not a ``False``:
    ``False`` is the Collector positively saying it cannot look, which is worth
    telling a reader about, while ``None`` means nobody has said, and asserting
    "we could not look" on that basis would be the same guess in the other
    direction.

    Reads the Collector's own reported capability rather than checking whether
    any MAC turned up, which is what ``collector_can_see_hardware_addresses``
    exists for — inference from absence can only ever conclude "we did not
    look", and that is exactly the answer that must be earned.
    """
    if not package.discovery_run_id:
        return None
    run = (
        db.query(DiscoveryRun)
        .filter(
            DiscoveryRun.id == package.discovery_run_id,
            DiscoveryRun.organization_id == organization_id,
        )
        .first()
    )
    if run is None or not run.scanner_instance_id:
        return None
    instance = (
        db.query(ScannerInstance)
        .filter(
            ScannerInstance.id == run.scanner_instance_id,
            ScannerInstance.organization_id == organization_id,
        )
        .first()
    )
    if instance is None:
        return None

    # #320 — asked per *target*, not once for the Collector. The privilege is
    # granted by Docker's defaults and so is nearly always true; what varies is
    # whether the Collector is standing on the network it scanned. A run whose
    # targets it could not reach must not report that it looked.
    readiness = resolve_collector_readiness(db, instance)
    targets = _run_targets(run)
    if not targets:
        return None
    return all(
        collector_can_see_hardware_addresses_for(
            readiness, network_segments=instance.network_segments, target=target
        )
        for target in targets
    )


def _run_targets(run: DiscoveryRun) -> list[str]:
    """The addresses or ranges this run was approved to scan.

    Read from the run's own snapshot rather than from live targets: the question
    is whether the Collector could see *what this evidence came from*, and the
    approved scope may have changed since.
    """
    snapshot = run.target_snapshot if isinstance(run.target_snapshot, list) else []
    targets: list[str] = []
    for entry in snapshot:
        if not isinstance(entry, dict):
            continue
        value = entry.get("approvedValue") or entry.get("value")
        if isinstance(value, str) and value.strip():
            targets.append(value.strip())
    return targets


class DiscoveryExecutionEvidenceAdapter:
    source_type = "discovery_execution"

    def supports(self, source_type: str) -> bool:
        return source_type == self.source_type

    def normalize(
        self,
        db: Session,
        *,
        organization_id: int,
        actor_user_id: int | None,
        execution_id: int | str,
    ) -> NormalizationResult:
        package = (
            db.query(EvidencePackage)
            .filter(
                EvidencePackage.id == execution_id,
                EvidencePackage.organization_id == organization_id,
            )
            .first()
        )
        if package is None:
            raise ValueError(
                f"No EvidencePackage found for organization_id={organization_id!r}, id={execution_id!r}"
            )
        parser = _PARSERS_BY_FORMAT_AND_PROVIDER.get((package.evidence_format, package.provider_id))
        if parser is None:
            raise ValueError(
                f"DiscoveryExecutionEvidenceAdapter does not support evidence_format={package.evidence_format!r} "
                f"from provider_id={package.provider_id!r} yet"
            )

        try:
            backend = get_evidence_storage_backend()
            raw_bytes = backend.retrieve(reference=package.raw_evidence_reference)
        except EvidenceStorageError as exc:
            _mark_normalization_failed(
                db,
                package,
                organization_id=organization_id,
                actor_user_id=actor_user_id,
                error=str(exc),
            )
            raise DiscoveryEvidenceNormalizationError(str(exc)) from exc

        try:
            host_records = parser(raw_bytes)
        except (ET.ParseError, DefusedXmlException, UnicodeDecodeError) as exc:
            # DefusedXmlException (DTDForbidden/EntitiesForbidden/
            # ExternalReferenceForbidden) is a ValueError subclass, not a
            # ParseError — without naming it, a hostile evidence package would
            # be blocked by defusedxml but crash normalisation instead of being
            # recorded as failed, leaving the package in a non-terminal state.
            _mark_normalization_failed(
                db,
                package,
                organization_id=organization_id,
                actor_user_id=actor_user_id,
                error=str(exc),
            )
            raise DiscoveryEvidenceNormalizationError(str(exc)) from exc

        # CA-09A.2 — stamped here rather than in the parser, because it is a
        # property of the *Collector*, not of the document it produced: one
        # answer for the whole package, exactly as `fingerprinting_ran` is read
        # once per scan. The parser stays a pure function of its bytes.
        hardware_visible = _hardware_addresses_visible(db, package, organization_id=organization_id)
        if hardware_visible is not None:
            for host_record in host_records:
                host_record["hardware_addresses_visible"] = hardware_visible

        # BUG-DISC-14: this used to synthesise a host record named
        # f"{provider_id}-scan-{package.id[:8]}" so a scan that found nothing
        # still produced a signal. It also produced an *asset* — an inventory
        # entry for something that does not exist, named after an internal
        # evidence-package id, on a screen where an executive approves what
        # their organisation owns. "We scanned and found nothing" is a real and
        # valid outcome; it is just not an asset. The EvidencePackage and its
        # audit event already record that the scan ran, and the run summary
        # reports the empty result (see discovery_results_service).

        batch = RiskIngestionBatch(
            organization_id=organization_id,
            source_name=f"discovery_execution:{package.provider_id}",
            collector_profile="discovery_execution_pipeline",
            content_type="application/xml",
            payload_checksum=package.integrity_hash or hashlib.sha256(raw_bytes).hexdigest(),
            raw_payload={"hosts": host_records},
            raw_payload_size_bytes=len(raw_bytes),
            status=RiskIngestionBatchStatus.RECEIVED,
            # CA-06.2 — carry the package through, so every signal normalization
            # writes can point back at the evidence, the job and the Collector
            # that produced it. Previously the only trace was a batch id inside
            # a JSON blob, which meant an inventory claim could not be traced to
            # its evidence without re-parsing a raw payload.
            evidence_package_id=package.id,
        )
        db.add(batch)
        db.flush()  # populate batch.id before normalize_ingestion_batch looks it up

        result = normalize_ingestion_batch(
            db, organization_id=organization_id, actor_user_id=actor_user_id, batch_id=batch.id
        )

        previous_state = package.normalization_status
        transition_evidence_package_normalization(
            package, EvidenceNormalizationStatus.NORMALIZED.value
        )
        db.add(package)
        _record_on_evidence_source(
            db,
            package,
            organization_id=organization_id,
            record_count=len(host_records),
            succeeded=True,
        )
        db.add(
            AuditEvent(
                organization_id=organization_id,
                actor_user_id=actor_user_id,
                event_type=EVIDENCE_PACKAGE_AUDIT_NORMALIZED,
                metadata_json=with_lifecycle_audit_metadata(
                    _with_process_context(
                        {
                            "evidencePackageId": package.id,
                            "ingestionBatchId": batch.id,
                            "matchedAssetIds": result.matched_asset_ids,
                            "createdAssetIds": result.created_asset_ids,
                        },
                        package,
                    ),
                    LifecycleAuditDetails(
                        object_type="evidence_package",
                        object_id=package.id,
                        family=LifecycleFamily.EVIDENCE,
                        source=LifecycleTransitionSource.SYSTEM_EXECUTED,
                        previous_state=previous_state,
                        current_state=package.normalization_status,
                    ),
                ),
            )
        )
        return result


__all__ = ["DiscoveryExecutionEvidenceAdapter", "DiscoveryEvidenceNormalizationError"]

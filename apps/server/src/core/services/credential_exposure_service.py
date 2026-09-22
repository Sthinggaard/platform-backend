"""#296 — a credential in a customer's configuration, recorded as a finding.

Søren, 2026-08-24, while deciding that ``read_service_config`` stays in CA-08's
scope: *if this exposes a credential in a `.env` or a config file, that is also a
vulnerability we expose to the client, and it should appear as something which
needs to be fixed.*

He is right, and the half that is easy to miss is why it is not enough to redact
it. Redaction protects **us** — it keeps the platform inside CA-07.2's rule that
it cannot receive secret material. It does nothing for the customer, whose
credential is still sitting in a readable file on a host. Redacting silently
would mean the platform knew about a real exposure and said nothing about it.

**The value never reaches this module.** Redaction happens on the Collector
(``scanner_agent/config_redaction.py``), so what arrives here is already only a
shape: which service's configuration, which setting, and which rule matched.
That is deliberate rather than incidental — reporting the finding is proof we
read the thing we promised never to hold, so the report has to be able to stand
without it.

**How precisely a finding may point.** It names the service and the setting —
"the nginx configuration stores a value under `password`" — and never the file
path. A report naming exact paths across an estate is a map for anyone who later
gets into Risklence, and the path adds nothing a person needs in order to act:
whoever owns nginx knows where its config lives.
"""

from __future__ import annotations

from sqlalchemy.orm import Session

from src.core.model_defs.assets_runtime import (
    AssetFinding,
    AssetFindingStatus,
    SeverityLevel,
)

#: Findings are grouped by domain elsewhere in the product; this is the one they
#: belong to. A credential in deployed configuration is a resilience problem
#: before it is a compliance one — if that host is compromised the credential
#: grants whatever it opens, which is the business consequence.
CREDENTIAL_EXPOSURE_DOMAIN = "credential_exposure"

#: Frameworks that have something to say about stored credentials. Named so the
#: finding can carry them into the intervention flow, which already speaks this
#: language, rather than being re-derived at the surface.
CREDENTIAL_EXPOSURE_FRAMEWORKS = ("DORA", "PCI-DSS", "NIS2")

_TITLE = "Stored credential in {service} configuration"

_DESCRIPTION = (
    "This artefact's {service} configuration holds a value under '{setting}' that is stored "
    "in plain text. Anyone who can read that file — or who reaches this host — has whatever "
    "it opens, without needing to break anything.\n\n"
    "Risklence did not store this value and does not hold a copy: it was redacted where it "
    "was read and never left the machine. This records that it is there, so it can be moved "
    "into a secret store and rotated."
)


def record_credential_exposure(
    db: Session,
    *,
    organization_id: int,
    asset_id: int,
    findings: list[dict],
) -> list[AssetFinding]:
    """Record what verification found sitting in the open, without recording it.

    Idempotent per (artefact, service, setting): re-reading the same file must
    not produce a second finding, or a weekly schedule would turn one real
    problem into a growing pile. ``last_seen_at`` advancing is what says it is
    still there.
    """
    recorded: list[AssetFinding] = []

    for finding in findings:
        service = str(finding.get("target") or "this service")
        setting = str(finding.get("setting") or "a credential")
        title = _TITLE.format(service=service)

        existing = (
            db.query(AssetFinding)
            .filter(
                AssetFinding.organization_id == organization_id,
                AssetFinding.asset_id == asset_id,
                AssetFinding.domain == CREDENTIAL_EXPOSURE_DOMAIN,
                AssetFinding.title == title,
            )
            .first()
        )

        if existing is not None:
            # Seen again. Touched rather than duplicated, and deliberately not
            # reopened: if somebody resolved it, saying so again is their
            # business to reconsider, not ours to overrule.
            existing.description = _DESCRIPTION.format(service=service, setting=setting)
            db.add(existing)
            recorded.append(existing)
            continue

        row = AssetFinding(
            organization_id=organization_id,
            asset_id=asset_id,
            domain=CREDENTIAL_EXPOSURE_DOMAIN,
            # High, not critical. It is a real weakness that needs fixing, and
            # it is not an active incident — reserving critical for things that
            # are burning is what keeps critical meaningful.
            severity=SeverityLevel.HIGH,
            title=title,
            description=_DESCRIPTION.format(service=service, setting=setting),
            # The shape, never the value. `kind` says which rule matched, so the
            # finding can explain why it believes this.
            evidence_refs=[
                {
                    "service": service,
                    "setting": setting,
                    "kind": finding.get("kind"),
                    "frameworks": list(CREDENTIAL_EXPOSURE_FRAMEWORKS),
                }
            ],
            status=AssetFindingStatus.OPEN,
        )
        db.add(row)
        recorded.append(row)

    return recorded

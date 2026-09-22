"""CA-08.4 (#292) — writing down what verification established, and what it did not.

Separate from ``verification_identity_service``, which reads a name out of
command output and touches no database. This one decides whether that name may
be carried at all, records it against the artefact with provenance, and makes
sure "we looked inside and it still would not say" is written down as a finding
rather than left as an absence.

**The output allow-list is the load-bearing part.** Redaction does not exist yet
(#296), so output is only accepted from capabilities that cannot return a
credential — ``OUTPUT_SAFE_BEFORE_REDACTION``. ``read_service_config`` is
excluded, which means its output stays on the Collector where it was read. An
allow-list rather than a deny-list: a capability added later carries nothing
until somebody looks at what it returns and adds it on purpose.

**The artefact's own name is only ever improved, never downgraded.**
``IDENTITY_BASIS_PRECEDENCE`` decides, and verification-derived evidence sits
above everything read from the network — so a run that cost a person a decision
visibly changes what they see, and a later weaker observation cannot quietly
undo it.
"""

from __future__ import annotations

from src.core.constants.artefact_identity_evidence_enums import IDENTITY_BASIS_PRECEDENCE
from src.core.constants.verification_command_templates import OUTPUT_SAFE_BEFORE_REDACTION
from src.core.constants.verification_inspection_enums import (
    VERIFICATION_IDENTITY_AUDIT_DETERMINED,
    VERIFICATION_IDENTITY_AUDIT_UNDETERMINED,
    VERIFICATION_IDENTITY_AUDIT_OUTPUT_WITHHELD,
)
from src.core.model_defs.assets_runtime import Asset
from src.core.model_defs.verification_inspection_command import VerificationInspectionCommand
from src.core.services.artefact_identity_evidence_service import DeterminedIdentity
from src.core.services.audit_service import append_audit_event
from src.core.services.verification_identity_service import identity_from_inspection
from sqlalchemy.orm import Session


def record_identity_from_inspection(
    db: Session, *, command: VerificationInspectionCommand, stdout: str
) -> DeterminedIdentity | None:
    """Turn one inspection's output into what the organisation now knows.

    Returns ``None`` only when the output was refused outright — the one case
    where nothing was learned because nothing was allowed to be read here.
    """
    if command.capability not in OUTPUT_SAFE_BEFORE_REDACTION:
        # Refused, and said so. Silently dropping it would leave a person
        # looking at a successful run that established nothing, with no way to
        # tell that the platform chose not to look.
        append_audit_event(
            db,
            command.organization_id,
            VERIFICATION_IDENTITY_AUDIT_OUTPUT_WITHHELD,
            metadata={
                "command_id": command.id,
                "run_id": command.verification_run_id,
                "capability": command.capability,
                "reason": (
                    "This capability's output can contain a credential, and redaction "
                    "is not built yet, so it was not carried off the Collector."
                ),
            },
        )
        return None

    identity = identity_from_inspection(capability=command.capability, stdout=stdout)

    if not identity.determined:
        append_audit_event(
            db,
            command.organization_id,
            VERIFICATION_IDENTITY_AUDIT_UNDETERMINED,
            metadata={
                "command_id": command.id,
                "run_id": command.verification_run_id,
                "capability": command.capability,
                # An empty result is a finding, not a gap — CA-08.4's own words.
                "reason": identity.undetermined_reason,
                "explanation": identity.explanation,
            },
        )
        return identity

    command.identity_name = identity.name
    command.identity_basis = identity.basis
    command.identity_evidence = identity.evidence
    db.add(command)

    # What the artefact is *called* changes only when this evidence beats the
    # best any previous verification produced for it. Compared against prior
    # verifications rather than a column on the asset: nothing on `assets`
    # records where its name came from, and inventing one to hold that would be
    # a schema change to the busiest table in the product for a question only
    # this epic asks.
    if _outranks(identity.basis, _best_prior_basis(db, command)):
        asset = (
            db.query(Asset)
            .filter(
                Asset.id == command.asset_id,
                Asset.organization_id == command.organization_id,
            )
            .first()
        )
        if asset is not None:
            asset.display_name = identity.name
            db.add(asset)

    append_audit_event(
        db,
        command.organization_id,
        VERIFICATION_IDENTITY_AUDIT_DETERMINED,
        metadata={
            "command_id": command.id,
            "run_id": command.verification_run_id,
            "capability": command.capability,
            "name": identity.name,
            "basis": identity.basis,
        },
    )
    return identity


def _best_prior_basis(
    db: Session, command: VerificationInspectionCommand
) -> str | None:
    """The strongest basis any earlier verification established for this artefact."""
    order = [basis.value for basis in IDENTITY_BASIS_PRECEDENCE]
    rows = (
        db.query(VerificationInspectionCommand.identity_basis)
        .filter(
            VerificationInspectionCommand.organization_id == command.organization_id,
            VerificationInspectionCommand.asset_id == command.asset_id,
            VerificationInspectionCommand.id != command.id,
            VerificationInspectionCommand.identity_basis.is_not(None),
        )
        .all()
    )
    ranked = [row[0] for row in rows if row[0] in order]
    if not ranked:
        return None
    return min(ranked, key=order.index)


def _outranks(new_basis: str | None, current_basis: str | None) -> bool:
    """Whether this evidence should replace what the artefact is called now.

    Unknown or absent current basis loses to anything. A basis not in the
    precedence tuple at all also loses — a name whose provenance the platform
    cannot rank is not something to overwrite a ranked one with.
    """
    if new_basis is None:
        return False
    order = [basis.value for basis in IDENTITY_BASIS_PRECEDENCE]
    if new_basis not in order:
        return False
    if current_basis is None or current_basis not in order:
        return True
    return order.index(new_basis) < order.index(current_basis)

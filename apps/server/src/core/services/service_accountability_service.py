"""Who is accountable for a Business Service, and for the dependencies under it.

Søren's ruling, refined three times and settled 2026-08-31, restated 2026-09-04:

    "The service is owned by the process unless the service has been given an
    owner. [Where] the same service is used in multiple processes — who owns
    it? It is owned by the team who maintains it. In this case the assigned
    owner owns it."

So accountability is **stated only where the chain cannot answer**:

===========================  ==================================================
Service in one process       Resolves through the chain. The process owner is
                             accountable; nothing is stated separately.
Service in several           The chain is ambiguous, so a holder is stated.
Service in no process        Not a valid resting state (#378, DATA-01).
Dependencies                 Inherit through their service. There is no
                             person-level dependency owner — that framing was
                             considered and dropped.
===========================  ==================================================

⚠️ **Stated accountability is a scoped mandate, not ``owner_user_id``.** The
storage already exists: a ``BUSINESS_SERVICE_OWNER`` role assignment bound to a
``business_service`` scope. ``BusinessService.owner_user_id`` is the documented
legacy compatibility fallback (see ``process_access_resolution_service``) and is
deliberately not read here — building on it would extend the field the codebase
is already retiring.

This module answers **who**. It never decides *whether* someone may act — that
is the mandate model's job — and it never writes.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum

from sqlalchemy.orm import Session

from src.core.constants.org_access_enums import (
    CanonicalMandateRole,
    MandateAssignmentSubjectType,
)
from src.core.model_defs.org_access import OrgMandateRoleAssignment, OrgMandateScopeBinding


class ServiceAccountabilitySource(StrEnum):
    """How the answer was reached — never inferred by the caller."""

    #: A person is named on the service itself, via a scoped mandate.
    STATED = "stated"
    #: Resolved through the service's single process. Settled: there is no other
    #: process it could belong to.
    PROCESS_CHAIN = "process_chain"

    #: Resolved through the process being *viewed*, for a service that several
    #: processes carry. **A proposal, not a verdict.**
    #:
    #: Søren, 2026-09-04: *"If the service is in other processes the question
    #: should be: is this service maintained in this process, or by this process
    #: owner?"* So the reader is shown a sensible default and asked — three
    #: processes each showing their own owner as settled fact would be three
    #: answers for one service, and the system deciding something nobody did.
    #:
    #: Answering pins it as {@link STATED}, which then holds everywhere.
    PROCESS_CHAIN_ASSUMED = "process_chain_assumed"
    #: Nobody is accountable yet. Always paired with a gap.
    UNRESOLVED = "unresolved"


class ServiceAccountabilityGap(StrEnum):
    """Why the chain could not answer. Each one needs a different repair."""

    #: Used by several processes, so "the process owner" names more than one.
    SEVERAL_PROCESSES = "several_processes"
    #: Attached to no process — the chain terminates at nobody (#378).
    NO_PROCESS = "no_process"
    #: One process, and nobody holds its owner mandate.
    PROCESS_HAS_NO_OWNER = "process_has_no_owner"
    #: One process with more than one owner bound.
    #:
    #: ⚠️ Unreachable through the schema: a unique index covers
    #: (organisation, process, canonical_role), so the table cannot hold two.
    #: Kept as defence against rows that arrived around that constraint — the
    #: alternative is choosing an accountable person arbitrarily, which is the
    #: one thing this module must never do.
    PROCESS_HAS_SEVERAL_OWNERS = "process_has_several_owners"

    #: More than one holder stated on the service itself.
    #:
    #: ⚠️ Unreachable for the same reason and by the matching index —
    #: (organisation, business_service, canonical_role). Søren, 2026-09-04, on
    #: whether one-owner-per-process cascades to services: it does, and the
    #: database already says so. Treated exactly like its process twin so that
    #: "one holder" is refused in the same way at both levels.
    STATED_SEVERAL_HOLDERS = "stated_several_holders"


@dataclass(frozen=True)
class ServiceAccountability:
    service_id: str
    #: ``None`` exactly when ``source`` is UNRESOLVED.
    holder_user_id: int | None
    source: ServiceAccountabilitySource
    #: Set exactly when ``source`` is UNRESOLVED.
    gap: ServiceAccountabilityGap | None
    process_ids: tuple[str, ...]

    #: The owners of the processes this service sits in, always.
    #:
    #: ⚠️ **A stated holder does not replace them.** Søren, 2026-09-04: *"The
    #: team is always the process owner... The process owner can decide to
    #: delegate partial ownership to the services such that the accountability
    #: of the service not working is pinned to one in the team."* Delegation is
    #: partial: the delegate answers for this service, the process owner remains
    #: the authority who delegated — and is who #375 must inform when the
    #: delegate decides. Returning only one of the two would make "who acts" and
    #: "who is told" the same question, which is the defect that ruling avoids.
    process_owner_user_ids: tuple[int, ...]

    @property
    def needs_confirmation(self) -> bool:
        """Whether the reader should be asked to confirm this answer.

        True only for a service several processes carry, where the holder is the
        owner of the process being viewed. The question is Søren's: *"is this
        service maintained in this process, or by this process owner?"*
        """
        return self.source is ServiceAccountabilitySource.PROCESS_CHAIN_ASSUMED

    @property
    def is_delegated(self) -> bool:
        """A person answers for this service other than through the chain."""
        return self.source is ServiceAccountabilitySource.STATED

    @property
    def must_be_stated(self) -> bool:
        """Whether a person has to be named before this service can be acted on.

        A gap is a state to surface, never a silent default — the fallback to
        nobody is what this whole ruling exists to prevent.
        """
        return self.source is ServiceAccountabilitySource.UNRESOLVED


@dataclass(frozen=True)
class ScopedMandateHolders:
    """Who holds which scoped mandate, for one organisation."""

    #: process id -> user ids holding BUSINESS_PROCESS_OWNER for it.
    process_owners: dict[str, set[int]]
    #: service id -> user ids holding BUSINESS_SERVICE_OWNER for it.
    #:
    #: A set, not one id, for the same reason ``process_owners`` is one: a
    #: mapping that keeps whichever row was read last would name an accountable
    #: person by accident. The schema allows only one; this refuses to guess if
    #: it ever holds two.
    service_owners: dict[str, set[int]]


def resolve_scoped_mandate_holders(
    db: Session, *, organization_id: int
) -> ScopedMandateHolders:
    """Read the scoped mandate bindings that name an accountable person.

    A binding only counts when its role assignment agrees with it: the same
    canonical role, a user subject, and a user actually set. The role assignment
    owns eligibility; the binding owns the scope. Neither alone is a mandate.

    Shared with ``process_access_resolution_service`` rather than repeated —
    "who holds this mandate" is one piece of knowledge (AGENTS.md, DRY).
    """
    assignments_by_id = {
        assignment.id: assignment
        for assignment in db.query(OrgMandateRoleAssignment)
        .filter(OrgMandateRoleAssignment.organization_id == organization_id)
        .all()
    }
    bindings = (
        db.query(OrgMandateScopeBinding)
        .filter(OrgMandateScopeBinding.organization_id == organization_id)
        .all()
    )

    process_owners: dict[str, set[int]] = {}
    service_owners: dict[str, set[int]] = {}
    for binding in bindings:
        assignment = assignments_by_id.get(binding.role_assignment_id)
        if (
            assignment is None
            or assignment.subject_type != MandateAssignmentSubjectType.USER.value
            or assignment.user_id is None
            or assignment.canonical_role != binding.canonical_role
        ):
            continue
        if (
            binding.canonical_role == CanonicalMandateRole.BUSINESS_PROCESS_OWNER.value
            and binding.value_stream_id
        ):
            process_owners.setdefault(binding.value_stream_id, set()).add(assignment.user_id)
        elif (
            binding.canonical_role == CanonicalMandateRole.BUSINESS_SERVICE_OWNER.value
            and binding.business_service_id
        ):
            service_owners.setdefault(binding.business_service_id, set()).add(assignment.user_id)

    return ScopedMandateHolders(process_owners=process_owners, service_owners=service_owners)


def _accountability_for(
    service: object,
    holders: ScopedMandateHolders,
    as_seen_from_process_id: str | None = None,
) -> ServiceAccountability:
    service_id = service.id
    process_ids = tuple(getattr(service, "value_stream_ids", None) or ())
    process_owner_user_ids = tuple(
        sorted({
            owner_id
            for process_id in process_ids
            for owner_id in holders.process_owners.get(process_id, set())
        })
    )

    def unresolved(gap: ServiceAccountabilityGap) -> ServiceAccountability:
        return ServiceAccountability(
            service_id=service_id,
            holder_user_id=None,
            source=ServiceAccountabilitySource.UNRESOLVED,
            gap=gap,
            process_ids=process_ids,
            process_owner_user_ids=process_owner_user_ids,
        )

    stated = holders.service_owners.get(service_id, set())
    if len(stated) > 1:
        return unresolved(ServiceAccountabilityGap.STATED_SEVERAL_HOLDERS)
    if len(stated) == 1:
        # A stated holder answers regardless of how many processes depend on the
        # service — that is the whole point of stating one.
        return ServiceAccountability(
            service_id=service_id,
            holder_user_id=next(iter(stated)),
            source=ServiceAccountabilitySource.STATED,
            gap=None,
            process_ids=process_ids,
            process_owner_user_ids=process_owner_user_ids,
        )

    if len(process_ids) == 0:
        return unresolved(ServiceAccountabilityGap.NO_PROCESS)

    # ⚠️ **Read through a process, "several processes" is not ambiguous.**
    #
    # Søren, 2026-09-04, on a process map showing "No owner" for the two
    # services that several processes carry: *"If no owner has been assigned a
    # service the process owner is the owner... it should just be the process
    # owner who it defaults to."*
    #
    # #376 called this case ambiguous because it asked the question globally —
    # "the process owner" names three people for Data Platform. Asked from
    # inside one process it names exactly one, and that is how every screen
    # except the standalone service list asks it.
    #
    # Without a process the question stays global, and stays unresolved: a
    # caller with no context must not be handed one of three owners at random.
    resolving_process_id = (
        as_seen_from_process_id
        if as_seen_from_process_id in process_ids
        else process_ids[0] if len(process_ids) == 1 else None
    )
    if resolving_process_id is None:
        return unresolved(ServiceAccountabilityGap.SEVERAL_PROCESSES)

    owners = holders.process_owners.get(resolving_process_id, set())
    if len(owners) == 0:
        return unresolved(ServiceAccountabilityGap.PROCESS_HAS_NO_OWNER)
    if len(owners) > 1:
        # Narrowing to one would be this module choosing an accountable person.
        return unresolved(ServiceAccountabilityGap.PROCESS_HAS_SEVERAL_OWNERS)

    return ServiceAccountability(
        service_id=service_id,
        holder_user_id=next(iter(owners)),
        # Settled only where there is one process it could be. Where several
        # carry it, this is the proposal the reader is asked to confirm.
        source=(
            ServiceAccountabilitySource.PROCESS_CHAIN
            if len(process_ids) == 1
            else ServiceAccountabilitySource.PROCESS_CHAIN_ASSUMED
        ),
        gap=None,
        process_ids=process_ids,
        process_owner_user_ids=process_owner_user_ids,
    )


def resolve_service_accountability(
    db: Session,
    *,
    organization_id: int,
    services: list[object],
    as_seen_from_process_id: str | None = None,
) -> dict[str, ServiceAccountability]:
    """Accountability for each service, keyed by service id.

    One function every caller uses, so "who is accountable" and "who must be
    informed" cannot disagree — which is the acceptance criterion that made this
    a service rather than a query inside a route.

    Archived services are skipped: they are not a resting place for a decision.

    ``as_seen_from_process_id`` answers the question **from inside one process**,
    which is how every process-scoped screen asks it. A service several
    processes carry then resolves to *that* process's owner rather than being
    reported ambiguous.
    """
    holders = resolve_scoped_mandate_holders(db, organization_id=organization_id)
    return {
        service.id: _accountability_for(service, holders, as_seen_from_process_id)
        for service in services
        if getattr(service, "archived_at", None) is None
    }

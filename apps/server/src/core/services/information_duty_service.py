"""Who must be told when someone decides about a Business Service.

Søren's ruling, 2026-09-04, on who is affected:

    "Anyone who owns a process where there is a service which the process does
    not own and will be affected by it."

and, 2026-08-31, on why it matters:

    "There are cases where one of the services which the service is dependent on
    is owned by another person... In this case the owner of this service makes
    the decisions and the ones affected by this decision is informed."

Authority follows ownership of the thing decided. Everyone else who carries a
process that leans on it is **informed** — never asked, never made to approve.

⚠️ **Being informed is not agreeing.** This module names people; it does not
grant them a veto, and nothing downstream may read its output as an approval
step. A record that someone was told is exactly that (#375).

⚠️ **Grain: this answers for a decision about a SERVICE.** A decision about one
*dependency* reaches further — other processes whose services lean on the same
asset — and that set is already computed as ``shared_with_process_ids`` on the
workspace projection. The two are different questions and the second is not
folded in here; see the note in ``resolve_information_duty``.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum

from sqlalchemy.orm import Session

from src.core.services.service_accountability_service import (
    ServiceAccountability,
    ServiceAccountabilitySource,
    resolve_scoped_mandate_holders,
)


class InformationBasis(StrEnum):
    """Why this person has to be told. The message differs for each."""

    #: They own a process that carries this service, and someone else decided.
    CARRIES_THE_SERVICE = "carries_the_service"
    #: They own the process, and the service was delegated to someone in it who
    #: then decided. Partial delegation — the owner keeps the authority.
    DELEGATED_AWAY = "delegated_away"


@dataclass(frozen=True)
class PersonToInform:
    user_id: int
    #: The process of theirs that is affected — what the message names.
    process_id: str
    basis: InformationBasis


@dataclass(frozen=True)
class InformationDuty:
    service_id: str
    decided_by_user_id: int
    people: tuple[PersonToInform, ...]

    @property
    def is_owed(self) -> bool:
        return bool(self.people)


def resolve_information_duty(
    db: Session,
    *,
    organization_id: int,
    service: object,
    accountability: ServiceAccountability,
    decided_by_user_id: int,
) -> InformationDuty:
    """Everyone owed a message about a decision on ``service``.

    The owners of every process carrying the service, minus whoever decided —
    nobody is informed of their own decision.

    ⚠️ Takes the accountability rather than re-deriving it, so "who may act" and
    "who is told" cannot disagree. That was #376's acceptance criterion and it
    only holds while both come from the one resolver.

    ⚠️ Scope: a decision about a service. A decision about a single dependency
    also reaches processes that merely share the *asset* — that set is
    ``shared_with_process_ids`` on the workspace projection, at a different
    grain, and deliberately not merged in. Søren's ruling names a service; which
    grain applies to a dependency-level decision is an open question, and
    guessing it would quietly widen who gets messaged.
    """
    holders = resolve_scoped_mandate_holders(db, organization_id=organization_id)
    delegated = accountability.source is ServiceAccountabilitySource.STATED

    people: list[PersonToInform] = []
    seen: set[tuple[int, str]] = set()
    for process_id in getattr(service, "value_stream_ids", None) or ():
        for owner_id in sorted(holders.process_owners.get(process_id, set())):
            if owner_id == decided_by_user_id:
                # You are not informed of your own decision.
                continue
            if (owner_id, process_id) in seen:
                continue
            seen.add((owner_id, process_id))
            people.append(
                PersonToInform(
                    user_id=owner_id,
                    process_id=process_id,
                    basis=(
                        InformationBasis.DELEGATED_AWAY
                        if delegated
                        else InformationBasis.CARRIES_THE_SERVICE
                    ),
                )
            )

    return InformationDuty(
        service_id=accountability.service_id,
        decided_by_user_id=decided_by_user_id,
        people=tuple(people),
    )

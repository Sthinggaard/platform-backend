"""Find Business Services that belong to no process, and report them (#378).

Søren, 2026-08-31: *"A service in no process should not exist."*

Under the accountability model settled in #376, accountability resolves
dependency → service → process → owner. A service in no process terminates that
chain at **nobody**: there is no process owner to fall back to, so every
dependency beneath it is unowned and undecidable.

⚠️ **This script changes nothing, by design.** The ticket is explicit: *"56
orphans is most of organisation 4. Treat it as data to be reviewed with a
person, not swept up by a script."* Attaching a service to a process is a claim
about how the business runs, and a script guessing it would manufacture exactly
the kind of unfounded assertion this platform exists to remove. It prints what
is there, with enough context for a human to decide.

Read-only, idempotent, and safe to run against production.

Usage:
    poetry run python scripts/report_orphaned_services.py
    poetry run python scripts/report_orphaned_services.py --org-id 4
"""

from __future__ import annotations

import argparse
from collections import defaultdict

from sqlalchemy import func, or_

from src.core.database import get_db_context
from src.core.models import BusinessService, DependencyBundle, ValueStream


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--org-id", type=int, default=None, help="limit to one organisation")
    args = parser.parse_args()

    with get_db_context() as db:
        query = db.query(BusinessService).filter(
            or_(
                BusinessService.value_stream_ids.is_(None),
                func.cardinality(BusinessService.value_stream_ids) == 0,
            )
        )
        if args.org_id is not None:
            query = query.filter(BusinessService.organization_id == args.org_id)
        orphans = query.order_by(
            BusinessService.organization_id, BusinessService.name
        ).all()

        if not orphans:
            print("No orphaned services. Every Business Service belongs to at least one process.")
            return

        by_org: dict[int, list[BusinessService]] = defaultdict(list)
        for service in orphans:
            by_org[service.organization_id].append(service)

        placed_names = {
            (row.organization_id, row.name)
            for row in db.query(BusinessService.organization_id, BusinessService.name)
            .filter(func.cardinality(BusinessService.value_stream_ids) > 0)
            .distinct()
        }
        with_twin = sum(1 for s in orphans if (s.organization_id, s.name) in placed_names)

        print(f"{len(orphans)} Business Service(s) belong to no process.\n")
        print(f"  {with_twin} of them share a name with a service that IS placed — those are")
        print("  most likely duplicate rows, not services awaiting a home.\n")
        print("  Nothing has been changed. Each needs a human decision: attach it to the")
        print("  process it serves, or remove it. Neither can be guessed from the data.\n")

        for org_id, services in sorted(by_org.items()):
            total = (
                db.query(func.count(BusinessService.id))
                .filter(BusinessService.organization_id == org_id)
                .scalar()
            )
            processes = (
                db.query(func.count(ValueStream.id))
                .filter(ValueStream.organization_id == org_id)
                .scalar()
            )
            print(f"─ Organisation {org_id} — {len(services)} of {total} services, {processes} process(es) exist")

            for service in services:
                # What would be lost, and what a reviewer needs in order to place it.
                bundles = (
                    db.query(func.count(DependencyBundle.id))
                    .filter(
                        DependencyBundle.organization_id == org_id,
                        DependencyBundle.service_id == service.id,
                    )
                    .scalar()
                )
                # ⚠️ The single most useful fact for a reviewer, found 2026-09-06:
                # most orphans are not services somebody forgot to place. They
                # are duplicate rows — org 4 holds **25** services named
                # "Payment Processing", 24 of them orphaned, created across
                # seven days in April. 37 of the 57 orphans are surplus copies.
                #
                # A twin that *is* placed changes the question entirely: not
                # "which process does this belong to?" but "should this row
                # exist at all?" — which is a far easier thing for a person to
                # answer, and the reason this is surfaced rather than left for
                # them to notice.
                twin = (
                    db.query(func.count(BusinessService.id))
                    .filter(
                        BusinessService.organization_id == org_id,
                        BusinessService.name == service.name,
                        BusinessService.id != service.id,
                        func.cardinality(BusinessService.value_stream_ids) > 0,
                    )
                    .scalar()
                )
                notes = []
                if twin:
                    notes.append(f"⚠️ {twin} placed service(s) share this name — likely a duplicate row")
                if bundles:
                    # Dependencies beneath an unowned service: the concrete cost.
                    notes.append(f"{bundles} dependency bundle(s) — unowned while this stands")
                if service.tier:
                    notes.append(f"tier {service.tier}")
                if service.archetype:
                    notes.append(str(service.archetype))
                suffix = f"  ({' · '.join(notes)})" if notes else ""
                print(f"    {service.name}{suffix}")
                print(f"      {service.id}")
            print()

        print("  Attach one with: PATCH /api/v1/services/{id}/value-streams  (never empty)")
        print("  New services can no longer be created without a process (#378).")


if __name__ == "__main__":
    main()

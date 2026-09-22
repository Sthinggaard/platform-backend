"""Seed a **fabricated** "while you were away" situation, to exercise #375 in the UI.

⚠️ **Everything this writes is invented.** No service was observed to be slow, no
team said any of these words, and no decision was taken. These rows exist so the
notice surfaces — node markers, the digest banner, the drawer cards and the
walkthrough — have something to draw. Never read a seeded notice as a report
about the platform, and never screenshot one as evidence of anything.

It spans **two** real org-7 processes and writes to the dev login
(``admin@risklence.com``, user 2), so the notices appear to whoever signs in there.

The shape mirrors Søren's overview design of 2026-09-05 exactly, so the seeded
banner can be held against the mock:

- **SaaS Core Platform** — Monitoring Service (an *issue*) and CI/CD Pipeline (an
  *update*). Two services, so the row shows both count chips.
- **Billing & Subscription** — Billing and Invoicing management (one *update*).
- Three services across two processes: *"1 open issue · 2 updates"*, and the
  process carrying the issue is listed first.

Each service carries one notice here. The case where a *single* service carries
both an issue and an update — which once made "Next" advance a counter without
moving the screen — is covered by a regression test rather than by this fixture.

Usage:
    poetry run python scripts/seed_service_change_notices.py
    poetry run python scripts/seed_service_change_notices.py --clear   # remove them
"""

from __future__ import annotations

import argparse
import uuid
from datetime import datetime, timedelta, timezone

from src.core.database import get_db_context
from src.core.models import ServiceChangeNotice

ORGANIZATION_ID = 7

#: The dev login. Notices are written *to a person*, so they only appear here.
RECIPIENT_USER_ID = 2
#: Somebody else, deliberately: the reader must not be the decider, or the
#: information duty would be telling them what they already know.
ACTOR_USER_ID = 12

# Two real org-7 processes, and the services the design names really are in
# them — so the seeded banner can be held up against the mock directly.
BILLING_PROCESS = "5630daef-69a6-531e-8b4e-e2874de31849"  # Billing & Subscription
SAAS_CORE_PROCESS = "e679e267-f973-582d-a964-51e432cc6c39"  # SaaS Core Platform

MONITORING_SERVICE = "a39073f3-d46a-41da-8274-591870ecef05"
CICD_PIPELINE = "d972b2ae-7f9f-4b16-9d0e-6f8b7b820d29"
BILLING_MANAGEMENT = "345cc5ec-2992-55e8-8d50-97949d92a59d"

SEED_MARKER = "seed-fixture-375"


NOTICES = [
    # ── SaaS Core Platform — an issue and an update, on two services ─────────
    {
        "process_id": SAAS_CORE_PROCESS,
        "service_id": MONITORING_SERVICE,
        "kind": "issue",
        "age": timedelta(days=2),
        "title": "Elevated latency",
        "description": (
            "The metrics pipeline is running 15-20 minutes behind. Alerts still "
            "fire, but dashboards lag, so a graph read right now may not show "
            "what is happening right now."
        ),
        "owner_comment": (
            "We are adding a second ingest worker this afternoon. Alerting is "
            "unaffected — it reads the stream, not the rollups."
        ),
    },
    {
        "process_id": SAAS_CORE_PROCESS,
        "service_id": CICD_PIPELINE,
        "kind": "update",
        "age": timedelta(days=1),
        "title": "Runner image upgraded",
        "description": (
            "Build runners moved to Ubuntu 24.04. Build times drop by roughly a "
            "minute; nothing in the pipeline definition changes."
        ),
        "owner_comment": "No action needed unless you pin a runner image explicitly.",
    },
    # ── Billing & Subscription — one update ─────────────────────────────────
    {
        "process_id": BILLING_PROCESS,
        "service_id": BILLING_MANAGEMENT,
        "kind": "update",
        "age": timedelta(hours=6),
        "title": "API contract v2 rolled out",
        "description": (
            "The billing API now returns amounts in minor units on every "
            "endpoint. v1 keeps working until the end of the quarter."
        ),
        "owner_comment": None,
    },
]


def clear(db) -> int:
    removed = (
        db.query(ServiceChangeNotice)
        .filter(
            ServiceChangeNotice.organization_id == ORGANIZATION_ID,
            ServiceChangeNotice.decision_record_id == SEED_MARKER,
        )
        .delete(synchronize_session=False)
    )
    db.commit()
    return removed


def seed(db) -> int:
    now = datetime.now(timezone.utc).replace(tzinfo=None)
    for entry in NOTICES:
        db.add(
            ServiceChangeNotice(
                id=str(uuid.uuid4()),
                organization_id=ORGANIZATION_ID,
                service_id=entry["service_id"],
                process_id=entry["process_id"],
                recipient_user_id=RECIPIENT_USER_ID,
                kind=entry["kind"],
                title=entry["title"],
                description=entry["description"],
                owner_comment=entry["owner_comment"],
                actor_user_id=ACTOR_USER_ID,
                decision_record_id=SEED_MARKER,
                created_at=now - entry["age"],
                updated_at=now - entry["age"],
            )
        )
    db.commit()
    return len(NOTICES)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--clear", action="store_true", help="remove seeded notices and stop")
    args = parser.parse_args()

    with get_db_context() as db:
        removed = clear(db)
        if args.clear:
            print(f"Removed {removed} seeded notice(s). Nothing else was touched.")
            return

        written = seed(db)
        print(
            f"Removed {removed} stale seeded notice(s); wrote {written} FABRICATED notice(s).\n"
            f"\n"
            f"  ⚠️  These are invented. No service was observed to be slow and no team\n"
            f"      said any of these words. They exist only to draw the #375 surfaces.\n"
            f"\n"
            f"  Sign in as admin@risklence.com (user {RECIPIENT_USER_ID}, org {ORGANIZATION_ID}).\n"
            f"\n"
            f"  On the OVERVIEW: a banner reading '3 services across 2 business\n"
            f"  processes changed · 1 open issue · 2 updates', with SaaS Core Platform\n"
            f"  first (it carries the issue) and a 'Walk through' on each row.\n"
            f"\n"
            f"  On either MAP: a warning marker on Monitoring Service, update markers\n"
            f"  on CI/CD Pipeline and Billing and Invoicing, and a Notifications tab\n"
            f"  on each.\n"
            f"\n"
            f"  Remove with: poetry run python scripts/seed_service_change_notices.py --clear"
        )


if __name__ == "__main__":
    main()

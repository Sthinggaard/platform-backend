"""A service may never be left in no process (#378).

Søren, 2026-08-31: *"A service in no process should not exist."* The API refuses
to create one; these cover the other half — the paths that take a process away.

⚠️ The 57 orphans that exist were not made through a request model. They were
made by code that rebuilt `value_stream_ids` directly and left `[]` when it
removed the last one, which no amount of request validation would have caught.
"""

from __future__ import annotations

import pytest

from src.core.models import BusinessService
from src.core.services.service_process_membership import (
    ServiceWouldBeOrphanedError,
    assert_removal_leaves_a_process,
)


def service(name: str, streams: list[str]) -> BusinessService:
    return BusinessService(id=name, name=name, value_stream_ids=streams)


def test_removing_a_process_a_service_also_belongs_elsewhere_is_allowed():
    assert_removal_leaves_a_process(
        [service("Card Processing", ["p1", "p2"])], process_id="p1", process_name="Payments"
    )


def test_removing_a_service_last_process_is_refused():
    with pytest.raises(ServiceWouldBeOrphanedError) as raised:
        assert_removal_leaves_a_process(
            [service("Card Processing", ["p1"])], process_id="p1", process_name="Payments"
        )

    # Named, because "a service would be orphaned" is not something a reader can
    # act on — they need to know which one.
    assert raised.value.service_names == ["Card Processing"]
    assert "Card Processing" in str(raised.value)
    assert "no accountable owner" in str(raised.value)


def test_it_names_every_service_at_once_rather_than_one_per_attempt():
    """All-or-nothing: a template switch must not fail four services deep."""
    with pytest.raises(ServiceWouldBeOrphanedError) as raised:
        assert_removal_leaves_a_process(
            [
                service("Audit Logging", ["p1"]),
                service("Card Processing", ["p1"]),
                service("Booking", ["p1", "p2"]),
            ],
            process_id="p1",
            process_name="Payments",
        )

    assert raised.value.service_names == ["Audit Logging", "Card Processing"]
    # The one that belongs elsewhere is not in the refusal.
    assert "Booking" not in str(raised.value)


def test_a_service_not_in_the_process_orphans_nothing():
    # Removing what is not there is not a removal.
    assert_removal_leaves_a_process(
        [service("Card Processing", ["p2"])], process_id="p1", process_name="Payments"
    )


def test_a_service_already_orphaned_is_not_reported_by_this_guard():
    """It guards the *transition*, not the existing 57.

    Those are reported by `scripts/report_orphaned_services.py` and resolved by a
    person — never by a rule firing on an edit that did not cause them.
    """
    assert_removal_leaves_a_process(
        [service("Card Processing", [])], process_id="p1", process_name="Payments"
    )

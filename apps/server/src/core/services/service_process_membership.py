"""Keeping every Business Service inside at least one process (#378).

Søren, 2026-08-31: *"A service in no process should not exist."*

Accountability resolves dependency → service → process → owner. A service in no
process terminates that chain at **nobody** — there is no process owner to fall
back to — so every dependency beneath it becomes unowned and undecidable.

The API refuses to create one. This is the other half: the paths that take a
process *away* from a service. Two of them rebuilt `value_stream_ids` directly,
without going near a request model, and left `[]` whenever they removed the last
one. That is almost certainly how 57 orphans came to exist.

⚠️ **Checked before anything is written, never during.** Søren chose refusal
over deleting the service or silently keeping the link, and a refusal halfway
through a template switch would leave the process in a state nobody asked for.
So the whole removal is examined first and either all of it happens or none of
it does.
"""

from __future__ import annotations

from src.core.exceptions import RisklenceException
from src.core.models import BusinessService


class ServiceWouldBeOrphanedError(RisklenceException):
    """A removal would leave a Business Service in no process at all.

    Carries the names, because "a service would be orphaned" tells the reader
    nothing they can act on — they need to know which, so they can attach it
    somewhere else or remove it deliberately.
    """

    def __init__(self, service_names: list[str], process_name: str) -> None:
        self.service_names = service_names
        self.process_name = process_name
        listed = ", ".join(f'"{name}"' for name in service_names)
        plural = "services" if len(service_names) > 1 else "service"
        super().__init__(
            f"Cannot remove {listed} from {process_name!r}: "
            f"{'they belong' if len(service_names) > 1 else 'it belongs'} to no other process, "
            f"and a {plural.rstrip('s')} with no process has no accountable owner. "
            f"Attach {'them' if len(service_names) > 1 else 'it'} to another process first, "
            f"or delete {'them' if len(service_names) > 1 else 'it'} deliberately."
        )


def assert_removal_leaves_a_process(
    services: list[BusinessService], *, process_id: str, process_name: str
) -> None:
    """Refuse the whole removal if it would orphan any of these services.

    `services` are the ones about to lose `process_id`. A service that is not in
    that process is ignored — removing what is not there orphans nothing.
    """
    orphaned = [
        service
        for service in services
        if process_id in (service.value_stream_ids or [])
        and len([sid for sid in (service.value_stream_ids or []) if sid != process_id]) == 0
    ]
    if orphaned:
        raise ServiceWouldBeOrphanedError(
            sorted(service.name for service in orphaned), process_name
        )

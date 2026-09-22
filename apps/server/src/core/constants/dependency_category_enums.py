"""The five stable categories used to organise a service's dependencies (#464)."""

from enum import StrEnum


class DependencyCategory(StrEnum):
    APPLICATION = "application"
    INFRASTRUCTURE = "infrastructure"
    DATA = "data"
    THIRD_PARTIES = "third_parties"
    OPERATIONAL_TEAM = "operational_team"


#: Legacy capability-group keys → the approved five-category taxonomy. The
#: category remains on the logical slot; it is never inferred from an Artefact.
#: Søren approved identity/access as Infrastructure on 2026-09-18.
DEPENDENCY_CATEGORY_BY_GROUP_KEY: dict[str, DependencyCategory] = {
    "systems": DependencyCategory.APPLICATION,
    "application": DependencyCategory.APPLICATION,
    "infrastructure": DependencyCategory.INFRASTRUCTURE,
    "identity_access": DependencyCategory.INFRASTRUCTURE,
    "data": DependencyCategory.DATA,
    "external_providers": DependencyCategory.THIRD_PARTIES,
    "operations": DependencyCategory.OPERATIONAL_TEAM,
    # Kept for audit continuity even though accountable teams are not counted
    # as dependency answers (#434).
    "teams": DependencyCategory.OPERATIONAL_TEAM,
}


def dependency_category_for_group(group_key: str | None) -> DependencyCategory | None:
    """Return a category only when the group's product mapping is explicit."""
    return DEPENDENCY_CATEGORY_BY_GROUP_KEY.get(group_key or "")

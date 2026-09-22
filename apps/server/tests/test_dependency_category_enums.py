"""The five-category dependency taxonomy is complete for every canonical slot."""

from src.core.constants.dependency_category_enums import (
    DependencyCategory,
    dependency_category_for_group,
)
from src.core.constants.dependency_templates import PATTERN_GROUP_BY_KEY


def test_every_canonical_slot_group_has_an_approved_category() -> None:
    unmapped_groups = {
        group_key
        for group_key in PATTERN_GROUP_BY_KEY.values()
        if dependency_category_for_group(group_key) is None
    }

    assert unmapped_groups == set()


def test_identity_access_is_infrastructure() -> None:
    assert dependency_category_for_group("identity_access") is DependencyCategory.INFRASTRUCTURE

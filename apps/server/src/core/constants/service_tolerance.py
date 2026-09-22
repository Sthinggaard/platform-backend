"""Canonical business-service tolerance windows and legacy read compatibility."""

from __future__ import annotations

from typing import Literal, TypeAlias

ServiceToleranceWindow: TypeAlias = Literal["le_1h", "le_4h", "le_24h", "gt_24h"]

SERVICE_TOLERANCE_WINDOWS: tuple[ServiceToleranceWindow, ...] = (
    "le_1h",
    "le_4h",
    "le_24h",
    "gt_24h",
)

_CANONICAL_SERVICE_TOLERANCE_WINDOW_MAP: dict[str, ServiceToleranceWindow] = {
    value: value for value in SERVICE_TOLERANCE_WINDOWS
}

# Seeded records before the BIA taxonomy used elapsed-hour strings. This map is
# read-only compatibility: API writes remain limited to the canonical values.
LEGACY_SERVICE_TOLERANCE_WINDOW_MAP: dict[str, ServiceToleranceWindow] = {
    "1h": "le_1h",
    "2h": "le_4h",
    "4h": "le_4h",
    "24h": "le_24h",
    "48h": "gt_24h",
}


def normalize_service_tolerance_window(value: str | None) -> ServiceToleranceWindow | None:
    """Return a canonical tolerance window without inventing an unknown value."""
    if value is None:
        return None

    normalized = value.strip().casefold()
    return (
        _CANONICAL_SERVICE_TOLERANCE_WINDOW_MAP.get(normalized)
        or LEGACY_SERVICE_TOLERANCE_WINDOW_MAP.get(normalized)
    )

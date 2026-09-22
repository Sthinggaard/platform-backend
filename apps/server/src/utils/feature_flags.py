"""
Lightweight feature flag helper.

Flags can be set via settings.feature_flags or overridden with env vars:
FEATURE_FLAG_<UPPER_SNAKE_CASE>=true/false.
"""

import os
from typing import Optional

from src.core.config import settings


def _env_override(flag: str) -> Optional[bool]:
    env_key = f"FEATURE_FLAG_{flag.upper().replace('-', '_')}"
    val = os.getenv(env_key)
    if val is None:
        return None
    return val.lower() in {"1", "true", "yes", "on"}


def is_enabled(flag: str, default: bool = False) -> bool:
    """
    Check if a feature flag is enabled.

    Order of precedence:
    1. Environment variable FEATURE_FLAG_<FLAG>
    2. settings.feature_flags[flag]
    3. default
    """
    override = _env_override(flag)
    if override is not None:
        return override
    return settings.feature_flags.get(flag, default)


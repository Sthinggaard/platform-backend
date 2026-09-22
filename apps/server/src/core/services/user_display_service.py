"""Human-readable display name for a User, shared wherever an owner/sponsor is shown."""

from __future__ import annotations

from src.core.model_defs.tenant_identity import User


def user_display_name(user: User) -> str:
    parts = [part for part in [user.first_name, user.last_name] if part]
    if parts:
        return " ".join(parts)
    return user.email.split("@")[0].replace(".", " ").title()

"""Provider adapter interface for connectivity verification."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Optional, Protocol, Tuple

from src.core.logging_config import get_logger

logger = get_logger(__name__)


class ProviderAdapter(Protocol):
    def verify(self, *, role_arn: Optional[str], external_id: Optional[str], provider_account_id: Optional[str]) -> Tuple[bool, Optional[str]]:
        """Return (success, diagnostic_code). Diagnostic_code is optional slug on failure."""


@dataclass
class AWSAdapter:
    """Stubbed AWS adapter. In production, perform STS AssumeRole with external_id."""

    def verify(
        self,
        *,
        role_arn: Optional[str],
        external_id: Optional[str],
        provider_account_id: Optional[str],
    ) -> Tuple[bool, Optional[str]]:
        if not role_arn:
            return False, "ROLE_ARN_MISSING"
        if not external_id:
            return False, "EXTERNAL_ID_MISSING"
        if not provider_account_id or len(provider_account_id) != 12:
            return False, "ACCOUNT_ID_INVALID"
        # Stub success without calling AWS; replace with STS AssumeRole when configured.
        logger.info("Stub AWS verification for role_arn=%s account=%s", role_arn, provider_account_id)
        return True, None


class NoOpAdapter:
    """Adapter placeholder for providers we do not yet support."""

    def verify(
        self,
        *,
        role_arn: Optional[str],
        external_id: Optional[str],
        provider_account_id: Optional[str],
    ) -> Tuple[bool, Optional[str]]:
        return False, "ADAPTER_NOT_AVAILABLE"


def get_provider_adapter(provider: str) -> ProviderAdapter:
    from src.core.constants import Provider

    if provider == Provider.AWS.value:
        return AWSAdapter()
    return NoOpAdapter()

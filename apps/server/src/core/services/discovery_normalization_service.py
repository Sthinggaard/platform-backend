"""Step 4.1A — source-independent normalization boundary.

The Collector remains responsible for collecting technical facts; this
boundary is responsible for turning those facts into stable,
organisation-level ``Asset`` rows via ``artefact_identity_service``. It
never assigns business criticality or Business Service ownership — that
stays Step 4.1C's job.

Two concrete adapters exist now, both wrapping the same real, working
normalization pipeline (``risk_intelligence_normalization_service``) —
neither duplicates its asset-matching/signal/finding logic:
``RiskIntelligenceIngestionAdapter`` (uploaded batches, the original
source) and ``DiscoveryExecutionEvidenceAdapter`` (DISC-32 — Step 4.2's
own ``EvidencePackage`` rows, the scanner-sourced adapter this module's
own docstring long flagged as a defined extension point, not fabricated
until a real execution pipeline existed to produce one).
"""

from __future__ import annotations

from typing import Protocol

from sqlalchemy.orm import Session

from src.core.services.discovery_execution_evidence_adapter import DiscoveryExecutionEvidenceAdapter
from src.core.services.risk_intelligence_normalization_service import (
    NormalizationResult,
    normalize_ingestion_batch,
)


class CollectorOutputAdapter(Protocol):
    """One adapter per raw Collector-output shape.

    ``execution_id`` is ``int | str`` — the risk-intelligence-ingestion
    source's batches are integer-keyed, but Step 4.2's own
    ``EvidencePackage`` is UUID-keyed (DISC-32 resolves the typing gap
    flagged back at ``DISC-17``: each adapter still only ever receives the
    identifier shape its own source actually produces, this Protocol just
    stops pretending every source is integer-keyed)."""

    source_type: str

    def supports(self, source_type: str) -> bool: ...

    def normalize(
        self, db: Session, *, organization_id: int, actor_user_id: int | None, execution_id: int | str
    ) -> NormalizationResult: ...


class RiskIntelligenceIngestionAdapter:
    """Adapts uploaded risk-intelligence-ingestion batches — real,
    already-wired, the only genuine Collector-output source today."""

    source_type = "risk_intelligence_ingestion"

    def supports(self, source_type: str) -> bool:
        return source_type == self.source_type

    def normalize(
        self, db: Session, *, organization_id: int, actor_user_id: int | None, execution_id: int
    ) -> NormalizationResult:
        return normalize_ingestion_batch(
            db,
            organization_id=organization_id,
            actor_user_id=actor_user_id,
            batch_id=execution_id,
        )


_ADAPTERS: tuple[CollectorOutputAdapter, ...] = (
    RiskIntelligenceIngestionAdapter(),
    DiscoveryExecutionEvidenceAdapter(),
)


def normalize_execution(
    db: Session, *, organization_id: int, actor_user_id: int | None, source_type: str, execution_id: int | str
) -> NormalizationResult:
    """``DiscoveryNormalizationService.normalizeExecution`` — resolves the
    right adapter for ``source_type`` and delegates. Raises ``ValueError``
    for an unsupported source rather than silently picking one."""
    for adapter in _ADAPTERS:
        if adapter.supports(source_type):
            return adapter.normalize(
                db, organization_id=organization_id, actor_user_id=actor_user_id, execution_id=execution_id
            )
    raise ValueError(f"No CollectorOutputAdapter supports source_type={source_type!r}")

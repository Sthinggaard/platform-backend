"""Step 4.2 Part 2 — DISC-32: outbox-style normalization handoff durability.

Mirrors ``discovery_execution_scheduler_service.dispatch_ready_jobs``'s own
shape: a periodic sweep (not committing itself — the Celery task wrapper
that calls it owns the commit, exactly like ``dispatch_ready_jobs``) that
finds every ``EvidencePackage`` still waiting to be normalized and hands
each to ``DiscoveryExecutionEvidenceAdapter`` via the existing
``discovery_normalization_service.normalize_execution`` dispatcher — so a
queued handoff survives a worker restart (the package's own
``normalization_status`` is the durable queue, not an in-memory list).

Only ``STORED`` packages with ``evidence_format=nmap_xml`` are picked up
today — the only format ``DiscoveryExecutionEvidenceAdapter`` actually
supports (see its own module docstring); a package in any other format is
left ``PENDING``, correctly reflecting "no adapter for this format yet,"
not a failure.
"""

from __future__ import annotations

from sqlalchemy import tuple_
from sqlalchemy.orm import Session

from src.core.constants.discovery_execution_enums import (
    EvidenceFormat,
    EvidenceNormalizationStatus,
    EvidencePackageProcessingStatus,
)
from src.core.logging_config import get_logger
from src.core.model_defs.discovery_execution import EvidencePackage
from src.core.services.discovery_execution_evidence_adapter import (
    DiscoveryEvidenceNormalizationError,
    DiscoveryExecutionEvidenceAdapter,
)
from src.core.services.discovery_normalization_service import normalize_execution
from src.core.services.discovery_execution_evidence_adapter import (
    SUPPORTED_EVIDENCE_PARSER_KEYS,
)
from src.core.services.evidence_package_lifecycle_service import (
    transition_evidence_package_normalization,
)

logger = get_logger(__name__)


def process_pending_evidence_packages(db: Session) -> list[EvidencePackage]:
    processed: list[EvidencePackage] = []
    packages = (
        db.query(EvidencePackage)
        .filter(
            EvidencePackage.processing_status == EvidencePackageProcessingStatus.STORED.value,
            EvidencePackage.normalization_status.in_(
                [
                    EvidenceNormalizationStatus.PENDING.value,
                    EvidenceNormalizationStatus.QUEUED.value,
                ]
            ),
            # Whatever the evidence adapter can parse — not a hardcoded single
            # format. This previously pinned NMAP_XML, so a Subfinder package
            # was never selected even though _parse_subfinder_text has been
            # registered for it all along: the parser existed, the query just
            # never handed it anything. Nothing could be normalised, so no
            # discovery ever produced an asset.
            tuple_(EvidencePackage.evidence_format, EvidencePackage.provider_id).in_(
                sorted(SUPPORTED_EVIDENCE_PARSER_KEYS)
            ),
        )
        .all()
    )
    for package in packages:
        transition_evidence_package_normalization(package, EvidenceNormalizationStatus.QUEUED.value)
        db.add(package)
        db.flush()
        try:
            normalize_execution(
                db,
                organization_id=package.organization_id,
                actor_user_id=None,
                source_type=DiscoveryExecutionEvidenceAdapter.source_type,
                execution_id=package.id,
            )
        except DiscoveryEvidenceNormalizationError as exc:
            # Already marked NORMALIZATION_FAILED and audited inside the
            # adapter itself before this was raised — logged here only so
            # the failure is visible in the worker's own logs too, and so
            # one package's failure never stops the sweep from processing
            # every other one (mirrors dispatch_ready_jobs's own per-job
            # failure isolation).
            logger.warning(
                "discovery_evidence_normalization_failed",
                evidence_package_id=package.id,
                error=str(exc),
            )
            continue
        processed.append(package)
    return processed


__all__ = ["process_pending_evidence_packages"]

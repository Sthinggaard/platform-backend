"""Lightweight monitoring loop simulating evidence signals and status changes."""

from __future__ import annotations

import random
import threading
import time
from datetime import datetime, timezone
from typing import Callable

from sqlalchemy.orm import Session, sessionmaker

from src.asset_monitoring.service import create_signal, record_status, create_network_findings
from src.core.logging_config import get_logger
from src.core.database import Base, get_postgres_engine
from src.core.models import (
    Asset,
    AssetFindingStatus,
    AssetStatus,
    SeverityLevel,
    utcnow,
)
from src.core.services.resolution_verification_service import run_verification_for_asset

logger = get_logger(__name__)


class AssetMonitoringEngine:
    """Background simulator for continuous monitoring."""

    def __init__(self, session_factory: Callable[[], Session] | sessionmaker, interval_seconds: int = 10, seed: int = 1337):
        self.session_factory = session_factory
        self.interval_seconds = interval_seconds
        self.seed = seed
        self._stop_event = threading.Event()
        self._thread = threading.Thread(target=self._run_loop, daemon=True)
        self._schema_ready = False

    def start(self) -> None:
        if self._thread.is_alive():
            return
        self._stop_event.clear()
        self._thread.start()
        logger.info("monitoring_engine_started", interval_seconds=self.interval_seconds)

    def stop(self) -> None:
        self._stop_event.set()
        if self._thread.is_alive():
            self._thread.join(timeout=5)
        logger.info("monitoring_engine_stopped")

    def enqueue_initial_observation(self, asset_id: int, delay_seconds: float = 1.5) -> None:
        """Schedule an initial observation to move an asset out of partial state."""
        threading.Timer(delay_seconds, self._initial_probe, args=(asset_id,)).start()

    def _create_session(self) -> Session:
        """Return a new Session, whether session_factory is a sessionmaker or a callable returning Session."""
        candidate = self.session_factory()
        if isinstance(candidate, sessionmaker):
            return candidate()
        if isinstance(candidate, Session):
            return candidate
        # If the factory returns another callable (nested), attempt one more call.
        if callable(candidate):
            maybe_session = candidate()
            if isinstance(maybe_session, Session):
                return maybe_session
        raise TypeError("session_factory did not return a Session")

    def _ensure_schema(self) -> None:
        """Create tables if they do not exist (idempotent)."""
        if self._schema_ready:
            return
        try:
            Base.metadata.create_all(bind=get_postgres_engine())
            self._schema_ready = True
        except Exception as exc:  # pragma: no cover - guardrail
            logger.error("monitoring_engine_schema_setup_failed", error=str(exc), exc_info=True)

    def _initial_probe(self, asset_id: int) -> None:
        db: Session | None = None
        try:
            db = self._create_session()
            asset = db.get(Asset, asset_id)
            if not asset:
                return
            target_status = (
                AssetStatus.AT_RISK if asset.layer.lower() == "network" else AssetStatus.OPERATIONALLY_COMPLIANT
            )
            if target_status == AssetStatus.AT_RISK:
                create_network_findings(db, asset)
                risk_score = 80.0
                confidence = 0.62
            else:
                risk_score = 12.0
                confidence = 0.92
            record_status(
                db,
                asset,
                target_status,
                risk_score=risk_score,
                observation_level="enhanced",
                findings_count=asset.findings_count,
                confidence=confidence,
                observed_at=utcnow(),
            )
            run_verification_for_asset(db, organization_id=asset.organization_id, asset_id=asset.id)
            db.commit()
        finally:
            if db:
                db.close()

    def _run_loop(self) -> None:
        rng = random.Random(self.seed)
        while not self._stop_event.is_set():
            started = time.perf_counter()
            db: Session | None = None
            try:
                self._ensure_schema()
                db = self._create_session()
                self._tick(db, rng)
                db.commit()
            except Exception as exc:  # pragma: no cover - guardrail
                if db:
                    db.rollback()
                logger.error("monitoring_engine_tick_failed", error=str(exc), exc_info=True)
            finally:
                if db:
                    db.close()
            elapsed = time.perf_counter() - started
            wait_for = max(0.5, self.interval_seconds - elapsed)
            self._stop_event.wait(wait_for)

    def _tick(self, db: Session, rng: random.Random) -> None:
        assets = (
            db.query(Asset)
            .filter(Asset.status != AssetStatus.NOT_CONNECTED)
            .all()
        )
        for asset in assets:
            self._simulate_asset(db, asset, rng)

    def _simulate_asset(self, db: Session, asset: Asset, rng: random.Random) -> None:
        """Generate synthetic signals and adjust status."""
        observed_at = utcnow()
        base_confidence = 0.55 + rng.random() * 0.35
        drift = rng.uniform(-10.0, 10.0)
        risk_score = max(0.0, min(100.0, (asset.risk_score or 20.0) + drift))

        signal_kind = "health"
        payload = {
            "latency_ms": round(50 + rng.random() * 100, 2),
            "throughput": round(100 + rng.random() * 50, 1),
            "alerts": rng.choice([0, 0, 1]),
        }
        if asset.layer.lower() == "network":
            signal_kind = "network_scan"
            payload |= {"ingress_public": rng.choice([True, False, False]), "anomaly_score": round(rng.random(), 2)}
        elif asset.layer.lower() == "identity":
            signal_kind = "identity_event"
            payload |= {"mfa_events": rng.randint(0, 3), "sso_errors": rng.randint(0, 2)}

        create_signal(
            db,
            asset,
            kind=signal_kind,
            payload=payload,
            confidence=base_confidence,
            risk_score=risk_score,
            observed_at=observed_at,
        )

        next_status = AssetStatus.OPERATIONALLY_COMPLIANT
        findings_count = asset.findings_count
        if asset.layer.lower() == "network" and (payload.get("ingress_public") or risk_score > 60):
            next_status = AssetStatus.AT_RISK
        elif risk_score > 70:
            next_status = AssetStatus.AT_RISK
        elif asset.status == AssetStatus.PARTIALLY_OBSERVED and risk_score > 20:
            next_status = AssetStatus.OPERATIONALLY_COMPLIANT

        # Create findings when risky
        if next_status == AssetStatus.AT_RISK and not asset.findings:
            create_network_findings(db, asset)
            findings_count = len(asset.findings)
        elif next_status == AssetStatus.OPERATIONALLY_COMPLIANT and asset.findings:
            # mark findings as resolved after sustained healthy signals
            for finding in asset.findings:
                finding.status = AssetFindingStatus.RESOLVED
                finding.last_seen_at = datetime.now(tz=timezone.utc)
            findings_count = 0

        record_status(
            db,
            asset,
            next_status,
            risk_score=risk_score,
            observation_level="continuous",
            findings_count=findings_count,
            confidence=base_confidence,
            observed_at=observed_at,
        )
        run_verification_for_asset(db, organization_id=asset.organization_id, asset_id=asset.id)

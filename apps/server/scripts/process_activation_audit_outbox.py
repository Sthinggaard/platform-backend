"""
Process pending tenant activation audit outbox rows.

Usage:
    PYTHONPATH=apps/server:apps python apps/server/scripts/process_activation_audit_outbox.py
    PYTHONPATH=apps/server:apps python apps/server/scripts/process_activation_audit_outbox.py --dry-run
"""

from __future__ import annotations

import argparse
import json
import sys
import time
from datetime import datetime, timezone

from sqlalchemy import func, select

from src.api.routes.activation import process_activation_audit_outbox
from src.core.database import get_db_context
from src.core.logging_config import get_logger
from src.core.models import ActivationAuditOutbox

logger = get_logger(__name__)


def _outbox_stats(db) -> dict[str, object]:
    pending_count = db.execute(
        select(func.count()).select_from(ActivationAuditOutbox).where(ActivationAuditOutbox.status == "pending")
    ).scalar_one()
    oldest_pending = db.execute(
        select(ActivationAuditOutbox.created_at)
        .where(ActivationAuditOutbox.status == "pending")
        .order_by(ActivationAuditOutbox.created_at.asc())
        .limit(1)
    ).scalar_one_or_none()
    age_seconds = None
    if isinstance(oldest_pending, datetime):
        normalized = oldest_pending if oldest_pending.tzinfo else oldest_pending.replace(tzinfo=timezone.utc)
        age_seconds = max(0, int((datetime.now(timezone.utc) - normalized).total_seconds()))
    return {
        "pendingCount": int(pending_count or 0),
        "oldestPendingAt": oldest_pending.isoformat() if isinstance(oldest_pending, datetime) else None,
        "oldestPendingAgeSeconds": age_seconds,
    }


def _threshold_breaches(
    *,
    stats: dict[str, object],
    warn_pending_threshold: int | None,
    warn_oldest_seconds: int | None,
) -> list[str]:
    breaches: list[str] = []
    pending_count = int(stats.get("pendingCount") or 0)
    oldest_age = stats.get("oldestPendingAgeSeconds")
    if warn_pending_threshold is not None and pending_count > warn_pending_threshold:
        breaches.append(f"pendingCount>{warn_pending_threshold} (actual={pending_count})")
    if warn_oldest_seconds is not None and isinstance(oldest_age, int) and oldest_age > warn_oldest_seconds:
        breaches.append(f"oldestPendingAgeSeconds>{warn_oldest_seconds} (actual={oldest_age})")
    return breaches


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Process pending activation audit outbox rows.")
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Only print pending outbox stats without processing rows.",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Emit machine-readable JSON output.",
    )
    parser.add_argument(
        "--loop",
        action="store_true",
        help="Run continuously (process + report in intervals).",
    )
    parser.add_argument(
        "--interval-seconds",
        type=int,
        default=30,
        help="Loop interval seconds when --loop is used (default: 30).",
    )
    parser.add_argument(
        "--max-iterations",
        type=int,
        default=0,
        help="Stop after N iterations in loop mode (0 = infinite).",
    )
    parser.add_argument(
        "--warn-pending-threshold",
        type=int,
        default=None,
        help="Warn when pending outbox rows exceed this count.",
    )
    parser.add_argument(
        "--warn-oldest-seconds",
        type=int,
        default=None,
        help="Warn when oldest pending outbox row age exceeds this many seconds.",
    )
    parser.add_argument(
        "--fail-on-threshold-breach",
        action="store_true",
        help="Exit non-zero if backlog thresholds are exceeded.",
    )
    args = parser.parse_args(argv)
    if args.interval_seconds < 1:
        parser.error("--interval-seconds must be >= 1")
    if args.max_iterations < 0:
        parser.error("--max-iterations must be >= 0")

    iterations = 0
    overall_exit_code = 0
    while True:
        iterations += 1
        with get_db_context() as db:
            before = _outbox_stats(db)
            flushed = 0
            if not args.dry_run and before["pendingCount"]:
                flushed = process_activation_audit_outbox(db)
            after = _outbox_stats(db)

        breaches = _threshold_breaches(
            stats=after,
            warn_pending_threshold=args.warn_pending_threshold,
            warn_oldest_seconds=args.warn_oldest_seconds,
        )
        payload = {
            "mode": "dry_run" if args.dry_run else "process",
            "iteration": iterations,
            "before": before,
            "flushedCount": int(flushed),
            "after": after,
            "thresholdBreaches": breaches,
        }

        if args.json:
            print(json.dumps(payload, ensure_ascii=True, separators=(",", ":"), sort_keys=True))
        else:
            print(
                "Activation audit outbox processed: "
                f"iteration={iterations} before={before['pendingCount']} flushed={flushed} after={after['pendingCount']}"
            )
            if after["oldestPendingAt"]:
                print(
                    "Oldest pending outbox row: "
                    f"{after['oldestPendingAt']} (ageSeconds={after['oldestPendingAgeSeconds']})"
                )
            if breaches:
                print("Backlog threshold breach: " + "; ".join(breaches))

        if breaches:
            logger.warning(
                "activation_audit_outbox_backlog_threshold_breach",
                breaches=breaches,
                pending_count=after["pendingCount"],
                oldest_pending_at=after["oldestPendingAt"],
                oldest_pending_age_seconds=after["oldestPendingAgeSeconds"],
            )
            if args.fail_on_threshold_breach:
                overall_exit_code = 2
        logger.info(
            "activation_audit_outbox_processor_finished",
            mode=payload["mode"],
            iteration=iterations,
            before_pending=before["pendingCount"],
            flushed_count=flushed,
            after_pending=after["pendingCount"],
            oldest_pending_at=after["oldestPendingAt"],
            oldest_pending_age_seconds=after["oldestPendingAgeSeconds"],
            threshold_breaches=breaches,
        )

        if not args.loop:
            return overall_exit_code
        if args.max_iterations and iterations >= args.max_iterations:
            return overall_exit_code
        time.sleep(args.interval_seconds)


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))

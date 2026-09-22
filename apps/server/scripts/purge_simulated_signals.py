"""Remove the fabricated signals the monitoring simulator wrote (BUG-DISC-18).

``AssetMonitoringEngine`` generated random latency, throughput and event counts
and stored them in ``asset_evidence_signals`` — the table that also holds the
real evidence justifying every artefact. On Søren's database that was **14.5
million rows and 3.6 GB behind 84 assets**, and it was still growing at ~25,000
rows an hour.

These rows are not evidence of anything. Keeping them has no audit value and a
real cost: they are indistinguishable in shape from genuine evidence, they were
feeding control-coverage evaluation (BL-01/BL-02 read ``identity_event`` and
``network_scan``), and their volume is what made normalisation unfinishable.

**A script, not a migration**, for the same reason as the classification
backfill: a schema migration is the wrong place for a bulk data decision that
may need repeating, that should be observable while it runs, and that a
deployment must not silently block on for minutes.

Deletes in batches so the table stays writable throughout. Dry-run by default.
"""

from __future__ import annotations

import argparse

from sqlalchemy import func, select

from src.core.database import get_db_context
from src.core.model_defs.assets_runtime import AssetEvidenceSignal
from src.core.services.signal_retention_service import PRUNE_BATCH_SIZE, SIMULATED_KINDS


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--apply", action="store_true", help="actually delete (default: dry run)")
    parser.add_argument("--batch-size", type=int, default=PRUNE_BATCH_SIZE)
    args = parser.parse_args()

    with get_db_context() as db:
        counts = dict(
            db.execute(
                select(AssetEvidenceSignal.kind, func.count(AssetEvidenceSignal.id))
                .where(AssetEvidenceSignal.kind.in_(SIMULATED_KINDS))
                .group_by(AssetEvidenceSignal.kind)
            ).all()
        )
        total = sum(counts.values())
        for kind, count in sorted(counts.items(), key=lambda item: -item[1]):
            print(f"  {kind:<20} {count:>12,}")
        if not total:
            print("Nothing fabricated left to remove.")
            return
        if not args.apply:
            print(f"\n{total:,} fabricated signals would be removed (dry run — pass --apply).")
            return

        removed = 0
        while True:
            ids = [
                row[0]
                for row in db.execute(
                    select(AssetEvidenceSignal.id)
                    .where(AssetEvidenceSignal.kind.in_(SIMULATED_KINDS))
                    .limit(args.batch_size)
                ).all()
            ]
            if not ids:
                break
            db.query(AssetEvidenceSignal).filter(AssetEvidenceSignal.id.in_(ids)).delete(
                synchronize_session=False
            )
            db.commit()
            removed += len(ids)
            print(f"  removed {removed:,} / {total:,}", end="\r", flush=True)

        print(f"\n{removed:,} fabricated signals removed.")
        print("Run VACUUM FULL on asset_evidence_signals to reclaim the space.")


if __name__ == "__main__":
    main()

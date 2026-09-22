"""Re-derive discovered artefacts' classification from evidence already stored.

Discovery's classifier was rewritten (BUG-DISC-15): it used to record whether a
scan found ports rather than what a host is. Rows written before that cannot be
re-derived by the normal path until the next scan observes those hosts again —
so this reclassifies them now, from the host records already captured in
``asset_evidence_signals``.

Not a migration on purpose. A migration must keep doing the same thing years
later, and this deliberately calls the *current* classifier — inlining a copy of
its rules would duplicate them and let the two drift. This is a one-off repair,
run deliberately.

Never touches a classification a person set. That is marked specifically
(``intent.classificationSetByHuman``) rather than inferred from ``reviewed_at``:
confirming an artefact means "yes, this is ours" and says nothing about whether
the label is right, so keying on it would leave a machine guess in place exactly
on the rows someone had already looked at.

    poetry run python scripts/backfill_artefact_classification.py [--apply]

Without --apply it reports what it would change and writes nothing.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from src.core.database import get_db_context  # noqa: E402
from src.core.model_defs.assets_runtime import Asset  # noqa: E402
from src.core.models import AssetEvidenceSignal  # noqa: E402
from src.core.services.artefact_classification_service import (  # noqa: E402
    classify_host_record,
)

_INGESTION_KIND = "risk_intelligence_ingestion"


def _latest_host_record(db, asset_id: int) -> dict | None:
    signal = (
        db.query(AssetEvidenceSignal)
        .filter(
            AssetEvidenceSignal.asset_id == asset_id,
            AssetEvidenceSignal.kind == _INGESTION_KIND,
        )
        .order_by(AssetEvidenceSignal.observed_at.desc())
        .first()
    )
    if signal is None or not isinstance(signal.payload_json, dict):
        return None
    host = signal.payload_json.get("host")
    return host if isinstance(host, dict) else None


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--apply", action="store_true", help="write the changes")
    args = parser.parse_args()

    changed = 0
    evidence_only = 0
    skipped_human = 0
    no_evidence = 0

    with get_db_context() as db:
        assets = (
            db.query(Asset)
            .filter(Asset.provider == "collector")
            .order_by(Asset.id.asc())
            .all()
        )
        for asset in assets:
            intent = asset.intent if isinstance(asset.intent, dict) else {}
            if intent.get("classificationSetByHuman"):
                skipped_human += 1
                continue
            host_record = _latest_host_record(db, asset.id)
            if host_record is None:
                no_evidence += 1
                continue

            result = classify_host_record(host_record)
            reclassifies = (asset.type, asset.layer) != (result.asset_type, result.layer)
            # Refreshed even when the class does not move. The observed services
            # are *evidence*, not a classification, and a host whose evidence is
            # genuinely ambiguous keeps the generic class precisely because its
            # services disagree — which is exactly the row where a reviewer most
            # needs to see them. Gating this on a class change left the best
            # evidence on the emptiest-looking rows.
            refreshes = list(result.observed) != (intent.get("observedServices") or [])
            if not reclassifies and not refreshes:
                continue

            if reclassifies:
                print(
                    f"{asset.display_name}: {asset.type} · {asset.layer}"
                    f"  ->  {result.asset_type} · {result.layer}"
                    f"   observed={', '.join(result.observed) or '-'}"
                )
                changed += 1
            else:
                print(
                    f"{asset.display_name}: class unchanged ({asset.type})"
                    f"   evidence added: {', '.join(result.observed) or '-'}"
                )
                evidence_only += 1

            if args.apply:
                asset.type = result.asset_type
                asset.layer = result.layer
                intent = dict(asset.intent) if isinstance(asset.intent, dict) else {}
                intent["observedServices"] = list(result.observed)
                asset.intent = intent
                db.add(asset)

        if args.apply:
            db.commit()

    print(
        f"\n{changed} reclassified{'' if args.apply else ' (dry run — pass --apply)'}, "
        f"{evidence_only} had only their observed evidence refreshed, "
        f"{skipped_human} left alone because a person had classified them, "
        f"{no_evidence} with no stored host record."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

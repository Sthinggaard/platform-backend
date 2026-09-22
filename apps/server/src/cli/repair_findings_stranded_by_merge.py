"""Findings left behind on artefacts that were merged into another record.

``merge_artefacts`` moved identifiers, ports, relationships and evidence signals
to the survivor, and — until 2026-09-07 — not findings. Every merge before that
fix left its findings pointing at a tombstone: a row in ``MERGED`` that no
surface reads. Read from organisation 7 on 2026-09-07, that was **22 of 25
findings across 4 tombstones**, including the 13 on ``192.168.50.152`` while
``pi-local`` — the surviving record for the same machine — showed none.

The code no longer creates this state. This repairs what it already created.

**Read-only by default**, and reports before it changes anything, following the
precedent Søren set on #378: *"treat it as data to be reviewed with a person,
not swept up by a script."* The difference here, and the reason repair is
offered at all, is that no judgement is being made — the merge decision was
already taken by a person or by identity resolution, and this only finishes an
operation that stopped half way. Nothing is deleted and nothing is invented: a
finding is re-pointed at the record the merge already named as the survivor.

Usage::

    python -m src.cli.repair_findings_stranded_by_merge            # report only
    python -m src.cli.repair_findings_stranded_by_merge --apply    # move them
    python -m src.cli.repair_findings_stranded_by_merge --org 7    # one tenant
"""

from __future__ import annotations

import argparse
from dataclasses import dataclass

from sqlalchemy.orm import Session

from src.core.database import get_db_context
from src.core.model_defs.assets_runtime import Asset, AssetFinding, AssetLifecycleState


@dataclass(frozen=True)
class StrandedFindings:
    organization_id: int
    tombstone_id: int
    tombstone_name: str
    survivor_id: int
    survivor_name: str
    finding_ids: tuple[int, ...]
    titles: tuple[str, ...]


def find_stranded(db: Session, *, organization_id: int | None = None) -> list[StrandedFindings]:
    """Every finding sitting on a merged artefact, grouped by tombstone.

    A tombstone whose survivor is itself merged is **skipped, not followed**.
    Chasing the chain would be this script deciding where a finding really
    belongs, which is exactly the judgement it is written not to make; those are
    reported so a person can look.
    """
    tombstones = (
        db.query(Asset)
        .filter(Asset.lifecycle_state == AssetLifecycleState.MERGED)
        .filter(Asset.merged_into_asset_id.isnot(None))
    )
    if organization_id is not None:
        tombstones = tombstones.filter(Asset.organization_id == organization_id)

    stranded: list[StrandedFindings] = []
    for tombstone in tombstones.all():
        findings = (
            db.query(AssetFinding)
            .filter(AssetFinding.asset_id == tombstone.id)
            .order_by(AssetFinding.id)
            .all()
        )
        if not findings:
            continue

        survivor = db.get(Asset, tombstone.merged_into_asset_id)
        if survivor is None or survivor.organization_id != tombstone.organization_id:
            # Never move a finding across a tenant boundary, whatever the merge
            # record says.
            continue
        if survivor.lifecycle_state == AssetLifecycleState.MERGED:
            continue

        stranded.append(
            StrandedFindings(
                organization_id=tombstone.organization_id,
                tombstone_id=tombstone.id,
                tombstone_name=tombstone.display_name,
                survivor_id=survivor.id,
                survivor_name=survivor.display_name,
                finding_ids=tuple(f.id for f in findings),
                titles=tuple(f.title for f in findings),
            )
        )
    return stranded


def apply(db: Session, stranded: list[StrandedFindings]) -> int:
    moved = 0
    for group in stranded:
        for finding_id in group.finding_ids:
            finding = db.get(AssetFinding, finding_id)
            if finding is None:
                continue
            finding.asset_id = group.survivor_id
            db.add(finding)
            moved += 1
    db.flush()
    return moved


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--apply", action="store_true", help="move them; without this, report only")
    parser.add_argument("--org", type=int, default=None, help="limit to one organisation")
    args = parser.parse_args()

    with get_db_context() as db:
        stranded = find_stranded(db, organization_id=args.org)
        if not stranded:
            print("No findings are stranded on a merged artefact.")
            return 0

        total = sum(len(group.finding_ids) for group in stranded)
        print(f"{total} finding(s) on {len(stranded)} merged artefact(s):\n")
        for group in stranded:
            print(
                f"  org {group.organization_id}  "
                f"{group.tombstone_name} (#{group.tombstone_id}, merged)"
                f"  →  {group.survivor_name} (#{group.survivor_id})"
            )
            for title in group.titles:
                print(f"      · {title}")
            print()

        if not args.apply:
            print("Read-only. Re-run with --apply to move them to the surviving record.")
            return 0

        moved = apply(db, stranded)
        db.commit()
        print(f"Moved {moved} finding(s) to their surviving artefact.")
        return 0


if __name__ == "__main__":
    raise SystemExit(main())

"""CA-09A.6 (#318) — a rejection is evidence about the matching rules.

Søren, 2026-08-26: learning from rejections is the intention for the
intelligence engine.

**What a rejection already did, and where it stopped.** Rejecting a suggestion
writes ``mapping_status="rejected"`` on the row, and ``is_human_decided()`` stops
the engine touching *that row* again. So the wrong suggestion is not repeated in
the one place it was refused — and is made again, identically, for every other
service whose template names the same slot. The person answered a question about
the rules and the platform heard it as a question about one row.

**Only one kind of rejection is evidence about a rule**, which is the whole
reason CA-09A.5 made the reason codes vary:

- ``wrong_asset`` — *the slot is right; this is not what fills it.* The matcher
  reached the wrong artefact, and that is a statement about the rule. **This is
  the only code that refutes.**
- ``asset_not_applicable`` — the artefact is real, nothing in *this service*
  depends on it. True here, and says nothing about anywhere else.
- ``low_confidence`` — *not a no, a not yet.* Treating it as a refutation would
  silence a suggestion the reviewer explicitly declined to rule on.
- ``other`` — refused without saying why. An honest answer, and not one the
  engine may read meaning into.

Reading any of the others as refutation would be the failure Søren gated this
story on: **learning from noise, and degrading the rules it was meant to
improve.**

📌 **Nothing here maps anything.** A refutation only ever *removes* a proposal.
The engine proposes less; it does not decide more. That is the CA-08.3 shape —
"cannot exceed" had to be structural, and so does "cannot map".
"""

from __future__ import annotations

from dataclasses import dataclass

from sqlalchemy.orm import Session

from src.core.constants.dependency_mapping_enums import SlotMappingReasonCode
from src.core.model_defs.value_streams import MappingDecision
from src.core.services.asset_context_service import normalise_asset_reference

#: The reason codes that say something about the *rule* rather than about one
#: service's circumstances. Deliberately a set of one: widening it is a product
#: decision about what the engine is allowed to learn, not a tidy-up.
REFUTING_REASON_CODES: frozenset[str] = frozenset({SlotMappingReasonCode.WRONG_ASSET.value})

#: How a refusal is recorded in the append-only decision log.
_REJECT_ACTION = "reject_slot_mapping"


@dataclass(frozen=True)
class Refutation:
    """One (slot, artefact) pair a person has ruled out, and when."""

    slot_id: str
    asset_id: str
    #: Kept so a surface can say *why* the engine stopped offering this, rather
    #: than silently offering less. A reviewer who cannot see that a suggestion
    #: was withdrawn cannot tell learning from a bug.
    reason_code: str


def load_refutations(db: Session, *, organization_id: int) -> dict[tuple[str, str], Refutation]:
    """Every (slot_id, asset_id) this organisation has refused as a wrong match.

    Read from ``MappingDecision``, the existing append-only decision log, rather
    than from a new table: the evidence has been recorded there since Step 4.1C
    and nothing ever read it back. A second store would be a second truth about
    what a person decided.

    Scoped to one organisation and never wider. What one customer's estate
    refutes says nothing about another's, and a matcher that learned across
    tenants would leak the shape of one organisation into another's suggestions.
    """
    rows = (
        db.query(MappingDecision)
        .filter(
            MappingDecision.organization_id == organization_id,
            MappingDecision.action == _REJECT_ACTION,
        )
        .order_by(MappingDecision.created_at.asc())
        .all()
    )

    refuted: dict[tuple[str, str], Refutation] = {}
    for row in rows:
        before = row.before_state if isinstance(row.before_state, dict) else {}
        after = row.after_state if isinstance(row.after_state, dict) else {}
        reason_code = after.get("reason_code")
        if reason_code not in REFUTING_REASON_CODES:
            continue
        # The artefact is on the *before* state: rejecting clears `asset_id`
        # from the row, so the after state no longer knows what was refused.
        # ⚠️ #363 — in the one stored spelling. Suggestions carried ``"92"`` until
        # 2026-09-13 and ``"asset-92"`` since, so a refusal recorded before the
        # fix must still rule out the same artefact the engine now names.
        asset_id = normalise_asset_reference(before.get("asset_id"))
        slot_id = before.get("slot_id") or row.node_id
        if not asset_id or not slot_id:
            # A decision that cannot name what was refused cannot refute
            # anything. Older rows predate `slot_id` being captured, and
            # guessing which slot they meant would suppress a suggestion nobody
            # ruled out.
            continue
        key = (str(slot_id), asset_id)
        refuted[key] = Refutation(
            slot_id=str(slot_id), asset_id=asset_id, reason_code=str(reason_code)
        )
    return refuted

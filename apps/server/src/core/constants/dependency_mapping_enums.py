"""Step 4.1C — Business Service dependency mapping actions.

Controlled reason-code vocabulary for the two actions the existing
`SlotInstance` lifecycle (BSP-02/BSP-05) never actually wired up:
rejecting a mapping (`mapping_status="rejected"` is a documented valid
value, confirmed unwritten anywhere in the codebase) and superseding an
existing decision with a different asset. Not a DB-level enum — validated
at the route layer, matching `mapping_status`/`provenance`'s own existing
String-not-Enum precedent on this table.
"""

from enum import StrEnum


class SlotMappingReasonCode(StrEnum):
    SUGGESTION_ACCEPTED = "suggestion_accepted"
    MANUAL_ASSIGNMENT = "manual_assignment"
    WRONG_ASSET = "wrong_asset"
    ASSET_NOT_APPLICABLE = "asset_not_applicable"
    LOW_CONFIDENCE = "low_confidence"
    REPLACED_BY_NEWER_EVIDENCE = "replaced_by_newer_evidence"
    OTHER = "other"


#: The reasons a person can give for refusing a suggestion, in the order the
#: surface offers them, with the words they are offered in.
#:
#: CA-09A.5 (#317). Every rejection used to be written as ``WRONG_ASSET`` with
#: the string *"Dismissed in the slot mapping wizard."* — so whatever a reviewer
#: actually meant, the platform recorded one verdict, and **every rejection said
#: the same uninformative thing**. CA-09A.6 is supposed to learn from these; it
#: cannot learn anything from a field that never varies.
#:
#: The three are chosen for the distinction that decides what a rejection
#: *teaches*: was the matching rule wrong, or was the artefact never a candidate?
#: Søren's reframing of the epic turns on exactly that — *"the rejections are
#: there already but that is because the scanner filters devices out"* — and
#: only the first kind is evidence about the rules.
#:
#: Deliberately three, not a free-text box. Refusing has to cost about what
#: accepting costs, or the surface collects agreement rather than decisions.
SLOT_REJECTION_REASONS: tuple[tuple[str, str, str], ...] = (
    (
        SlotMappingReasonCode.WRONG_ASSET.value,
        "That is not the right thing",
        "The slot is right; this is not what fills it. The matching rule reached the wrong artefact.",
    ),
    (
        SlotMappingReasonCode.ASSET_NOT_APPLICABLE.value,
        "That does not belong here",
        "The artefact is real, but nothing in this service depends on it.",
    ),
    (
        SlotMappingReasonCode.LOW_CONFIDENCE.value,
        "Not enough to go on",
        "The evidence offered is too thin to decide either way. Not a no — a not yet.",
    ),
)

#: Looked up by code, for a surface that has one and needs the words.
SLOT_REJECTION_REASON_LABEL: dict[str, str] = {
    code: label for code, label, _ in SLOT_REJECTION_REASONS
}
SLOT_REJECTION_REASON_EXPLANATION: dict[str, str] = {
    code: explanation for code, _, explanation in SLOT_REJECTION_REASONS
}

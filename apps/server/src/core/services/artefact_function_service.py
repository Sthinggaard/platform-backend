"""CA-09A.3 (#315) — deriving what an artefact does from evidence already held.

Reads nothing new. The scan already recorded which services answered and whether
each was **probed** or read out of nmap's port-number table (#249); classification
already turned those into an ``ArtefactType``. This turns that into the sentence a
person deciding a dependency actually needs.

**Derived from ``ArtefactType``, never from a second table of service names.**
That mapping has exactly one definition in ``_SERVICE_EVIDENCE``, and a parallel
list here would drift the first time a service was added to one and not the other
— the failure the DRY rule exists to prevent.

**Disagreement is reported, not resolved.** A host answering DNS *and* serving a
web UI is genuinely ambiguous — a router with an admin page and a web server that
also runs DNS look identical from outside — so it returns ``UNDETERMINED`` rather
than picking by precedence. That is the same rule ``classify_host_record``
already applies, for the same reason.

📌 The result is evidence for a suggestion. Nothing here maps anything.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from typing import Any

from src.core.constants.artefact_function_enums import (
    ARTEFACT_FUNCTION_STATEMENT,
    FUNCTION_FROM_PORT_NUMBER_ALONE,
    ArtefactFunction,
)
from src.core.services.artefact_classification_service import (
    ArtefactType,
    is_administrative,
    service_artefact_type,
)

#: One function per ``ArtefactType`` that carries a purpose. Types absent here
#: say nothing about function — ``OBSERVED_HOST`` is "we saw something", which is
#: not a job — and fall through to ``UNDETERMINED``.
_FUNCTION_BY_TYPE: dict[ArtefactType, ArtefactFunction] = {
    ArtefactType.WEB_SERVICE: ArtefactFunction.SERVES_APPLICATION,
    ArtefactType.DATABASE: ArtefactFunction.STORES_DATA,
    ArtefactType.NETWORK_DEVICE: ArtefactFunction.CARRIES_NETWORK_TRAFFIC,
    ArtefactType.IDENTITY_SERVICE: ArtefactFunction.VERIFIES_IDENTITY,
    ArtefactType.REMOTE_ACCESS: ArtefactFunction.ALLOWS_ADMINISTRATION,
}


@dataclass(frozen=True)
class DeterminedFunction:
    """What this does, said once, with the evidence that supports it."""

    function: str
    #: The business-language sentence, already hedged when the evidence is weak.
    #: Composed here so every surface says the same thing.
    statement: str
    #: The service names the claim rests on, so a reader can disagree with the
    #: evidence rather than only with the conclusion.
    evidence: tuple[str, ...]
    #: False when nothing behind this was actually probed — the claim stands on
    #: port numbers alone.
    probed: bool

    @property
    def determined(self) -> bool:
        """One purpose, established. Several purposes is evidence worth showing
        a reader, but it is not a function anything may be mapped on."""
        return self.function not in {
            ArtefactFunction.UNDETERMINED.value,
            ArtefactFunction.SERVES_SEVERAL_PURPOSES.value,
        }


def determine_function(
    observed_evidence: Sequence[dict[str, Any]] | None,
    *,
    observed_names: Sequence[str] | None = None,
) -> DeterminedFunction:
    """What this artefact does, from what the scan heard.

    ``observed_evidence`` is ``intent["observedServiceEvidence"]`` — one entry
    per port, each carrying ``probed``. ``observed_names`` is the older
    ``intent["observedServices"]``, accepted as a fallback so an artefact
    recorded before #249 still gets a function; it simply cannot say whether
    anything was probed, and is treated as unprobed rather than assumed.
    """
    entries = _entries(observed_evidence, observed_names)
    if not entries:
        return _undetermined(())

    # Administrative paths sit on almost everything and say very little about
    # purpose — classifying a database by the fact that someone can log into it
    # is exactly the mistake `_ADMINISTRATIVE_TYPES` exists to prevent. So they
    # are set aside while deciding, and used only when nothing else was heard.
    purposeful = [e for e in entries if not is_administrative(e[1])]
    considered = purposeful or entries

    functions = {_FUNCTION_BY_TYPE[t] for _, t in considered if t in _FUNCTION_BY_TYPE}
    if not functions:
        return _undetermined(tuple(name for name, _ in considered))

    if len(functions) > 1:
        # Two purposes that disagree, which is a *finding* and not a tie to
        # break. Reported apart from "nothing recognised": on a real estate this
        # is the router answering DNS and serving its own admin page, and
        # telling the reader "nothing says what this is for" while holding
        # evidence of two things it does would be plainly untrue.
        names = tuple(name for name, _ in considered)
        return DeterminedFunction(
            function=ArtefactFunction.SERVES_SEVERAL_PURPOSES.value,
            statement=ARTEFACT_FUNCTION_STATEMENT[ArtefactFunction.SERVES_SEVERAL_PURPOSES.value],
            evidence=names,
            probed=any(_with_probed(observed_evidence, names)),
        )

    function = functions.pop()
    names = tuple(name for name, t in considered if _FUNCTION_BY_TYPE.get(t) is function)
    probed = any(_with_probed(observed_evidence, names))
    statement = ARTEFACT_FUNCTION_STATEMENT[function.value]
    if not probed:
        statement = f"{statement} {FUNCTION_FROM_PORT_NUMBER_ALONE}"
    return DeterminedFunction(
        function=function.value, statement=statement, evidence=names, probed=probed
    )


def _undetermined(evidence: tuple[str, ...]) -> DeterminedFunction:
    return DeterminedFunction(
        function=ArtefactFunction.UNDETERMINED.value,
        statement=ARTEFACT_FUNCTION_STATEMENT[ArtefactFunction.UNDETERMINED.value],
        evidence=evidence,
        probed=False,
    )


def _entries(
    observed_evidence: Sequence[dict[str, Any]] | None,
    observed_names: Sequence[str] | None,
) -> list[tuple[str, ArtefactType]]:
    """Recognised (name, type) pairs, from evidence first and names as fallback."""
    names: list[str] = []
    if observed_evidence:
        names = [
            str(item.get("name", "")).strip().lower()
            for item in observed_evidence
            if isinstance(item, dict) and str(item.get("name", "")).strip()
        ]
    elif observed_names:
        names = [n.strip().lower() for n in observed_names if isinstance(n, str) and n.strip()]
    seen: dict[str, ArtefactType] = {}
    for name in names:
        artefact_type = service_artefact_type(name)
        if artefact_type is not None and name not in seen:
            seen[name] = artefact_type
    return list(seen.items())


def _with_probed(
    observed_evidence: Sequence[dict[str, Any]] | None, names: tuple[str, ...]
) -> list[bool]:
    """Whether each entry backing the chosen function was actually probed."""
    if not observed_evidence:
        return []
    wanted = set(names)
    return [
        bool(item.get("probed"))
        for item in observed_evidence
        if isinstance(item, dict) and str(item.get("name", "")).strip().lower() in wanted
    ]

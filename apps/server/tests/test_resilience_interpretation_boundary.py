"""CA-05-ALIGN (#170) — the boundary between technical discovery and
resilience interpretation, asserted rather than described.

CA-05 Initial Discovery collects **technical evidence**. It does not decide
what any of that evidence *means* for the business: not criticality, not
Resilience Service designation, not Outcome Goals, not Impact Tolerance, not
Resilience Capability, and not decision status. Those are human judgements the
product's own first rule reserves for a person — *the system never decides*.

A prose document saying so goes stale the first time someone adds an import.
This does not: the boundary is enforced by reading what the discovery path
actually depends on. The modules holding interpretation are named below, and a
discovery module importing any of them fails this test — at which point either
the import is wrong or the boundary has genuinely moved and this list, the
architecture doc, and TASKS.md are updated together, deliberately.

📄 docs/architecture/server/ca-05-resilience-interpretation-boundary.md
"""

from __future__ import annotations

import ast
from pathlib import Path

_SERVER_ROOT = Path(__file__).resolve().parents[1]
_SRC = _SERVER_ROOT / "src"

#: Every module on the CA-05 path: requesting a run, planning and executing it,
#: receiving evidence, normalising it into artefacts, and reconciling those
#: artefacts against what is already known.
_DISCOVERY_PATH_GLOBS = (
    "core/services/discovery_*.py",
    "core/services/artefact_classification_service.py",
    "core/services/artefact_reconciliation_service.py",
    "core/services/artefact_identity*.py",
    "core/services/risk_intelligence_normalization_service.py",
    "api/routes/discovery_*.py",
)

#: The interpretation layer. Each of these holds a judgement about what
#: technical evidence *means*, and each is reached through a human decision
#: somewhere — not through a scan.
_INTERPRETATION_MODULES = {
    "src.core.model_defs.process_bia_assessment": "business impact and Impact Tolerance",
    "src.core.model_defs.risk_appetite_policy": "risk appetite",
    "src.core.model_defs.service_appetite_reassessment": "risk appetite",
    "src.core.model_defs.risk_evaluation": "risk evaluation and decision status",
    "src.core.model_defs.value_streams": "Business Service criticality and designation",
    "src.core.model_defs.baseline_risk_hypothesis": "baseline risk hypotheses",
    "src.core.model_defs.process_activation": "activation of a Business Process",
    "src.core.model_defs.business_process_recommendation": "recommendations to a person",
    "src.core.services.process_bia_assessment_service": "business impact and Impact Tolerance",
    "src.core.services.risk_evaluation_service": "risk evaluation and decision status",
    "src.core.services.risk_appetite_policy_service": "risk appetite",
}


def _discovery_path_modules() -> list[Path]:
    paths: list[Path] = []
    for glob in _DISCOVERY_PATH_GLOBS:
        paths.extend(sorted(_SRC.glob(glob)))
    return paths


def _imported_module_names(path: Path) -> set[str]:
    tree = ast.parse(path.read_text(), filename=str(path))
    names: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            names.update(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module and node.level == 0:
            names.add(node.module)
    return names


def test_the_discovery_path_is_actually_the_set_this_guard_thinks_it_is():
    """A guard that silently matches nothing passes forever."""
    modules = _discovery_path_modules()
    assert len(modules) >= 15, f"expected the CA-05 path to be found, got {len(modules)} modules"


def test_discovery_never_imports_the_interpretation_layer():
    """CA-05 collects technical evidence only (#170's first eight criteria,
    which are one property: it cannot interpret what it cannot reach)."""
    offences: list[str] = []
    for path in _discovery_path_modules():
        for imported in _imported_module_names(path):
            for forbidden, decides in _INTERPRETATION_MODULES.items():
                if imported == forbidden or imported.startswith(f"{forbidden}."):
                    offences.append(
                        f"{path.relative_to(_SERVER_ROOT)} imports {imported}, which holds {decides}"
                    )
    assert offences == [], (
        "CA-05 Initial Discovery must not reach the resilience interpretation layer:\n  "
        + "\n  ".join(offences)
    )


def test_evidence_stays_reconcilable_after_discovery():
    """#170's ninth criterion, and the one the others could quietly break: a
    boundary kept by producing *less* evidence would satisfy every 'does not'
    above and destroy the reason discovery exists. The normalised artefact must
    still carry the identity key later reconciliation and Business Service
    mapping match on."""
    from src.core.model_defs.assets_runtime import Asset

    assert hasattr(Asset, "canonical_identity_key")
    assert hasattr(Asset, "lifecycle_state")
    assert hasattr(Asset, "intent")


def test_criticality_written_by_discovery_is_a_column_default_not_a_determination():
    """The honest exception, recorded rather than glossed.

    `Asset.criticality` is NOT NULL with a default, so normalisation writes
    MEDIUM into it — not because discovery assessed anything, but because the
    column demands a value. That is the one place the boundary is upheld in
    intent and not in the data: a reader querying an artefact straight out of
    discovery is told MEDIUM and cannot tell that nobody decided it.

    Asserted here so the exception cannot be quietly widened into a real
    determination — if this value ever varies with the evidence, discovery has
    started interpreting and this test says so.
    """
    import inspect

    from src.core.services import risk_intelligence_normalization_service as normalization

    source = inspect.getsource(normalization)
    assert source.count("criticality=") == 1, "discovery sets criticality in exactly one place"
    assert "criticality=Criticality.MEDIUM," in source, (
        "discovery's criticality must stay a fixed column default; a value derived from the "
        "evidence would make CA-05 an interpreter (#170)"
    )

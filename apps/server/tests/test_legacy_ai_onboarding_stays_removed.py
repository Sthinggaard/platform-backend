"""#250 — the legacy AI-onboarding service layer stays removed.

The first removal (`docs/tasks/active/remove-legacy-ai-onboarding.md`) took the
routes, thirteen tables and the BFF proxies, and left the entire service layer
behind: fifteen modules under `src/onboarding/` plus a `registry/`, reachable only
through one dead bridge in `src/remediation/auto_remediation.py`. It survived for
weeks because nothing imported it, nothing tested it, and nothing failed.

That is exactly the condition under which it would come back — a partial removal
leaves no signal. This asserts the absence, so the next reintroduction is a red
test rather than a discovery months later.

Worth stating why absence is worth a test here rather than being left to review:
the deleted code included `credential_service.py` and AI-provider clients, in a
codebase whose CA-07 contract is that credentials never reach the platform, and
`auto_remediation.py`, which names a behaviour the product forbids outright — the
system never fixes anything automatically. Dead code touching either is a surface
nobody reviews.
"""

from __future__ import annotations

import pathlib

import pytest

_REPO_ROOT = pathlib.Path(__file__).resolve().parents[3]
_SERVER_SRC = _REPO_ROOT / "apps" / "server" / "src"

#: Paths that must not come back. Named individually rather than globbed so that
#: re-adding any one of them fails with the name in the assertion message.
_REMOVED_PATHS = (
    "onboarding",
    "remediation/auto_remediation.py",
)

#: Import paths nothing may reference again.
_FORBIDDEN_IMPORTS = ("src.onboarding", "auto_remediation")

#: Directories searched for a reintroduced reference. `graphify-out` is a
#: generated analysis cache that still holds the old symbol names; it is not code
#: and re-scanning would produce a permanent false positive.
_SEARCH_ROOTS = (
    _REPO_ROOT / "apps" / "server" / "src",
    _REPO_ROOT / "apps" / "bff",
)
_IGNORED_PARTS = frozenset({"graphify-out", "__pycache__", ".venv", "node_modules"})


@pytest.mark.parametrize("relative_path", _REMOVED_PATHS)
def test_removed_module_has_not_returned(relative_path: str) -> None:
    assert not (_SERVER_SRC / relative_path).exists(), (
        f"src/{relative_path} was removed under #250 as dead code from a partial "
        "removal. If it is genuinely needed again, restore it deliberately with a "
        "live consumer and delete this assertion — do not let it drift back."
    )


def test_the_config_flag_for_the_removed_module_is_gone() -> None:
    """`enable_auto_remediation` named a module nothing imported, and no code read
    the flag. A setting that configures nothing reads as a capability the platform
    has."""
    config = (_SERVER_SRC / "core" / "config.py").read_text(encoding="utf-8")
    assert "enable_auto_remediation" not in config


def test_nothing_imports_the_removed_package() -> None:
    offenders: list[str] = []
    for root in _SEARCH_ROOTS:
        for path in root.rglob("*.py"):
            if _IGNORED_PARTS & set(path.parts):
                continue
            text = path.read_text(encoding="utf-8", errors="ignore")
            for forbidden in _FORBIDDEN_IMPORTS:
                # `from x import y` / `import x` only — a bare mention in a comment
                # or an unrelated enum value ("auto_remediation" is a
                # RemediationType member) is not a dependency.
                if f"import {forbidden}" in text or f"from {forbidden}" in text:
                    offenders.append(f"{path.relative_to(_REPO_ROOT)} → {forbidden}")

    assert not offenders, "removed AI-onboarding code is referenced again:\n" + "\n".join(offenders)

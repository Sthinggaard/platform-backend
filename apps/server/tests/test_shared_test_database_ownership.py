"""One suite owns the shared test database (#287).

`conftest.py` builds the session-scoped `test_engine` against `TEST_POSTGRES_URL`,
creates the schema once, and drops it once at the end of the run. A test module
that builds its own engine against the same database is pointed at that schema,
and a `drop_all()` in its teardown removes it out from under every later suite.

The damage is quiet. A missing table surfaces as a fixture *error*, not a failure,
and a suite with a standing error count is one where nobody notices seven more:
tests can be written, pass in isolation, be committed in good faith, and never
actually run. Three modules had done exactly that, erroring 36 tests on ordering
alone.

So the rule is narrow and mechanical: outside `conftest`, a test module may only
build an engine it demonstrably owns — a SQLite URL written as a literal at the
call. Anything else is either the shared database or unreadable at a glance, and
both are the same problem for whoever comes after. Modules needing real Postgres
use the shared `db_session` fixture, which rolls its transaction back per test
rather than dropping anything.

This check fails when the pattern is *written*, not when a run happens to order
two suites badly — which is the only point at which it is cheap to fix.
"""

from __future__ import annotations

import ast
from pathlib import Path

TESTS_ROOT = Path(__file__).resolve().parent
CONFTEST = TESTS_ROOT / "conftest.py"


def _test_modules() -> list[Path]:
    return sorted(p for p in TESTS_ROOT.rglob("*.py") if p != CONFTEST)


def _is_private_sqlite_url(node: ast.expr | None) -> bool:
    return (
        isinstance(node, ast.Constant)
        and isinstance(node.value, str)
        and node.value.startswith("sqlite")
    )


def _unowned_engine_lines(tree: ast.AST) -> list[int]:
    """Lines building an engine on anything but a literal SQLite URL."""
    lines: list[int] = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        func = node.func
        name = func.attr if isinstance(func, ast.Attribute) else getattr(func, "id", None)
        if name != "create_engine":
            continue
        url = node.args[0] if node.args else None
        if not _is_private_sqlite_url(url):
            lines.append(node.lineno)
    return lines


def test_no_test_module_builds_an_engine_it_does_not_own():
    offenders: dict[str, list[int]] = {}
    for path in _test_modules():
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        lines = _unowned_engine_lines(tree)
        if lines:
            offenders[str(path.relative_to(TESTS_ROOT))] = lines

    assert not offenders, (
        "These test modules build a database engine that is not provably their own:\n"
        + "\n".join(
            f"  {module}:{', '.join(str(line) for line in lines)}"
            for module, lines in sorted(offenders.items())
        )
        + "\n\nUse the shared `db_session` fixture from conftest, or pass a literal "
        "sqlite:// URL. An engine on the shared database that drops its tables takes "
        "the schema out from under every later suite (#287)."
    )

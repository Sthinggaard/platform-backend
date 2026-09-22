"""The two halves of the `alembic_version` widening must agree.

`VERSION_TABLE_COLUMN_LENGTH` tells Alembic how wide to make the column on a new
database; `WIDEN_VERSION_COLUMN_SQL` widens one that already exists. They are
written separately because DDL cannot be parameterised and building the
statement with an f-string is what semgrep's `avoid-sqlalchemy-text` refuses.
Separate literals drift, so this pins them.

The length itself has to clear the longest revision id in the chain. It did not
on 2026-09-09: the column was Alembic's default VARCHAR(32) and 32 of the 131
revisions were longer, so each applied its DDL and then died recording itself.
"""

from __future__ import annotations

import importlib.util
import re
from pathlib import Path

import pytest

ALEMBIC_DIR = Path(__file__).resolve().parents[2] / "alembic"


def _load_env_constants() -> tuple[int, str]:
    """Read the two constants without importing `env.py`.

    Importing it runs Alembic's `context` at module scope, which only exists
    inside an `alembic` command.
    """
    source = (ALEMBIC_DIR / "env.py").read_text()
    length = re.search(r"^VERSION_TABLE_COLUMN_LENGTH = (\d+)$", source, re.M)
    sql = re.search(r'^WIDEN_VERSION_COLUMN_SQL = \(\n\s*"([^"]+)"', source, re.M)
    assert length and sql, "env.py no longer declares both constants"
    return int(length.group(1)), sql.group(1)


def test_widening_sql_matches_the_configured_column_length() -> None:
    length, sql = _load_env_constants()
    stated = re.search(r"VARCHAR\((\d+)\)", sql)
    assert stated, f"no VARCHAR(n) in the widening statement: {sql}"
    assert int(stated.group(1)) == length, (
        "A new database would get "
        f"VARCHAR({length}) while an existing one is widened to "
        f"VARCHAR({stated.group(1)})."
    )


def test_every_revision_id_fits_the_column() -> None:
    length, _ = _load_env_constants()
    too_long = {
        match.group(1): path.name
        for path in (ALEMBIC_DIR / "versions").glob("*.py")
        for match in [re.search(r'^revision(?::\s*str)? = "([^"]+)"', path.read_text(), re.M)]
        if match and len(match.group(1)) > length
    }
    assert not too_long, (
        f"revision ids longer than VARCHAR({length}), which Alembic cannot "
        f"record: {too_long}"
    )

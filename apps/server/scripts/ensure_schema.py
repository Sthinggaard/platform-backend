#!/usr/bin/env python
"""Bring a pre-squash database onto the chain, or refuse to.

`20260910_schema_baseline` replaced 131 migrations, so a database stamped at any
of them now records a revision Alembic cannot find, and `alembic upgrade head`
stops with "Can't locate revision". Such a database has to be stamped at the new
baseline once — and stamping asserts something: *this schema is what the models
describe*. That assertion is exactly the one that was never true in production,
where a missing `assets.level` returned a 500 to a signed-in user on 2026-08-17.

So this does not stamp on faith. It compares the live schema to
`Base.metadata` and stamps only when nothing material differs. When something
does, it prints what and exits non-zero — which, in both environments that run
it, aborts the deploy with the previous version still serving.

Four states, and only the third does anything:

  no schema at all           nothing to do; `alembic upgrade head` builds it
  revision already on chain  nothing to do
  schema, revision unknown   compare, then stamp or refuse
  schema, no alembic_version compare, then stamp or refuse

Run it before `alembic upgrade head`. It is idempotent.
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from alembic import command  # noqa: E402
from alembic.autogenerate import compare_metadata  # noqa: E402
from alembic.config import Config  # noqa: E402
from alembic.migration import MigrationContext  # noqa: E402
from alembic.script import ScriptDirectory  # noqa: E402
from sqlalchemy import inspect  # noqa: E402

import src.core.models  # noqa: F401,E402  — registers every mapped table
from src.core.database import Base, get_postgres_engine  # noqa: E402

SERVER_ROOT = Path(__file__).resolve().parents[1]
BASELINE = "20260910_schema_baseline"

# A schema that is missing a table or a column will fail at runtime, and did.
# Everything else `compare_metadata` reports — a server default, a type width,
# an index Alembic cannot see the same way twice — is worth printing and not
# worth aborting a deploy over.
BLOCKING = {
    "add_table",
    "remove_table",
    "add_column",
    "remove_column",
}


def _alembic_config() -> Config:
    config = Config(str(SERVER_ROOT / "alembic.ini"))
    config.set_main_option("script_location", str(SERVER_ROOT / "alembic"))
    return config


def _entries(diff) -> list[tuple]:
    """The individual changes in one `compare_metadata` entry.

    ⚠️ **An entry is a tuple *or a list of them*.** `compare_metadata` groups
    the several operations that make up one column alteration — a type change
    and a nullability change, say — into a list, and the surrounding code read
    every entry as a tuple. A grouped entry then reached `in BLOCKING` whole and
    raised `TypeError: unhashable type: 'list'`, aborting the script before it
    could compare anything (Søren, 2026-09-11).

    A grouped entry is never blocking on its own terms — it is always a
    `modify_*` on a column that exists in both — but it has to be unpacked to be
    read at all.
    """
    if isinstance(diff, list):
        return [entry for entry in diff if isinstance(entry, tuple)]
    return [diff] if isinstance(diff, tuple) else []


def _kinds(diff) -> set[str]:
    return {entry[0] for entry in _entries(diff) if entry}


def _describe(diff) -> str:
    entries = _entries(diff)
    if not entries:
        return str(diff)
    if len(entries) > 1:
        return "; ".join(_describe(entry) for entry in entries)

    single = entries[0]
    kind = single[0]
    if kind in {"add_table", "remove_table"}:
        return f"{kind}: {single[1].name}"
    if kind in {"add_column", "remove_column"}:
        return f"{kind}: {single[2]}.{single[3].name}"
    # A modify_* entry names its table and column in the middle of the tuple.
    if len(single) >= 4 and isinstance(single[2], str):
        return f"{kind}: {single[2]}.{single[3]}"
    return str(kind)


def main() -> int:
    engine = get_postgres_engine()
    config = _alembic_config()
    known = {revision.revision for revision in ScriptDirectory.from_config(config).walk_revisions()}

    with engine.connect() as connection:
        inspector = inspect(connection)
        tables = set(inspector.get_table_names())
        has_schema = bool(tables - {"alembic_version"})
        context = MigrationContext.configure(connection)
        current = context.get_current_revision()

        if not has_schema:
            print("ensure_schema: empty database; `alembic upgrade head` will build it")
            return 0

        if current in known:
            print(f"ensure_schema: already on the chain at {current}")
            return 0

        where = f"records {current}" if current else "has no alembic_version"
        print(f"ensure_schema: schema present but {where}; comparing it to the models")

        diffs = compare_metadata(context, Base.metadata)

    blocking = [d for d in diffs if _kinds(d) & BLOCKING]
    other = [d for d in diffs if not (_kinds(d) & BLOCKING)]

    for diff in other:
        print(f"  note: {_describe(diff)}")

    if blocking:
        print()
        print(f"ensure_schema: refusing to stamp {BASELINE}. This schema is not what the")
        print("models describe, and stamping would record that it is:")
        for diff in blocking:
            print(f"  {_describe(diff)}")
        print()
        print("Reconcile the database with the models first. Do not stamp past this.")
        return 1

    # `purge=True` because the row already there names a revision Alembic cannot
    # resolve — one of the 131 now in `versions_archive/`. Without it, `stamp`
    # tries to read the current revision first and dies on the same
    # "Can't locate revision" this script exists to clear.
    command.stamp(config, BASELINE, purge=True)
    print(f"ensure_schema: schema matches the models; stamped {BASELINE}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

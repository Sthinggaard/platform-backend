#!/usr/bin/env python
"""Assert that `alembic upgrade head` alone reproduces the models.

This is the check whose absence let the migration chain rot from December 2024
to September 2026 without anyone noticing. `0001_baseline` was a no-op, nothing
after it created a core table, and every environment worked around it by
building the schema with `create_all` and stamping head — so the migrations were
never the thing that made a database, and nothing ever said so.

Run against an empty database. It upgrades to head and then asks Alembic what
still differs between the result and `Base.metadata`. Anything at all is a
failure: a migration that does not reproduce the models is a migration that will
surprise someone in production.
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from alembic import command  # noqa: E402
from alembic.autogenerate import compare_metadata  # noqa: E402
from alembic.config import Config  # noqa: E402
from alembic.migration import MigrationContext  # noqa: E402
from sqlalchemy import inspect  # noqa: E402

import src.core.models  # noqa: F401,E402
from src.core.database import Base, get_postgres_engine  # noqa: E402

SERVER_ROOT = Path(__file__).resolve().parents[1]


def _describe(diff) -> str:
    kind = diff[0] if isinstance(diff, tuple) else str(diff)
    if kind in {"add_table", "remove_table"}:
        return f"{kind}: {diff[1].name}"
    if kind in {"add_column", "remove_column"}:
        return f"{kind}: {diff[2]}.{diff[3].name}"
    if kind in {"add_index", "remove_index"}:
        return f"{kind}: {diff[1].name}"
    if kind in {"add_fk", "remove_fk"}:
        return f"{kind}: {diff[1].table.name}"
    return str(kind)


def main() -> int:
    engine = get_postgres_engine()

    with engine.connect() as connection:
        existing = set(inspect(connection).get_table_names()) - {"alembic_version"}
    if existing:
        print(f"refusing to run: this database already has {len(existing)} tables.")
        print("This check is only meaningful against an empty database.")
        return 2

    config = Config(str(SERVER_ROOT / "alembic.ini"))
    config.set_main_option("script_location", str(SERVER_ROOT / "alembic"))
    command.upgrade(config, "head")

    with engine.connect() as connection:
        built = set(inspect(connection).get_table_names()) - {"alembic_version"}
        diffs = compare_metadata(MigrationContext.configure(connection), Base.metadata)

    print(f"`alembic upgrade head` built {len(built)} tables from an empty database.")

    if diffs:
        print()
        print(f"{len(diffs)} difference(s) remain between that schema and the models:")
        for diff in diffs:
            print(f"  {_describe(diff)}")
        print()
        print("The chain no longer reproduces the models. Add a migration for the")
        print("difference, or correct the one that introduced it.")
        return 1

    print("It matches the models exactly.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

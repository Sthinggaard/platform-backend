import os
import sys
from logging.config import fileConfig

from sqlalchemy import engine_from_config, pool, text

from alembic import context

# Ensure src is on path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

import src.core.models  # noqa: F401, E402 - register all mapped tables for autogenerate
from src.core.config import settings  # noqa: E402
from src.core.database import Base  # noqa: E402

# this is the Alembic Config object, which provides
# access to the values within the .ini file in use.
config = context.config

# Interpret the config file for Python logging.
fileConfig(config.config_file_name)

target_metadata = Base.metadata

# Alembic's default `alembic_version.version_num` is VARCHAR(32). This project
# names revisions after what they do — `20260820_user_timezone_and_location` is
# 35 characters, and 32 of the 131 revisions are over the limit, the longest at
# 60. Alembic writes the id *after* running the revision, so such a migration
# applies its DDL and then dies on
#
#   value too long for type character varying(32)
#
# taking the whole upgrade down with it. Staging hit this on 2026-09-09, the
# first environment to run `alembic upgrade head` as a must-succeed step; the
# guard held and the previous version kept serving.
#
# 255 leaves room; the longest id today is 60.
VERSION_TABLE_COLUMN_LENGTH = 255

# A fixed literal, not an f-string. `sqlalchemy.text()` built by string
# formatting is the exact shape SQL injection takes, and semgrep's
# `avoid-sqlalchemy-text` refuses it on sight — rightly, even here where the only
# value is the constant above and no user input can reach it. DDL cannot be
# parameterised, so the number is written out and
# `tests/unit/test_alembic_env.py` pins the two together.
WIDEN_VERSION_COLUMN_SQL = (
    "ALTER TABLE alembic_version ALTER COLUMN version_num TYPE VARCHAR(255)"
)


def _widen_version_column(connection) -> None:
    """Widen an `alembic_version` table that predates the setting below.

    `version_table_column_length` only governs the CREATE. A database whose
    table already exists keeps its VARCHAR(32) forever, so every environment
    created before this fix needs the column altered once — here, rather than as
    a migration, because a migration cannot run before the ones already failing.
    """
    current = connection.execute(
        text(
            "SELECT character_maximum_length FROM information_schema.columns "
            "WHERE table_name = 'alembic_version' AND column_name = 'version_num'"
        )
    ).scalar()

    if current is not None and current < VERSION_TABLE_COLUMN_LENGTH:
        connection.execute(text(WIDEN_VERSION_COLUMN_SQL))

    # Unconditionally, including after a read that changed nothing: the SELECT
    # above opens a transaction of its own, and this connection must not be
    # handed back to the pool still holding one.
    connection.commit()

# Override URL from settings if provided
if settings and settings.database:
    config.set_main_option("sqlalchemy.url", settings.database.postgres_url)


def run_migrations_offline():
    url = config.get_main_option("sqlalchemy.url")
    context.configure(
        url=url,
        target_metadata=target_metadata,
        literal_binds=True,
        compare_type=True,
        version_table_column_length=VERSION_TABLE_COLUMN_LENGTH,
    )

    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online():
    connectable = engine_from_config(
        config.get_section(config.config_ini_section),
        prefix="sqlalchemy.",
        poolclass=pool.NullPool,
    )

    # Its own connection, deliberately. Executing on the migration connection
    # before `context.configure` leaves it inside an implicit SQLAlchemy 2.0
    # transaction; alembic then finds a transaction it did not open, does not
    # commit it, and the close rolls everything back. `alembic stamp head`
    # printed "Running stamp_revision -> 20260906_tenant_index" and wrote
    # nothing — the failure looked like success, which is the worst shape a
    # failure can take. Verified on staging, 2026-09-09.
    with connectable.connect() as preparation:
        _widen_version_column(preparation)

    with connectable.connect() as connection:
        context.configure(
            connection=connection,
            target_metadata=target_metadata,
            compare_type=True,
            version_table_column_length=VERSION_TABLE_COLUMN_LENGTH,
        )

        with context.begin_transaction():
            context.run_migrations()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()

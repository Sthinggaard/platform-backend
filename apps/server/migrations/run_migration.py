#!/usr/bin/env python3
"""
Database migration runner for Risklence Tower.

Usage:
    python migrations/run_migration.py apply 001
    python migrations/run_migration.py rollback 001
    python migrations/run_migration.py list
"""

import os
import sys
from pathlib import Path

# Add project root to path
project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root))

from sqlalchemy import create_engine, text
from src.core.config import settings
from src.core.logging_config import get_logger

logger = get_logger(__name__)


class MigrationRunner:
    """Run SQL migrations against the database."""

    def __init__(self):
        """Initialize migration runner with database connection."""
        self.migrations_dir = Path(__file__).parent
        self.engine = create_engine(settings.database.postgres_url)

    def list_migrations(self):
        """List available migrations."""
        print("\nAvailable migrations:")
        print("-" * 50)

        migration_files = sorted(self.migrations_dir.glob("*_add_*.sql"))

        for migration_file in migration_files:
            # Get migration number
            migration_num = migration_file.stem.split("_")[0]
            migration_name = "_".join(migration_file.stem.split("_")[1:])

            # Check if rollback exists
            rollback_file = self.migrations_dir / f"{migration_num}_{migration_name}_rollback.sql"
            has_rollback = rollback_file.exists()

            print(
                f"  {migration_num}: {migration_name.replace('_', ' ').title()}"
                f" (rollback: {'✓' if has_rollback else '✗'})"
            )

        print("-" * 50)

    def apply_migration(self, migration_num: str):
        """
        Apply a migration.

        Args:
            migration_num: Migration number (e.g., "001")
        """
        # Find migration file
        migration_files = list(self.migrations_dir.glob(f"{migration_num}_*.sql"))

        if not migration_files:
            print(f"❌ Error: Migration {migration_num} not found")
            sys.exit(1)

        # Filter out rollback files
        migration_files = [f for f in migration_files if "rollback" not in f.name]

        if not migration_files:
            print(f"❌ Error: Migration {migration_num} not found")
            sys.exit(1)

        migration_file = migration_files[0]

        print(f"\n🚀 Applying migration: {migration_file.name}")
        print("-" * 50)

        try:
            # Read SQL file
            with open(migration_file, "r") as f:
                sql_content = f.read()

            # Execute migration
            with self.engine.begin() as conn:
                # Split by statement and execute
                statements = self._split_sql_statements(sql_content)

                for i, statement in enumerate(statements, 1):
                    if statement.strip():
                        logger.info(
                            "executing_migration_statement",
                            migration=migration_file.name,
                            statement_num=i,
                        )
                        # False positive (A1 security remediation review):
                        # `statement` comes from a version-controlled .sql
                        # migration file in this repo, never runtime/user
                        # input — this is the standard way to apply
                        # developer-authored migration SQL.
                        conn.execute(text(statement))  # nosemgrep: python.sqlalchemy.security.audit.avoid-sqlalchemy-text.avoid-sqlalchemy-text

            print(f"✅ Migration {migration_num} applied successfully!")
            logger.info("migration_applied", migration=migration_file.name)

        except Exception as e:
            print(f"❌ Error applying migration: {str(e)}")
            logger.error("migration_failed", migration=migration_file.name, error=str(e))
            sys.exit(1)

    def rollback_migration(self, migration_num: str):
        """
        Rollback a migration.

        Args:
            migration_num: Migration number (e.g., "001")
        """
        # Find rollback file
        rollback_files = list(self.migrations_dir.glob(f"{migration_num}_*_rollback.sql"))

        if not rollback_files:
            print(f"❌ Error: Rollback for migration {migration_num} not found")
            sys.exit(1)

        rollback_file = rollback_files[0]

        print(f"\n⚠️  WARNING: Rolling back migration: {rollback_file.name}")
        print("This will DELETE data. Are you sure? (yes/no): ", end="")

        confirmation = input().strip().lower()

        if confirmation != "yes":
            print("Rollback cancelled")
            return

        print("-" * 50)

        try:
            # Read SQL file
            with open(rollback_file, "r") as f:
                sql_content = f.read()

            # Execute rollback
            with self.engine.begin() as conn:
                statements = self._split_sql_statements(sql_content)

                for i, statement in enumerate(statements, 1):
                    if statement.strip():
                        logger.info(
                            "executing_rollback_statement",
                            migration=rollback_file.name,
                            statement_num=i,
                        )
                        # False positive (A1 security remediation review):
                        # `statement` comes from a version-controlled .sql
                        # migration file in this repo, never runtime/user
                        # input — this is the standard way to apply
                        # developer-authored migration SQL.
                        conn.execute(text(statement))  # nosemgrep: python.sqlalchemy.security.audit.avoid-sqlalchemy-text.avoid-sqlalchemy-text

            print(f"✅ Migration {migration_num} rolled back successfully!")
            logger.info("migration_rolled_back", migration=rollback_file.name)

        except Exception as e:
            print(f"❌ Error rolling back migration: {str(e)}")
            logger.error("rollback_failed", migration=rollback_file.name, error=str(e))
            sys.exit(1)

    def _split_sql_statements(self, sql_content: str) -> list:
        """
        Split SQL content into individual statements.

        Handles DO blocks, CREATE blocks, and regular statements. The previous
        approach double-counted the opening `DO $$` line and could prematurely
        close the block, leaving the body out and causing syntax errors. Here
        we explicitly track entry/exit of DO blocks.
        """
        statements = []
        current_statement = []
        in_do_block = False

        lines = sql_content.split("\n")

        for line in lines:
            stripped = line.strip()

            # Skip comments
            if stripped.startswith("--"):
                continue

            # Track dollar-quoted blocks: enter on DO $$ or AS $$ (e.g., functions)
            if ("DO $$" in line or "DO $func$" in line or "AS $$" in line) and not in_do_block:
                in_do_block = True

            current_statement.append(line)

            if in_do_block:
                # End of DO block when the terminating dollar quote is reached
                if stripped.endswith("$$;") or stripped == "$$" or stripped.startswith("$$ LANGUAGE"):
                    statements.append("\n".join(current_statement))
                    current_statement = []
                    in_do_block = False
            else:
                # End of regular statement
                if stripped.endswith(";"):
                    statements.append("\n".join(current_statement))
                    current_statement = []

        # Add any remaining statement
        if current_statement:
            statements.append("\n".join(current_statement))

        return [s for s in statements if s.strip()]


def main():
    """Main entry point."""
    if len(sys.argv) < 2:
        print("Usage:")
        print("  python migrations/run_migration.py apply <migration_num>")
        print("  python migrations/run_migration.py rollback <migration_num>")
        print("  python migrations/run_migration.py list")
        sys.exit(1)

    command = sys.argv[1].lower()
    runner = MigrationRunner()

    if command == "list":
        runner.list_migrations()

    elif command == "apply":
        if len(sys.argv) < 3:
            print("Error: Migration number required")
            print("Usage: python migrations/run_migration.py apply <migration_num>")
            sys.exit(1)

        migration_num = sys.argv[2]
        runner.apply_migration(migration_num)

    elif command == "rollback":
        if len(sys.argv) < 3:
            print("Error: Migration number required")
            print("Usage: python migrations/run_migration.py rollback <migration_num>")
            sys.exit(1)

        migration_num = sys.argv[2]
        runner.rollback_migration(migration_num)

    else:
        print(f"Error: Unknown command '{command}'")
        print("Valid commands: apply, rollback, list")
        sys.exit(1)


if __name__ == "__main__":
    main()

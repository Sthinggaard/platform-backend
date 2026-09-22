#!/usr/bin/env python3
"""
Database initialization script.
Creates all tables and indexes for PostgreSQL and MongoDB.
"""

import sys
from pathlib import Path

# Add src to Python path
project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root))

from src.core.database import init_databases
from src.core.logging_config import get_logger

logger = get_logger(__name__)


def main() -> None:
    """Initialize databases."""
    logger.info("starting_database_initialization")

    try:
        init_databases()
        logger.info(
            "database_initialization_complete",
            message="All databases and tables have been initialized successfully",
        )
        print("✓ Database initialization completed successfully!")

    except Exception as e:
        logger.error("database_initialization_failed", error=str(e), exc_info=True)
        print(f"✗ Database initialization failed: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()

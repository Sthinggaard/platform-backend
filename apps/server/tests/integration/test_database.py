"""
Integration tests for database connections.
These tests require PostgreSQL and MongoDB to be running.
"""

import pytest
from sqlalchemy import text
from sqlalchemy.exc import OperationalError

from src.core.database import (
    MongoDBConnection,
    create_postgres_engine,
    get_db_context,
    get_mongodb,
    init_databases,
)
from src.core.exceptions import DatabaseConnectionError
from src.core.models import ComplianceFramework


@pytest.mark.integration
class TestPostgreSQLConnection:
    """Test PostgreSQL connection and operations."""

    def test_create_engine(self) -> None:
        """Test creating PostgreSQL engine."""
        engine = create_postgres_engine()
        assert engine is not None

        # Test connection
        with engine.connect() as conn:
            result = conn.execute(text("SELECT 1"))
            assert result.scalar() == 1

    def test_connection_pool(self) -> None:
        """Test connection pooling."""
        engine = create_postgres_engine()

        # Pool settings
        assert engine.pool.size() == 10  # type: ignore
        assert engine.pool._max_overflow == 20  # type: ignore

    def test_session_context_manager(self) -> None:
        """Test database session context manager."""
        with get_db_context() as db:
            # Create a test framework
            framework = ComplianceFramework(
                name="Test Framework",
                version="1.0",
                description="Test framework for integration test",
            )
            db.add(framework)
            db.commit()

            assert framework.id is not None

            # Clean up
            db.delete(framework)
            db.commit()

    def test_session_rollback_on_error(self) -> None:
        """Test automatic rollback on error."""
        try:
            with get_db_context() as db:
                framework = ComplianceFramework(
                    name="Test Rollback",
                    version="1.0",
                )
                db.add(framework)
                # Cause an error before commit
                raise ValueError("Test error")
        except ValueError:
            pass

        # Verify rollback occurred
        with get_db_context() as db:
            result = db.query(ComplianceFramework).filter_by(name="Test Rollback").first()
            assert result is None


@pytest.mark.integration
class TestMongoDBConnection:
    """Test MongoDB connection and operations."""

    def test_mongodb_singleton(self) -> None:
        """Test MongoDB singleton pattern."""
        mongo1 = MongoDBConnection()
        mongo2 = MongoDBConnection()
        assert mongo1 is mongo2

    def test_get_database(self) -> None:
        """Test getting MongoDB database."""
        db = get_mongodb()
        assert db is not None
        assert db.name == "risklence_scans"

    def test_get_collection(self) -> None:
        """Test getting MongoDB collection."""
        mongodb = MongoDBConnection()
        collection = mongodb.get_collection("scan_results_raw")
        assert collection is not None
        assert collection.name == "scan_results_raw"

    def test_mongodb_operations(self) -> None:
        """Test basic MongoDB operations."""
        db = get_mongodb()
        collection = db["test_collection"]

        # Insert
        doc = {"test": "data", "value": 123}
        result = collection.insert_one(doc)
        assert result.inserted_id is not None

        # Find
        found = collection.find_one({"test": "data"})
        assert found is not None
        assert found["value"] == 123

        # Clean up
        collection.delete_one({"_id": result.inserted_id})

    def test_mongodb_indexes(self) -> None:
        """Test MongoDB indexes are created."""
        db = get_mongodb()

        # Check scan_results_raw indexes
        indexes = list(db.scan_results_raw.list_indexes())
        index_names = [idx["name"] for idx in indexes]

        assert "scan_run_id_1" in index_names
        assert "asset_id_1" in index_names
        assert "cloud_provider_1" in index_names


@pytest.mark.integration
class TestDatabaseInitialization:
    """Test database initialization."""

    def test_init_databases(self) -> None:
        """Test database initialization."""
        # This should create tables and indexes
        init_databases()

        # Verify PostgreSQL tables exist
        engine = create_postgres_engine()
        with engine.connect() as conn:
            result = conn.execute(
                text(
                    """
                    SELECT table_name
                    FROM information_schema.tables
                    WHERE table_schema = 'public'
                    """
                )
            )
            tables = [row[0] for row in result]

            assert "compliance_frameworks" in tables
            assert "compliance_controls" in tables
            assert "policy_rules" in tables
            assert "cloud_assets" in tables
            assert "scan_runs" in tables
            assert "findings" in tables
            assert "jira_tickets" in tables

        # Verify MongoDB indexes exist
        db = get_mongodb()
        indexes = list(db.scan_results_raw.list_indexes())
        assert len(indexes) > 1  # Should have more than just _id index

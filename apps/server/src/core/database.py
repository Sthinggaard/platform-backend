"""
Database connection management for PostgreSQL and MongoDB.
"""

from contextlib import contextmanager
from contextvars import ContextVar
from typing import Any, Generator

from pymongo import MongoClient
from pymongo.database import Database as MongoDatabase
from sqlalchemy import create_engine, event, text
from sqlalchemy.engine import Engine
from sqlalchemy.orm import Session, declarative_base, sessionmaker
from sqlalchemy.pool import Pool

from src.core.config import settings
from src.core.exceptions import AuthorizationError, DatabaseConnectionError
from src.core.logging_config import get_logger

logger = get_logger(__name__)

# Guard: public onboarding routes must not touch tenant DB.
_pretenant_request: ContextVar[bool] = ContextVar("pretenant_request", default=False)


def set_pretenant_request(enabled: bool):
    return _pretenant_request.set(enabled)


def reset_pretenant_request(token) -> None:
    _pretenant_request.reset(token)


def _assert_tenant_db_allowed() -> None:
    if _pretenant_request.get():
        raise AuthorizationError("Tenant DB access not allowed for public onboarding")
# SQLAlchemy declarative base for ORM models
Base = declarative_base()


# PostgreSQL Configuration
def create_postgres_engine() -> Engine:
    """
    Create PostgreSQL engine with connection pooling.

    Returns:
        SQLAlchemy engine instance

    Raises:
        DatabaseConnectionError: If connection fails
    """
    try:
        engine = create_engine(
            settings.database.postgres_url,
            pool_pre_ping=True,  # Verify connections before using
            pool_size=10,  # Connection pool size
            max_overflow=20,  # Allow extra connections beyond pool_size
            pool_recycle=3600,  # Recycle connections after 1 hour
            echo=settings.debug,  # Log SQL queries in debug mode
        )

        # Test connection
        with engine.connect() as conn:
            conn.execute(text("SELECT 1"))

        logger.info(
            "postgresql_connected",
            host="database_url" if settings.database.database_url else settings.database.postgres_host,
            database=settings.database.postgres_db,
        )

        return engine

    except Exception as e:
        logger.error(
            "postgresql_connection_failed",
            error=str(e),
            host="database_url" if settings.database.database_url else settings.database.postgres_host,
        )
        raise DatabaseConnectionError(
            f"Failed to connect to PostgreSQL: {str(e)}",
            details={"host": "database_url" if settings.database.database_url else settings.database.postgres_host},
        ) from e


# Add connection pool event listeners for debugging
@event.listens_for(Pool, "connect")
def receive_connect(dbapi_conn: Any, connection_record: Any) -> None:
    """Log when a new database connection is created."""
    logger.debug("postgresql_pool_connect", connection_id=id(dbapi_conn))


@event.listens_for(Pool, "checkout")
def receive_checkout(dbapi_conn: Any, connection_record: Any, connection_proxy: Any) -> None:
    """Log when a connection is retrieved from the pool."""
    logger.debug("postgresql_pool_checkout", connection_id=id(dbapi_conn))


_postgres_engine: Engine | None = None
_SessionLocal: sessionmaker | None = None


def get_postgres_engine() -> Engine:
    """Get (or create) the shared PostgreSQL engine lazily."""
    global _postgres_engine
    if _postgres_engine is None:
        _postgres_engine = create_postgres_engine()
    return _postgres_engine


def get_session_factory() -> sessionmaker:
    """Get (or create) the session factory bound to the shared engine."""
    global _SessionLocal
    if _SessionLocal is None:
        _SessionLocal = sessionmaker(
            autocommit=False,
            autoflush=False,
            bind=get_postgres_engine(),
        )
    return _SessionLocal


def get_db() -> Generator[Session, None, None]:
    """
    Dependency for getting PostgreSQL database sessions.
    Use this in FastAPI route dependencies.

    Yields:
        SQLAlchemy session

    Example:
        @app.get("/items")
        def get_items(db: Session = Depends(get_db)):
            return db.query(Item).all()
    """
    _assert_tenant_db_allowed()
    db = get_session_factory()()
    try:
        yield db
    except Exception:
        db.rollback()
        raise
    finally:
        db.rollback()
        db.close()


@contextmanager
def get_db_context() -> Generator[Session, None, None]:
    """
    Context manager for getting PostgreSQL database sessions.
    Use this in non-FastAPI contexts.

    Yields:
        SQLAlchemy session

    Example:
        with get_db_context() as db:
            items = db.query(Item).all()
    """
    _assert_tenant_db_allowed()
    db = get_session_factory()()
    try:
        yield db
    except Exception:
        db.rollback()
        raise
    finally:
        db.close()


# MongoDB Configuration
class MongoDBConnection:
    """MongoDB connection manager singleton."""

    _instance: "MongoDBConnection | None" = None
    _client: MongoClient | None = None
    _database: MongoDatabase | None = None

    def __new__(cls) -> "MongoDBConnection":
        """Ensure singleton instance."""
        if cls._instance is None:
            cls._instance = super().__new__(cls)
        return cls._instance

    def __init__(self) -> None:
        """Initialize MongoDB connection if not already initialized."""
        if self._client is None:
            self.connect()

    def connect(self) -> None:
        """
        Connect to MongoDB.

        Raises:
            DatabaseConnectionError: If connection fails
        """
        try:
            self._client = MongoClient(
                settings.database.mongodb_uri,
                serverSelectionTimeoutMS=5000,  # 5 second timeout
                maxPoolSize=50,
                minPoolSize=10,
            )

            # Test connection
            self._client.server_info()

            # Get database
            self._database = self._client[settings.database.mongodb_db]

            logger.info(
                "mongodb_connected",
                uri=settings.database.mongodb_uri,
                database=settings.database.mongodb_db,
            )

        except Exception as e:
            logger.error(
                "mongodb_connection_failed",
                error=str(e),
                uri=settings.database.mongodb_uri,
            )
            raise DatabaseConnectionError(
                f"Failed to connect to MongoDB: {str(e)}",
                details={"uri": settings.database.mongodb_uri},
            ) from e

    def get_database(self) -> MongoDatabase:
        """
        Get MongoDB database instance.

        Returns:
            MongoDB database instance

        Raises:
            DatabaseConnectionError: If not connected
        """
        if self._database is None:
            raise DatabaseConnectionError("MongoDB not connected")
        return self._database

    def get_collection(self, collection_name: str):  # type: ignore
        """
        Get MongoDB collection.

        Args:
            collection_name: Name of the collection

        Returns:
            MongoDB collection instance
        """
        return self.get_database()[collection_name]

    def close(self) -> None:
        """Close MongoDB connection."""
        if self._client:
            self._client.close()
            self._client = None
            self._database = None
            logger.info("mongodb_disconnected")


_mongodb_connection: MongoDBConnection | None = None


def get_mongodb_connection() -> MongoDBConnection:
    """Get (or create) the shared MongoDB connection."""
    global _mongodb_connection
    if _mongodb_connection is None:
        _mongodb_connection = MongoDBConnection()
    return _mongodb_connection


def get_mongodb() -> MongoDatabase:
    """
    Get MongoDB database instance.
    Use this as a dependency in FastAPI routes.

    Returns:
        MongoDB database instance
    """
    return get_mongodb_connection().get_database()


# Initialization and cleanup functions
def init_databases() -> None:
    """
    Initialize both PostgreSQL and MongoDB connections.
    Creates tables if they don't exist.
    """
    logger.info("initializing_databases")

    # Create PostgreSQL tables
    try:
        Base.metadata.create_all(bind=get_postgres_engine())
        logger.info("postgresql_tables_created")
    except Exception as e:
        logger.error("postgresql_table_creation_failed", error=str(e))
        raise

    # Ensure MongoDB collections have proper indexes
    try:
        db = get_mongodb_connection().get_database()

        # Create indexes for scan_results_raw collection
        db.scan_results_raw.create_index([("scan_run_id", 1)])
        db.scan_results_raw.create_index([("asset_id", 1)])
        db.scan_results_raw.create_index([("cloud_provider", 1)])
        db.scan_results_raw.create_index([("scan_timestamp", -1)])

        # Create indexes for vulnerability_scan_results collection
        db.vulnerability_scan_results.create_index([("scan_run_id", 1)])
        db.vulnerability_scan_results.create_index([("asset_id", 1)])

        # Create indexes for threat_intelligence collection
        db.threat_intelligence.create_index([("indicator_type", 1)])
        db.threat_intelligence.create_index([("value", 1)])
        db.threat_intelligence.create_index([("last_seen", -1)])

        # TTL index for auto-deletion of old scan results (30 days)
        db.scan_results_raw.create_index([("ttl_expire_at", 1)], expireAfterSeconds=0)

        logger.info("mongodb_indexes_created")
    except Exception as e:
        logger.error("mongodb_index_creation_failed", error=str(e))
        raise

    logger.info("databases_initialized")


def close_databases() -> None:
    """Close all database connections."""
    logger.info("closing_databases")

    # Close PostgreSQL
    if _postgres_engine is not None:
        _postgres_engine.dispose()
        logger.info("postgresql_closed")

    # Close MongoDB
    if _mongodb_connection is not None:
        _mongodb_connection.close()

    logger.info("databases_closed")

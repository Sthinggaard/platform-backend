"""
Unit tests for configuration management.
"""

import pytest
from pydantic import ValidationError

from src.core.config import (
    AWSSettings,
    AzureSettings,
    DatabaseSettings,
    Environment,
    JiraSettings,
    ScanSettings,
    Settings,
)


class TestDatabaseSettings:
    """Test database configuration."""

    @pytest.mark.unreconciled
    def test_default_values(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Test default database settings."""
        monkeypatch.delenv("POSTGRES_HOST", raising=False)
        monkeypatch.delenv("POSTGRES_PORT", raising=False)
        monkeypatch.delenv("POSTGRES_USER", raising=False)
        monkeypatch.delenv("POSTGRES_PASSWORD", raising=False)
        monkeypatch.delenv("POSTGRES_DB", raising=False)
        monkeypatch.delenv("MONGODB_URI", raising=False)
        monkeypatch.delenv("MONGODB_DB", raising=False)
        db_settings = DatabaseSettings()
        assert db_settings.postgres_host == "localhost"
        # 5433, not Postgres's own 5432: `config/local-ports.env` maps the
        # compose Postgres to 5433 so it cannot collide with an installed one,
        # and `35536e138` moved the model default to match. This assertion was
        # left on the old value and has failed on every developer machine since
        # (#210, filed as "schema drift" — it is neither drift nor a schema).
        assert db_settings.postgres_port == 5433
        assert db_settings.postgres_user == "risklence"
        assert db_settings.postgres_db == "risklence_db"
        assert db_settings.mongodb_uri == "mongodb://localhost:27017"
        assert db_settings.mongodb_db == "risklence_scans"

    def test_postgres_url_generation(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Test PostgreSQL URL generation."""
        # `postgres_url` returns `database_url` verbatim when it is set, so a
        # `DATABASE_URL` in the environment makes the host/port/db arguments
        # below irrelevant and the assertion reads back that URL instead. The
        # security gate exports one for its Postgres service container, which
        # is why this passed on every developer machine and failed in CI.
        monkeypatch.delenv("DATABASE_URL", raising=False)
        db_settings = DatabaseSettings(
            postgres_host="testhost",
            postgres_port=5433,
            postgres_user="testuser",
            postgres_password="testpass",  # type: ignore
            postgres_db="testdb",
        )
        expected_url = "postgresql://testuser:testpass@testhost:5433/testdb"
        assert db_settings.postgres_url == expected_url

    def test_custom_values(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Test custom database settings from environment."""
        monkeypatch.setenv("POSTGRES_HOST", "customhost")
        monkeypatch.setenv("POSTGRES_PORT", "5434")
        db_settings = DatabaseSettings()
        assert db_settings.postgres_host == "customhost"
        assert db_settings.postgres_port == 5434


class TestAzureSettings:
    """Test Azure configuration."""

    @pytest.mark.unreconciled
    def test_default_values(self) -> None:
        """Test default Azure settings."""
        azure_settings = AzureSettings()
        assert azure_settings.azure_tenant_id is None
        assert azure_settings.azure_client_id is None
        assert azure_settings.azure_client_secret is None
        assert azure_settings.azure_subscription_ids == []

    def test_subscription_ids_from_json_string(self) -> None:
        """Test parsing subscription IDs from JSON string."""
        azure_settings = AzureSettings(
            azure_subscription_ids='["sub-1", "sub-2", "sub-3"]'  # type: ignore
        )
        assert azure_settings.azure_subscription_ids == ["sub-1", "sub-2", "sub-3"]

    def test_subscription_ids_from_list(self) -> None:
        """Test subscription IDs from list."""
        azure_settings = AzureSettings(azure_subscription_ids=["sub-1", "sub-2"])
        assert azure_settings.azure_subscription_ids == ["sub-1", "sub-2"]

    def test_invalid_json_subscription_ids(self) -> None:
        """Test handling of invalid JSON for subscription IDs."""
        azure_settings = AzureSettings(azure_subscription_ids="not-json")  # type: ignore
        assert azure_settings.azure_subscription_ids == ["not-json"]


class TestAWSSettings:
    """Test AWS configuration."""

    @pytest.mark.unreconciled
    def test_default_values(self) -> None:
        """Test default AWS settings."""
        aws_settings = AWSSettings()
        assert aws_settings.aws_access_key_id is None
        assert aws_settings.aws_secret_access_key is None
        assert aws_settings.aws_region == "us-east-1"
        assert aws_settings.aws_account_ids == []

    def test_account_ids_from_json_string(self) -> None:
        """Test parsing account IDs from JSON string."""
        aws_settings = AWSSettings(
            aws_account_ids='["123456789012", "210987654321"]'  # type: ignore
        )
        assert aws_settings.aws_account_ids == ["123456789012", "210987654321"]


class TestJiraSettings:
    """Test Jira configuration."""

    @pytest.mark.unreconciled
    def test_default_values(self) -> None:
        """Test default Jira settings."""
        jira_settings = JiraSettings()
        assert jira_settings.jira_url is None
        assert jira_settings.jira_username is None
        assert jira_settings.jira_api_token is None
        assert jira_settings.jira_project_key == "SEC"

    def test_custom_project_key(self) -> None:
        """Test custom Jira project key."""
        jira_settings = JiraSettings(jira_project_key="SECURITY")
        assert jira_settings.jira_project_key == "SECURITY"


class TestScanSettings:
    """Test scanning configuration."""

    @pytest.mark.unreconciled
    def test_default_values(self) -> None:
        """Test default scan settings."""
        scan_settings = ScanSettings()
        assert scan_settings.scan_parallelism == 5
        assert scan_settings.scan_timeout_seconds == 300
        assert scan_settings.scan_schedule_cron == "0 2 * * *"

    def test_validation_parallelism(self) -> None:
        """Test parallelism validation."""
        # Valid values
        scan_settings = ScanSettings(scan_parallelism=10)
        assert scan_settings.scan_parallelism == 10

        # Edge cases
        ScanSettings(scan_parallelism=1)  # Min value
        ScanSettings(scan_parallelism=50)  # Max value

    def test_validation_timeout(self) -> None:
        """Test timeout validation."""
        scan_settings = ScanSettings(scan_timeout_seconds=600)
        assert scan_settings.scan_timeout_seconds == 600


class TestSettings:
    """Test main application settings."""

    @pytest.mark.unreconciled
    def test_default_values(self) -> None:
        """Test default application settings."""
        settings = Settings()
        assert settings.environment == Environment.DEVELOPMENT
        assert settings.app_name == "Risklence Tower"
        assert settings.app_version == "0.1.0"
        assert settings.debug is False
        assert settings.log_level == "INFO"
        assert settings.api_host == "0.0.0.0"
        assert settings.api_port == 8000

    def test_environment_properties(self) -> None:
        """Test environment helper properties."""
        dev_settings = Settings(environment=Environment.DEVELOPMENT)
        assert dev_settings.is_development is True
        assert dev_settings.is_production is False

        prod_settings = Settings(environment=Environment.PRODUCTION)
        assert prod_settings.is_development is False
        assert prod_settings.is_production is True

    def test_nested_settings(self) -> None:
        """Test nested settings objects."""
        settings = Settings()
        assert isinstance(settings.database, DatabaseSettings)
        assert isinstance(settings.azure, AzureSettings)
        assert isinstance(settings.aws, AWSSettings)
        assert isinstance(settings.jira, JiraSettings)
        assert isinstance(settings.scan, ScanSettings)

    def test_allowed_origins_from_json(self) -> None:
        """Test parsing allowed origins from JSON."""
        settings = Settings(
            allowed_origins='["http://localhost:3000", "https://app.example.com"]'  # type: ignore
        )
        assert settings.allowed_origins == [
            "http://localhost:3000",
            "https://app.example.com",
        ]

    def test_port_validation(self) -> None:
        """Test API port validation."""
        # Valid port
        settings = Settings(api_port=3000)
        assert settings.api_port == 3000

        # Edge cases
        Settings(api_port=1)  # Min
        Settings(api_port=65535)  # Max

    def test_workers_validation(self) -> None:
        """Test API workers validation."""
        settings = Settings(api_workers=8)
        assert settings.api_workers == 8

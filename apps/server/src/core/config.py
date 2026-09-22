"""
Configuration management using Pydantic Settings.
Loads configuration from environment variables and .env file.
"""

from enum import Enum
from typing import Dict, List, Optional

from pydantic import Field, SecretStr, field_validator
from pydantic_settings import BaseSettings, NoDecode, SettingsConfigDict
from typing_extensions import Annotated


class Environment(str, Enum):
    """Application environment types."""

    DEVELOPMENT = "development"
    STAGING = "staging"
    PRODUCTION = "production"


class DatabaseSettings(BaseSettings):
    """PostgreSQL and MongoDB database configuration."""

    database_url: Optional[str] = Field(
        default=None,
        validation_alias="DATABASE_URL",
        description="Full PostgreSQL connection URL (overrides host/user/pass/db when set)",
    )
    postgres_host: str = Field(default="localhost", description="PostgreSQL host")
    # Local Compose exposes PostgreSQL on 5433; containers explicitly use
    # their internal 5432 port through environment configuration.
    postgres_port: int = Field(default=5433, description="PostgreSQL port")
    postgres_user: str = Field(default="risklence", description="PostgreSQL username")
    postgres_password: SecretStr = Field(
        default=SecretStr("risklence_dev_password"), description="PostgreSQL password"
    )
    postgres_db: str = Field(default="risklence_db", description="PostgreSQL database name")

    mongodb_uri: str = Field(
        default="mongodb://localhost:27017", description="MongoDB connection URI"
    )
    mongodb_db: str = Field(default="risklence_scans", description="MongoDB database name")

    @property
    def postgres_url(self) -> str:
        """Generate PostgreSQL connection URL."""
        if self.database_url:
            return self.database_url
        return (
            f"postgresql://{self.postgres_user}:"
            f"{self.postgres_password.get_secret_value()}@"
            f"{self.postgres_host}:{self.postgres_port}/{self.postgres_db}"
        )

    model_config = SettingsConfigDict(env_prefix="", case_sensitive=False)


class AzureSettings(BaseSettings):
    """Azure cloud provider configuration."""

    azure_tenant_id: Optional[str] = Field(default=None, description="Azure tenant ID")
    azure_client_id: Optional[str] = Field(default=None, description="Azure client ID")
    azure_client_secret: Optional[SecretStr] = Field(
        default=None, description="Azure client secret"
    )
    azure_subscription_ids: List[str] = Field(
        default_factory=list, description="List of Azure subscription IDs to scan"
    )

    @field_validator("azure_subscription_ids", mode="before")
    @classmethod
    def parse_subscription_ids(cls, v: str | List[str]) -> List[str]:
        """Parse subscription IDs from JSON string or list."""
        if isinstance(v, str):
            import json

            try:
                return json.loads(v)
            except json.JSONDecodeError:
                return [v] if v else []
        return v if v else []

    model_config = SettingsConfigDict(env_prefix="", case_sensitive=False)


class AWSSettings(BaseSettings):
    """AWS cloud provider configuration."""

    aws_access_key_id: Optional[str] = Field(default=None, description="AWS access key ID")
    aws_secret_access_key: Optional[SecretStr] = Field(
        default=None, description="AWS secret access key"
    )
    aws_region: str = Field(default="us-east-1", description="Default AWS region")
    aws_account_ids: List[str] = Field(
        default_factory=list, description="List of AWS account IDs to scan"
    )

    @field_validator("aws_account_ids", mode="before")
    @classmethod
    def parse_account_ids(cls, v: str | List[str]) -> List[str]:
        """Parse account IDs from JSON string or list."""
        if isinstance(v, str):
            import json

            try:
                return json.loads(v)
            except json.JSONDecodeError:
                return [v] if v else []
        return v if v else []

    model_config = SettingsConfigDict(env_prefix="", case_sensitive=False)


class JiraSettings(BaseSettings):
    """Jira integration configuration."""

    jira_url: Optional[str] = Field(default=None, description="Jira instance URL")
    jira_username: Optional[str] = Field(default=None, description="Jira username")
    jira_api_token: Optional[SecretStr] = Field(default=None, description="Jira API token")
    jira_project_key: str = Field(default="SEC", description="Jira project key")

    model_config = SettingsConfigDict(env_prefix="", case_sensitive=False)


class ServiceNowSettings(BaseSettings):
    """ServiceNow integration configuration for decision-layer change requests."""

    servicenow_url: Optional[str] = Field(default=None, description="ServiceNow instance URL")
    servicenow_username: Optional[str] = Field(default=None, description="ServiceNow username")
    servicenow_password: Optional[SecretStr] = Field(
        default=None, description="ServiceNow password or API token"
    )
    servicenow_table: str = Field(
        default="change_request",
        description="ServiceNow table name for change requests",
    )

    model_config = SettingsConfigDict(env_prefix="", case_sensitive=False)


class Auth0Settings(BaseSettings):
    """Auth0 authentication configuration."""

    auth0_domain: Optional[str] = Field(
        default=None, description="Auth0 domain (e.g., your-tenant.auth0.com)"
    )
    auth0_client_id: Optional[str] = Field(default=None, description="Auth0 application client ID")
    auth0_client_secret: Optional[SecretStr] = Field(
        default=None, description="Auth0 application client secret"
    )
    auth0_audience: Optional[str] = Field(default=None, description="Auth0 API audience identifier")
    auth0_api_audience: Optional[str] = Field(
        default=None, description="Auth0 API audience for API authentication"
    )
    auth0_jwks_url: Optional[str] = Field(
        default=None,
        description="Override JWKS URL (defaults to https://<domain>/.well-known/jwks.json)",
    )
    auth0_testing_secret: Optional[str] = Field(
        default=None, description="HS256 secret for local/testing token verification"
    )
    auth0_callback_url: str = Field(
        default="http://localhost:3000/api/auth/callback",
        description="OAuth2 callback URL",
    )
    auth0_custom_claims_namespace: Optional[str] = Field(
        default="https://risklence.com/",
        description="Namespace for custom claims in JWT tokens",
    )
    rs256_enabled: bool = Field(
        default=False,
        description="Enable RS256/JWKS validation for Auth0-issued tokens",
        validation_alias="AUTH0_RS256_ENABLED",
    )

    # JWT validation
    jwt_algorithm: str = Field(default="RS256", description="JWT signing algorithm")
    jwt_issuer: Optional[str] = Field(default=None, description="JWT issuer URL")

    model_config = SettingsConfigDict(env_prefix="", case_sensitive=False)


class AISettings(BaseSettings):
    """AI provider configuration for onboarding agent.

    Supports multiple providers: claude, openai, gemini, azure_openai.
    """

    # Provider selection
    ai_provider: str = Field(
        default="claude",
        description="AI provider to use (claude, openai, gemini, azure_openai)",
        validation_alias="AI_PROVIDER",
    )

    # Anthropic Claude
    anthropic_api_key: Optional[SecretStr] = Field(default=None, description="Anthropic API key")
    anthropic_model: str = Field(
        default="claude-3-5-sonnet-20241022",
        description="Claude model name",
    )

    # OpenAI
    openai_api_key: Optional[SecretStr] = Field(
        default=None,
        description="OpenAI API key",
        validation_alias="OPENAI_API_KEY",
    )
    openai_model: str = Field(
        default="gpt-4-turbo-preview",
        description="OpenAI model name",
        validation_alias="OPENAI_MODEL",
    )
    openai_organization: Optional[str] = Field(
        default=None,
        description="OpenAI organization ID",
        validation_alias="OPENAI_ORGANIZATION",
    )

    # Google Gemini
    gemini_api_key: Optional[SecretStr] = Field(default=None, description="Google Gemini API key")
    gemini_model: str = Field(
        default="gemini-1.5-pro",
        description="Gemini model name",
    )

    # Azure OpenAI
    azure_openai_api_key: Optional[SecretStr] = Field(
        default=None, description="Azure OpenAI API key"
    )
    azure_openai_endpoint: Optional[str] = Field(
        default=None, description="Azure OpenAI endpoint URL"
    )
    azure_openai_deployment: str = Field(
        default="gpt-4",
        description="Azure OpenAI deployment name",
    )
    azure_openai_api_version: str = Field(
        default="2024-02-15-preview",
        description="Azure OpenAI API version",
    )

    # Common settings (apply to all providers)
    ai_max_tokens: int = Field(
        default=1024, ge=1, le=4096, description="Max tokens for AI responses"
    )
    ai_temperature: float = Field(
        default=0.7, ge=0.0, le=1.0, description="Temperature for AI responses (creativity)"
    )
    ai_timeout_seconds: int = Field(
        default=30, ge=5, le=120, description="Timeout for AI API calls"
    )
    ai_hard_timeout_ms: int = Field(
        default=4000, ge=500, le=20000, description="Hard timeout in milliseconds"
    )
    ai_target_p95_ms: int = Field(
        default=2000, ge=500, le=10000, description="Target p95 latency budget in ms"
    )
    ai_max_retries: int = Field(default=3, ge=0, le=10, description="Max retries for AI calls")
    ai_initial_backoff_ms: int = Field(
        default=200, ge=0, le=5000, description="Initial backoff milliseconds"
    )
    ai_backoff_factor: float = Field(
        default=2.0, ge=1.0, le=5.0, description="Exponential backoff factor"
    )
    ai_circuit_failure_threshold: int = Field(
        default=3, ge=1, le=20, description="Failures before circuit opens"
    )
    ai_circuit_reset_seconds: int = Field(
        default=30, ge=1, le=600, description="Seconds to keep circuit open"
    )

    model_config = SettingsConfigDict(env_prefix="", case_sensitive=False)


class EncryptionSettings(BaseSettings):
    """Encryption configuration for cloud credentials."""

    encryption_key: SecretStr = Field(
        default=SecretStr("change-me-in-production-use-32-bytes"),
        description="Base encryption key for credential encryption (32 bytes)",
    )
    key_rotation_enabled: bool = Field(default=False, description="Enable automatic key rotation")

    model_config = SettingsConfigDict(env_prefix="", case_sensitive=False)


class ScanSettings(BaseSettings):
    """Scanning engine configuration."""

    scan_parallelism: int = Field(
        default=5, ge=1, le=50, description="Number of parallel scan tasks"
    )
    scan_timeout_seconds: int = Field(
        default=300, ge=60, le=3600, description="Scan timeout in seconds"
    )
    scan_schedule_cron: str = Field(
        default="0 2 * * *", description="Cron schedule for scans (default: 2 AM daily)"
    )

    model_config = SettingsConfigDict(env_prefix="", case_sensitive=False)


class MonitoringSettings(BaseSettings):
    """Background monitoring **simulator** controls (BUG-DISC-18).

    ``AssetMonitoringEngine`` does not monitor anything: it fabricates latency,
    throughput and event counts and writes them into ``asset_evidence_signals``
    — the same table that holds the real evidence justifying every artefact and
    decision. It is a development aid for populating a local demo.

    It used to default to **on**, and nothing anywhere set the variable that
    turns it off: not docker-compose, not the deploy workflow (which sets
    ``DO_MONITORING_ENABLED``, a name the application never reads). So it ran
    wherever it was deployed, at ~25,000 fabricated rows per hour, and control
    coverage was being evaluated from invented numbers.

    It now defaults to off, and ``api.main`` refuses to start it outside
    development whatever this says — a configuration mistake must not be able to
    put fabricated evidence in front of an auditor.
    """

    enabled: bool = Field(
        default=False,
        validation_alias="MONITORING_ENABLED",
        description="Enable the background monitoring simulator (development only)",
    )
    poll_interval_seconds: int = Field(default=10, ge=1, le=300)
    initial_probe_delay_seconds: float = Field(default=2.0, ge=0.1, le=30.0)
    simulation_seed: int = Field(default=1337)

    model_config = SettingsConfigDict(env_prefix="", case_sensitive=False)


class AuditSettings(BaseSettings):
    """Audit/evidence configuration."""

    share_link_ttl_hours: int = Field(default=24, ge=1, le=168)

    model_config = SettingsConfigDict(env_prefix="", case_sensitive=False)


class EmailSettings(BaseSettings):
    """Email delivery configuration."""

    smtp_host: Optional[str] = Field(default=None, validation_alias="EMAIL_SMTP_HOST")
    smtp_port: int = Field(default=587, validation_alias="EMAIL_SMTP_PORT")
    smtp_user: Optional[str] = Field(default=None, validation_alias="EMAIL_SMTP_USER")
    smtp_password: Optional[SecretStr] = Field(default=None, validation_alias="EMAIL_SMTP_PASSWORD")
    smtp_use_tls: bool = Field(default=True, validation_alias="EMAIL_SMTP_USE_TLS")
    model_config = SettingsConfigDict(env_prefix="", case_sensitive=False)


class SmsSettings(BaseSettings):
    """SMS delivery configuration."""

    provider: str = Field(default="dev", validation_alias="SMS_PROVIDER")
    twilio_account_sid: Optional[str] = Field(default=None, validation_alias="TWILIO_ACCOUNT_SID")
    twilio_auth_token: Optional[SecretStr] = Field(
        default=None, validation_alias="TWILIO_AUTH_TOKEN"
    )
    twilio_from: Optional[str] = Field(default=None, validation_alias="TWILIO_FROM")

    model_config = SettingsConfigDict(env_prefix="", case_sensitive=False)


class AuthSettings(BaseSettings):
    """Local auth and SSO configuration."""

    jwt_secret: Optional[SecretStr] = Field(default=None, validation_alias="AUTH_JWT_SECRET")
    jwt_issuer: Optional[str] = Field(default=None, validation_alias="AUTH_JWT_ISSUER")
    jwt_audience: Optional[str] = Field(default=None, validation_alias="AUTH_JWT_AUDIENCE")
    access_token_ttl_minutes: int = Field(default=15, validation_alias="AUTH_ACCESS_TOKEN_TTL")
    refresh_token_ttl_days: int = Field(default=30, validation_alias="AUTH_REFRESH_TOKEN_TTL")
    refresh_token_secret: Optional[SecretStr] = Field(
        default=None, validation_alias="AUTH_REFRESH_TOKEN_SECRET"
    )
    # A refresh token replayed within this many seconds of its own rotation is
    # treated as a benign client-side race (two tabs, several requests firing
    # near access-token expiry) rather than theft: the caller is transparently
    # handed the live descendant it was already rotated into. Outside this
    # window, reuse still revokes every session for the user, unchanged.
    refresh_token_reuse_grace_seconds: int = Field(
        default=10, validation_alias="AUTH_REFRESH_REUSE_GRACE_SECONDS"
    )
    refresh_cookie_name: str = Field(
        default="rl_refresh", validation_alias="AUTH_REFRESH_COOKIE_NAME"
    )
    refresh_cookie_domain: Optional[str] = Field(
        default=None, validation_alias="AUTH_REFRESH_COOKIE_DOMAIN"
    )
    refresh_cookie_secure: bool = Field(default=True, validation_alias="AUTH_REFRESH_COOKIE_SECURE")
    refresh_cookie_samesite: str = Field(
        default="strict", validation_alias="AUTH_REFRESH_COOKIE_SAMESITE"
    )
    password_reset_ttl_minutes: int = Field(default=30, validation_alias="AUTH_PASSWORD_RESET_TTL")
    invite_token_ttl_hours: int = Field(default=72, validation_alias="AUTH_INVITE_TOKEN_TTL")
    app_base_url: Optional[str] = Field(default=None, validation_alias="APP_BASE_URL")
    frontend_base_url: Optional[str] = Field(default=None, validation_alias="FRONTEND_BASE_URL")
    sso_callback_url: Optional[str] = Field(default=None, validation_alias="SSO_CALLBACK_URL")

    sso_state_cookie_name: str = Field(
        default="rl_sso_state", validation_alias="SSO_STATE_COOKIE_NAME"
    )
    sso_state_ttl_minutes: int = Field(default=10, validation_alias="SSO_STATE_TTL")
    sso_auto_link: bool = Field(default=True, validation_alias="SSO_AUTO_LINK")
    sso_auto_provision: bool = Field(default=False, validation_alias="SSO_AUTO_PROVISION")

    sso_google_client_id: Optional[str] = Field(
        default=None, validation_alias="SSO_GOOGLE_CLIENT_ID"
    )
    sso_google_client_secret: Optional[SecretStr] = Field(
        default=None, validation_alias="SSO_GOOGLE_CLIENT_SECRET"
    )
    sso_google_redirect_uri: Optional[str] = Field(
        default=None, validation_alias="SSO_GOOGLE_REDIRECT_URI"
    )

    sso_ms_client_id: Optional[str] = Field(default=None, validation_alias="SSO_MS_CLIENT_ID")
    sso_ms_client_secret: Optional[SecretStr] = Field(
        default=None, validation_alias="SSO_MS_CLIENT_SECRET"
    )
    sso_ms_redirect_uri: Optional[str] = Field(default=None, validation_alias="SSO_MS_REDIRECT_URI")
    sso_ms_tenant_mode: str = Field(default="common", validation_alias="SSO_MS_TENANT_MODE")

    email_from: Optional[str] = Field(default=None, validation_alias="EMAIL_FROM")
    mfa_otp_ttl_minutes: int = Field(default=5, validation_alias="AUTH_MFA_OTP_TTL")
    mfa_otp_max_attempts: int = Field(default=5, validation_alias="AUTH_MFA_OTP_MAX_ATTEMPTS")
    mfa_resend_cooldown_seconds: int = Field(
        default=60, validation_alias="AUTH_MFA_RESEND_COOLDOWN"
    )
    mfa_resend_rate_limit: int = Field(default=5, validation_alias="AUTH_MFA_RESEND_RATE_LIMIT")
    mfa_verify_rate_limit: int = Field(default=10, validation_alias="AUTH_MFA_VERIFY_RATE_LIMIT")

    model_config = SettingsConfigDict(env_prefix="", case_sensitive=False)


class TemplateGovernanceSettings(BaseSettings):
    """Template governance automation configuration."""

    scheduled_trigger_secret: Optional[SecretStr] = Field(
        default=None,
        validation_alias="TEMPLATE_GOVERNANCE_SCHEDULED_TRIGGER_SECRET",
    )

    model_config = SettingsConfigDict(env_prefix="", case_sensitive=False)


class LearningLoopSettings(BaseSettings):
    """Learning-loop automation configuration."""

    scheduled_trigger_secret: Optional[SecretStr] = Field(
        default=None,
        validation_alias="LEARNING_LOOP_SCHEDULED_TRIGGER_SECRET",
    )

    model_config = SettingsConfigDict(env_prefix="", case_sensitive=False)


class Settings(BaseSettings):
    """Main application settings."""

    # Application
    environment: Environment = Field(
        default=Environment.DEVELOPMENT, description="Application environment"
    )
    app_name: str = Field(default="Risklence Tower", description="Application name")
    app_version: str = Field(default="0.1.0", description="Application version")
    debug: bool = Field(default=False, description="Debug mode")
    log_level: str = Field(
        default="INFO", description="Logging level (DEBUG, INFO, WARNING, ERROR)"
    )

    # API Settings
    api_host: str = Field(default="0.0.0.0", description="API host")
    api_port: int = Field(default=8000, ge=1, le=65535, description="API port")
    api_workers: int = Field(default=4, ge=1, le=32, description="Number of API workers")
    # The API's own public origin — distinct from frontend_base_url/app_base_url
    # above (those are the tenant web app). Needed only to construct a
    # terminal command an operator runs on their own machine (the scanner
    # agent talks to this origin directly, never through the tenant Worker/
    # BFF chain a browser uses). Matches apps/scanner/README.md's own
    # documented example.
    scanner_api_base_url: str = Field(
        default="https://api.risklence.com", validation_alias="SCANNER_API_BASE_URL"
    )
    # A Collector running as a Docker container cannot reach the host's own
    # 127.0.0.1 — that address is the container. The tenant app already draws
    # this distinction (`dockerApiBaseUrl` in RiskScannerActivationGuide); the
    # server did not, so a dockerised Collector was handed an address it could
    # never connect to. Empty means "same as scanner_api_base_url", which is
    # correct in production where both are the public origin.
    scanner_docker_api_base_url: str = Field(
        default="", validation_alias="SCANNER_DOCKER_API_BASE_URL"
    )
    allowed_origins: Annotated[List[str], NoDecode] = Field(
        default_factory=lambda: [
            "http://localhost:3000",
            "http://localhost:8000",
            "http://127.0.0.1:3000",
            "http://127.0.0.1:8000",
        ],
        description="CORS allowed origins",
    )
    rate_limit_enabled: bool = Field(
        default=True,
        validation_alias="RATE_LIMIT_ENABLED",
        description="Enable global API rate limiting",
    )
    rate_limit_requests_per_minute: int = Field(
        default=120,
        validation_alias="RATE_LIMIT_REQUESTS_PER_MINUTE",
        description="Global rate limit per IP per minute",
    )
    pretenant_cvr_stub_enabled: bool = Field(
        default=False,
        validation_alias="PRETENANT_CVR_STUB_ENABLED",
        description="Use deterministic CVR enrichment data for local development",
    )

    @field_validator("allowed_origins", mode="before")
    @classmethod
    def parse_allowed_origins(cls, v: str | List[str]) -> List[str]:
        """Parse allowed origins from JSON string or list."""
        if isinstance(v, str):
            import json

            try:
                return json.loads(v)
            except json.JSONDecodeError:
                return [v] if v else []
        return v if v else []

    # Security
    secret_key: SecretStr = Field(
        default=SecretStr("change-me-in-production"),
        description="Secret key for JWT and encryption",
    )

    # Redis
    redis_url: str = Field(default="redis://localhost:6379/0", description="Redis connection URL")

    # Sub-configurations
    database: DatabaseSettings = Field(default_factory=DatabaseSettings)
    azure: AzureSettings = Field(default_factory=AzureSettings)
    aws: AWSSettings = Field(default_factory=AWSSettings)
    jira: JiraSettings = Field(default_factory=JiraSettings)
    servicenow: ServiceNowSettings = Field(default_factory=ServiceNowSettings)
    auth0: Auth0Settings = Field(default_factory=Auth0Settings)
    ai: AISettings = Field(default_factory=AISettings)
    encryption: EncryptionSettings = Field(default_factory=EncryptionSettings)
    scan: ScanSettings = Field(default_factory=ScanSettings)
    monitoring: MonitoringSettings = Field(default_factory=MonitoringSettings)
    audit: AuditSettings = Field(default_factory=AuditSettings)
    email: EmailSettings = Field(default_factory=EmailSettings)
    sms: SmsSettings = Field(default_factory=SmsSettings)
    auth: AuthSettings = Field(default_factory=AuthSettings)
    template_governance: TemplateGovernanceSettings = Field(
        default_factory=TemplateGovernanceSettings
    )
    learning_loop: LearningLoopSettings = Field(default_factory=LearningLoopSettings)
    feature_flags: Dict[str, bool] = Field(
        default_factory=dict, description="Feature flag toggles keyed by name"
    )

    model_config = SettingsConfigDict(
        env_file=(".env", ".env.local"),
        env_file_encoding="utf-8",
        env_nested_delimiter="__",
        case_sensitive=False,
        extra="ignore",
    )

    @property
    def is_development(self) -> bool:
        """Check if running in development mode."""
        return self.environment == Environment.DEVELOPMENT

    @property
    def is_production(self) -> bool:
        """Check if running in production mode."""
        return self.environment == Environment.PRODUCTION


def _validate_production_secrets(s: "Settings") -> None:
    """Refuse to start in production with default or missing secrets."""
    if s.environment != Environment.PRODUCTION:
        return

    # Exact-string blocklist alone is fragile (it must be kept in sync with
    # every placeholder ever committed anywhere in the repo, and silently
    # misses the next one). "risklence-dev-only-jwt-secret-do-not-use-in-prod"
    # is the literal value committed in apps/server/.env for local dev — it
    # was NOT previously in this list, so this validator would not, in fact,
    # have blocked it in production despite that file's comment claiming it
    # would (found in a security audit, 2026-07-16). Keep both the known
    # placeholders AND a minimum-entropy floor so a future short/committed
    # value is still caught even if no one remembers to add it here.
    _INSECURE_DEFAULTS = {
        "change-me-in-production",
        "change-me-in-production-use-32-bytes",
        "risklence-dev-only-jwt-secret-do-not-use-in-prod",
        "dev-testing-secret-for-jwt-generation",
        "",
    }
    _MIN_SECRET_LENGTH = 32

    def _check_secret(value: str, name: str, help_text: str) -> None:
        if value in _INSECURE_DEFAULTS:
            raise RuntimeError(
                f"{name} must be set to a strong random value in production. {help_text}"
            )
        if len(value) < _MIN_SECRET_LENGTH:
            raise RuntimeError(
                f"{name} is only {len(value)} characters in production; expected at least "
                f"{_MIN_SECRET_LENGTH}. {help_text}"
            )

    jwt_secret = s.auth.jwt_secret.get_secret_value() if s.auth.jwt_secret else ""
    _check_secret(jwt_secret, "AUTH_JWT_SECRET", "Run: python scripts/generate_jwt_secret.py")

    secret_key = s.secret_key.get_secret_value() if s.secret_key else ""
    _check_secret(secret_key, "SECRET_KEY", "Run: python scripts/generate_jwt_secret.py")

    enc_key = s.encryption.encryption_key.get_secret_value() if s.encryption.encryption_key else ""
    _check_secret(enc_key, "ENCRYPTION_KEY", "Cloud credentials are encrypted with this key.")


# Singleton instance
settings = Settings()
_validate_production_secrets(settings)

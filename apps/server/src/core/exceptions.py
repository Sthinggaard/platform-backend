"""
Custom exceptions for Risklence Tower application.
"""


class RisklenceException(Exception):
    """Base exception for all Risklence Tower errors."""

    def __init__(self, message: str, details: dict | None = None) -> None:
        self.message = message
        self.details = details or {}
        super().__init__(self.message)


# Configuration Exceptions
class ConfigurationError(RisklenceException):
    """Raised when there's a configuration error."""

    pass


# Database Exceptions
class DatabaseError(RisklenceException):
    """Base exception for database-related errors."""

    pass


class DatabaseConnectionError(DatabaseError):
    """Raised when database connection fails."""

    pass


class DatabaseQueryError(DatabaseError):
    """Raised when a database query fails."""

    pass


# Cloud Connector Exceptions
class ConnectorError(RisklenceException):
    """Base exception for cloud connector errors."""

    pass


class AuthenticationError(ConnectorError):
    """Raised when cloud provider authentication fails."""

    pass


class RefreshTokenReuseDetected(AuthenticationError):
    """A refresh token was replayed outside any benign-race grace window.

    Carries plain identifiers rather than a UserSession row so this module
    stays free of model imports — the route uses these to revoke every
    session for the user and write the audit event.
    """

    def __init__(self, *, user_id: int, organization_id: int, session_id: int):
        self.user_id = user_id
        self.organization_id = organization_id
        self.session_id = session_id
        super().__init__("Refresh token reuse detected")


class AssetDiscoveryError(ConnectorError):
    """Raised when asset discovery fails."""

    pass


class ScanError(ConnectorError):
    """Raised when scanning an asset fails."""

    pass


class UnsupportedProviderError(ConnectorError):
    """Raised when an unsupported cloud provider is specified."""

    pass


# Policy Engine Exceptions
class PolicyError(RisklenceException):
    """Base exception for policy engine errors."""

    pass


class FrameworkNotFoundError(PolicyError):
    """Raised when a compliance framework is not found."""

    pass


class FrameworkLoadError(PolicyError):
    """Raised when loading a framework fails."""

    pass


class RuleEvaluationError(PolicyError):
    """Raised when rule evaluation fails."""

    pass


class InvalidRuleError(PolicyError):
    """Raised when a rule definition is invalid."""

    pass


# Scanning Engine Exceptions
class ScanningError(RisklenceException):
    """Base exception for scanning engine errors."""

    pass


class ScanTimeoutError(ScanningError):
    """Raised when a scan times out."""

    pass


class ScanCancellationError(ScanningError):
    """Raised when a scan is cancelled."""

    pass


# Encryption / Credential Exceptions
class EncryptionError(RisklenceException):
    """Raised when encryption/decryption fails."""

    pass


# Risk Assessment Exceptions
class RiskAssessmentError(RisklenceException):
    """Base exception for risk assessment errors."""

    pass


class RiskCalculationError(RiskAssessmentError):
    """Raised when risk calculation fails."""

    pass


# Integration Exceptions
class IntegrationError(RisklenceException):
    """Base exception for integration errors."""

    pass


class JiraError(IntegrationError):
    """Raised when Jira integration fails."""

    pass


class VulnerabilityDatabaseError(IntegrationError):
    """Raised when vulnerability database query fails."""

    pass


class ThreatIntelError(IntegrationError):
    """Raised when threat intelligence fetch fails."""

    pass


# Reporting Exceptions
class ReportingError(RisklenceException):
    """Base exception for reporting errors."""

    pass


class ReportGenerationError(ReportingError):
    """Raised when report generation fails."""

    pass


class ExportError(ReportingError):
    """Raised when report export fails."""

    pass


# Validation Exceptions
class ValidationError(RisklenceException):
    """Raised when input validation fails."""

    pass


# API Exceptions
class APIError(RisklenceException):
    """Base exception for API errors."""

    pass


class NotFoundError(APIError):
    """Raised when a resource is not found."""

    pass


class ConflictError(APIError):
    """Raised when there's a resource conflict."""

    pass


class UnauthorizedError(APIError):
    """Raised when authentication is required."""

    pass


class ForbiddenError(APIError):
    """Raised when user doesn't have permission."""

    pass


# Common API aliases used across middleware/routes
class AuthorizationError(ForbiddenError):
    """Raised when a user is not authorized to perform an action."""

    pass


class ResourceNotFoundError(NotFoundError):
    """Raised when a requested resource cannot be found."""

    pass

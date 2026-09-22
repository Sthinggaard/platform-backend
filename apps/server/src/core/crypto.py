"""
Encryption service for cloud credentials.
Uses Fernet symmetric encryption with per-organization keys.
"""

import base64
import hashlib
import json
from typing import Any, Dict

from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from src.core.config import settings
from src.core.exceptions import EncryptionError
from src.core.logging_config import get_logger

logger = get_logger(__name__)


def _derive_fernet_key(context: str) -> bytes:
    """Shared context-scoped Fernet key derivation: SHA-256(base_key:context),
    base64-encoded. Extracted from ``CredentialEncryption._derive_key`` (still
    org-scoped, unchanged) so a second, differently-scoped secret — the
    per-scanner-instance command-signing key below — can reuse the same base
    encryption key without a second config setting."""
    base_key = settings.encryption.encryption_key.get_secret_value()
    combined = f"{base_key}:{context}".encode("utf-8")
    return base64.urlsafe_b64encode(hashlib.sha256(combined).digest())


# CA-04.1 — real per-instance command-signing key (spec: "Open design
# question for Soren" resolved as "build the real per-instance key").
#
# discovery_command_service.py previously signed commands with the platform's
# shared JWT secret, which the scanner CLI never has a copy of — client-side
# verification was cryptographically impossible, not merely unbuilt (see that
# module's now-superseded docstring). The one secret both sides durably hold
# is the raw activation token: the server only ever hashes and discards it
# (evidence_scanner_service.install_scanner/regenerate_activation_token), but
# the CLI keeps the raw value in credentials.json indefinitely. HKDF over that
# shared secret, salted by the scanner_instance_id, produces a per-instance
# signing key without inventing a new secret-provisioning channel.
#
# The derived key is captured server-side once, at the moment the raw token
# still exists (activation/rotation), then Fernet-encrypted at rest under a
# key scoped to this instance (never the raw token itself, and never the
# same key used for org-credential encryption) — so a leaked signing key
# only ever forges commands for that one scanner, not the whole platform.
_COMMAND_SIGNING_KEY_INFO = b"risklence-scanner-command-signing-v1"


def derive_command_signing_key(raw_activation_token: str, scanner_instance_id: str) -> bytes:
    """Real HKDF-SHA256, not the SHA-256-concat shortcut ``_derive_fernet_key``
    uses — this key must be independently re-derivable by the Collector from
    the same raw token, so it follows the standard construction exactly."""
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=scanner_instance_id.encode("utf-8"),
        info=_COMMAND_SIGNING_KEY_INFO,
    )
    return hkdf.derive(raw_activation_token.encode("utf-8"))


def encrypt_command_signing_key(scanner_instance_id: str, signing_key: bytes) -> bytes:
    fernet = Fernet(_derive_fernet_key(f"scanner_command_signing_{scanner_instance_id}"))
    return fernet.encrypt(signing_key)


def decrypt_command_signing_key(scanner_instance_id: str, encrypted_signing_key: bytes) -> bytes:
    fernet = Fernet(_derive_fernet_key(f"scanner_command_signing_{scanner_instance_id}"))
    try:
        return fernet.decrypt(encrypted_signing_key)
    except InvalidToken as exc:
        raise EncryptionError("Failed to decrypt scanner command-signing key: invalid token or data corrupted") from exc


class CredentialEncryption:
    """Encrypt and decrypt cloud credentials per organization.

    Uses Fernet (symmetric encryption) with a derived key per organization.
    The organization-specific key is derived from the base encryption key
    and the organization ID, ensuring each org has a unique encryption key.

    Security features:
    - AES-128 encryption in CBC mode
    - HMAC for authentication
    - Per-organization key derivation
    - Base64 encoding for storage

    Example usage:
        >>> encryptor = CredentialEncryption(organization_id=123)
        >>> encrypted = encryptor.encrypt_credentials({
        ...     "azure_client_id": "abc123",
        ...     "azure_client_secret": "secret",
        ... })
        >>> credentials = encryptor.decrypt_credentials(encrypted)
    """

    def __init__(self, organization_id: int) -> None:
        """Initialize encryption service for an organization.

        Args:
            organization_id: The organization ID to derive the encryption key
        """
        self.organization_id = organization_id
        self.key = self._derive_key(organization_id)
        self.fernet = Fernet(self.key)
        self.encryption_key_id = f"org_{organization_id}_v1"

    def _derive_key(self, organization_id: int) -> bytes:
        """Derive a unique encryption key for an organization.

        Uses PBKDF2-like key derivation from the base encryption key
        and organization ID.

        Args:
            organization_id: Organization ID to derive key for

        Returns:
            32-byte encryption key suitable for Fernet

        Raises:
            EncryptionError: If base encryption key is not configured
        """
        try:
            return _derive_fernet_key(str(organization_id))
        except Exception as e:
            logger.error("key_derivation_failed", organization_id=organization_id, error=str(e))
            raise EncryptionError(f"Failed to derive encryption key: {e}") from e

    def encrypt_credentials(self, credentials: Dict[str, Any]) -> bytes:
        """Encrypt credentials dictionary.

        Args:
            credentials: Dictionary of credential data to encrypt
                Example: {"azure_client_id": "...", "azure_client_secret": "..."}

        Returns:
            Encrypted credentials as bytes

        Raises:
            EncryptionError: If encryption fails
        """
        try:
            # Convert credentials dict to JSON string
            credentials_json = json.dumps(credentials)
            credentials_bytes = credentials_json.encode("utf-8")

            # Encrypt using Fernet
            encrypted_data = self.fernet.encrypt(credentials_bytes)

            logger.info(
                "credentials_encrypted",
                organization_id=self.organization_id,
                key_id=self.encryption_key_id,
            )

            return encrypted_data

        except Exception as e:
            logger.error(
                "encryption_failed",
                organization_id=self.organization_id,
                error=str(e),
            )
            raise EncryptionError(f"Failed to encrypt credentials: {e}") from e

    def decrypt_credentials(self, encrypted_data: bytes) -> Dict[str, Any]:
        """Decrypt credentials to dictionary.

        Args:
            encrypted_data: Encrypted credentials bytes

        Returns:
            Decrypted credentials dictionary

        Raises:
            EncryptionError: If decryption fails or data is invalid
        """
        try:
            # Decrypt using Fernet
            decrypted_bytes = self.fernet.decrypt(encrypted_data)

            # Convert bytes back to JSON string
            credentials_json = decrypted_bytes.decode("utf-8")

            # Parse JSON to dictionary
            credentials = json.loads(credentials_json)

            logger.debug(
                "credentials_decrypted",
                organization_id=self.organization_id,
                key_id=self.encryption_key_id,
            )

            return credentials

        except InvalidToken as e:
            logger.error(
                "decryption_invalid_token",
                organization_id=self.organization_id,
                error="Invalid encryption token or corrupted data",
            )
            raise EncryptionError(
                "Failed to decrypt credentials: Invalid token or data corrupted"
            ) from e
        except json.JSONDecodeError as e:
            logger.error(
                "decryption_invalid_json",
                organization_id=self.organization_id,
                error=str(e),
            )
            raise EncryptionError(
                f"Failed to decrypt credentials: Invalid JSON data - {e}"
            ) from e
        except Exception as e:
            logger.error(
                "decryption_failed",
                organization_id=self.organization_id,
                error=str(e),
            )
            raise EncryptionError(f"Failed to decrypt credentials: {e}") from e

    def rotate_key(self, old_encrypted_data: bytes) -> bytes:
        """Rotate encryption key by re-encrypting data with new key.

        This is used when the base encryption key changes or for
        periodic key rotation.

        Args:
            old_encrypted_data: Data encrypted with the old key

        Returns:
            Data re-encrypted with the new key

        Raises:
            EncryptionError: If rotation fails
        """
        try:
            # Decrypt with current key
            credentials = self.decrypt_credentials(old_encrypted_data)

            # Re-encrypt with new key (derived from updated settings)
            new_encrypted_data = self.encrypt_credentials(credentials)

            logger.info(
                "credentials_key_rotated",
                organization_id=self.organization_id,
                old_key_id=self.encryption_key_id,
            )

            return new_encrypted_data

        except Exception as e:
            logger.error(
                "key_rotation_failed",
                organization_id=self.organization_id,
                error=str(e),
            )
            raise EncryptionError(f"Failed to rotate encryption key: {e}") from e


def generate_encryption_key() -> str:
    """Generate a new Fernet encryption key.

    This is a utility function to generate a base encryption key
    for the settings. Should be called once during initial setup.

    Returns:
        Base64-encoded encryption key string

    Example:
        >>> key = generate_encryption_key()
        >>> # Add this key to .env as ENCRYPTION__ENCRYPTION_KEY=<key>
    """
    key = Fernet.generate_key()
    return key.decode("utf-8")


def validate_credentials_structure(credentials: Dict[str, Any], provider: str) -> bool:
    """Validate that credentials have the required fields for a provider.

    Args:
        credentials: Credentials dictionary to validate
        provider: Cloud provider name (azure, aws, gcp, etc.)

    Returns:
        True if valid, False otherwise
    """
    required_fields = {
        "azure": ["azure_tenant_id", "azure_client_id", "azure_client_secret"],
        "aws": ["aws_access_key_id", "aws_secret_access_key"],
        "gcp": ["project_id", "credentials_json"],
    }

    if provider not in required_fields:
        logger.warning("validate_credentials_unknown_provider", provider=provider)
        return True  # Unknown provider, can't validate

    provider_fields = required_fields[provider]
    missing_fields = [field for field in provider_fields if field not in credentials]

    if missing_fields:
        logger.warning(
            "validate_credentials_missing_fields",
            provider=provider,
            missing=missing_fields,
        )
        return False

    return True

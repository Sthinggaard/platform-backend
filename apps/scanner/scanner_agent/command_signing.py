"""CA-04.1 — real client-side verification of a signed discovery command.

Mirrors the server's ``src/core/crypto.py``/``discovery_command_service.py``
exactly: the same HKDF-SHA256 construction (salt=scanner_instance_id,
info=b"risklence-scanner-command-signing-v1"), over the same raw activation
token this agent already keeps in ``credentials.json``, produces the same
32-byte signing key the server derived once at activation/rotation time and
used to HMAC-sign the command. Reimplemented here with stdlib ``hmac``/
``hashlib`` rather than adding the ``cryptography`` package to this
deliberately small, signed, security-reviewed bundle (CA-03) — verified
byte-for-byte identical to ``cryptography.hazmat.primitives.kdf.hkdf.HKDF``
for the same inputs before relying on it.

Trust boundary (resolved deliberately as both, not one or the other): this
is real defense-in-depth — a compromised relay holding only the Bearer
credential cannot forge a signature without also holding this derived key —
*and* it supports non-repudiation, since a command that verifies here is
provably the exact one the platform signed, not merely one that arrived
over an authenticated connection.
"""

from __future__ import annotations

import hashlib
import hmac
import json
from datetime import datetime, timezone

_COMMAND_SIGNING_KEY_INFO = b"risklence-scanner-command-signing-v1"


def derive_command_signing_key(raw_activation_token: str, scanner_instance_id: str) -> bytes:
    return _hkdf_sha256(
        ikm=raw_activation_token.encode("utf-8"),
        salt=scanner_instance_id.encode("utf-8"),
        info=_COMMAND_SIGNING_KEY_INFO,
        length=32,
    )


def _hkdf_sha256(*, ikm: bytes, salt: bytes, info: bytes, length: int) -> bytes:
    """RFC 5869 HKDF-Extract-then-Expand — see module docstring."""
    prk = hmac.new(salt, ikm, hashlib.sha256).digest()
    okm = b""
    block = b""
    counter = 1
    while len(okm) < length:
        block = hmac.new(prk, block + info + bytes([counter]), hashlib.sha256).digest()
        okm += block
        counter += 1
    return okm[:length]


def _signable_payload(command: dict) -> str:
    """Byte-for-byte the same shape/ordering as the server's
    ``discovery_command_service._signable_payload`` — every field the
    server signs must be present here, including ``providerExecutionId``
    (always None for a whole-run Step 4.1 command, but part of the signed
    payload regardless)."""
    payload = {
        "commandId": command["command_id"],
        "commandType": command["command_type"],
        "organisationId": command["organisation_id"],
        "scannerInstanceId": command["scanner_instance_id"],
        "discoveryRunId": command["discovery_run_id"],
        "providerExecutionId": command.get("provider_execution_id"),
        # CA-04.7 added these to the server's signed payload. They were not
        # mirrored here at the time, so every command signed by a
        # CA-04.7-or-later server failed verification with
        # command_signature_invalid and no discovery could execute at all.
        # Absent for a command issued before the fields existed, hence .get().
        "businessProcessId": command.get("business_process_id"),
        "businessServiceId": command.get("business_service_id"),
        "issuedAt": _isoformat(command["issued_at"]),
        "expiresAt": _isoformat(command["expires_at"]),
    }
    return json.dumps(payload, sort_keys=True)


def _isoformat(value: str) -> str:
    """The wire value already arrives as an ISO-8601 string (Pydantic's
    JSON encoding of a datetime); the server signs ``datetime.isoformat()``
    of the same underlying value, so no reparsing/reformatting is needed —
    just guard against a trailing ``Z`` a future server version might add,
    since Python's own isoformat() never emits one."""
    return value[:-1] + "+00:00" if value.endswith("Z") else value


class CommandVerificationError(ValueError):
    """Raised with a CommandRejectionCode-shaped ``code`` — see
    discovery_run_enums.CommandRejectionCode on the server for the shared
    vocabulary these values must match exactly."""

    def __init__(self, message: str, *, code: str) -> None:
        super().__init__(message)
        self.code = code


def verify_command(command: dict, *, raw_activation_token: str, local_scanner_instance_id: str | None) -> None:
    """Raises CommandVerificationError with a real CommandRejectionCode if
    the command should not be executed. Returns normally (does not return a
    bool) so a caller cannot accidentally ignore the result — every
    rejection reason must be explicit and reported back to the platform."""
    if local_scanner_instance_id is not None and command["scanner_instance_id"] != local_scanner_instance_id:
        raise CommandVerificationError(
            "This command was not issued for this scanner instance.", code="scanner_instance_mismatch"
        )

    expires_at = _parse_iso(command["expires_at"])
    if expires_at <= datetime.now(timezone.utc):
        raise CommandVerificationError("This command has already expired.", code="command_expired")

    signing_key = derive_command_signing_key(raw_activation_token, command["scanner_instance_id"])
    expected_signature = hmac.new(signing_key, _signable_payload(command).encode("utf-8"), hashlib.sha256).hexdigest()
    if not hmac.compare_digest(expected_signature, command["signature"]):
        raise CommandVerificationError(
            "This command's signature does not match its contents.", code="command_signature_invalid"
        )


VERIFICATION_SIGNATURE_VERSION = "v1-verification"


def _signable_inspection_payload(inspection: dict) -> str:
    """Byte-for-byte the server's
    ``verification_inspection_service._signable_payload``.

    Two differences from the discovery payload above are deliberate and easy to
    get wrong:

    - ``signatureVersion`` is **inside** the signed payload. The signing key is
      shared with discovery on purpose, so without a domain string a discovery
      command's signature could be presented here, or the reverse.
    - the server uses compact separators (``,`` / ``:``). ``json.dumps``
      defaults to ``", "`` / ``": "``, which would produce a different byte
      string and fail every signature. Discovery's payload uses the default
      separators; this one does not, and the two must not be made to look alike.
    """
    payload = {
        "signatureVersion": inspection["signature_version"],
        "runId": inspection["run_id"],
        "organizationId": inspection["organization_id"],
        "assetId": inspection["asset_id"],
        "connectorId": inspection["connector_id"],
        "capability": inspection["capability"],
        "argv": list(inspection["argv"]),
        "issuedAt": _isoformat(inspection["issued_at"]),
        "expiresAt": _isoformat(inspection["expires_at"]),
    }
    return json.dumps(payload, sort_keys=True, separators=(",", ":"))


def verify_inspection(
    inspection: dict, *, raw_activation_token: str, local_scanner_instance_id: str | None
) -> None:
    """Raises ``CommandVerificationError`` unless this inspection may run.

    Returns nothing, like ``verify_command``, so a caller cannot accidentally
    ignore the result. **Nothing else in the agent may run an inspection
    without calling this first** — option C's whole claim is that an unsigned
    command cannot run, and that claim lives or dies here.

    Checked cheapest-first: instance, then expiry, then the signature, so a
    command that was never for us does not cost a key derivation.
    """
    if inspection.get("signature_version") != VERIFICATION_SIGNATURE_VERSION:
        raise CommandVerificationError(
            "This inspection is not signed for deep verification.",
            code="command_signature_invalid",
        )

    if (
        local_scanner_instance_id is not None
        and inspection.get("scanner_instance_id") != local_scanner_instance_id
    ):
        raise CommandVerificationError(
            "This inspection was not issued for this scanner instance.",
            code="scanner_instance_mismatch",
        )

    if _parse_iso(inspection["expires_at"]) <= datetime.now(timezone.utc):
        raise CommandVerificationError("This inspection has already expired.", code="command_expired")

    signing_key = derive_command_signing_key(
        raw_activation_token, inspection["scanner_instance_id"]
    )
    expected = hmac.new(
        signing_key, _signable_inspection_payload(inspection).encode("utf-8"), hashlib.sha256
    ).hexdigest()
    if not hmac.compare_digest(expected, inspection["signature"]):
        raise CommandVerificationError(
            "This inspection's signature does not match its contents.",
            code="command_signature_invalid",
        )


def _parse_iso(value: str) -> datetime:
    normalized = value[:-1] + "+00:00" if value.endswith("Z") else value
    parsed = datetime.fromisoformat(normalized)
    return parsed if parsed.tzinfo is not None else parsed.replace(tzinfo=timezone.utc)

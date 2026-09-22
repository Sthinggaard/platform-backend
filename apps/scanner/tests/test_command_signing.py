from datetime import datetime, timedelta, timezone

import pytest

from conftest import DEFAULT_ACTIVATION_TOKEN, DEFAULT_SCANNER_INSTANCE_ID, build_signed_command
from scanner_agent.command_signing import CommandVerificationError, derive_command_signing_key, verify_command


def test_verify_command_accepts_a_genuinely_signed_command():
    command = build_signed_command()
    verify_command(
        command, raw_activation_token=DEFAULT_ACTIVATION_TOKEN, local_scanner_instance_id=DEFAULT_SCANNER_INSTANCE_ID
    )  # does not raise


def test_verify_command_rejects_tampered_signature():
    command = build_signed_command(tamper_signature=True)
    with pytest.raises(CommandVerificationError) as exc_info:
        verify_command(
            command,
            raw_activation_token=DEFAULT_ACTIVATION_TOKEN,
            local_scanner_instance_id=DEFAULT_SCANNER_INSTANCE_ID,
        )
    assert exc_info.value.code == "command_signature_invalid"


def test_verify_command_rejects_expired_command():
    command = build_signed_command(
        issued_at=datetime.now(timezone.utc) - timedelta(minutes=30),
        expires_at=datetime.now(timezone.utc) - timedelta(minutes=1),
    )
    with pytest.raises(CommandVerificationError) as exc_info:
        verify_command(
            command,
            raw_activation_token=DEFAULT_ACTIVATION_TOKEN,
            local_scanner_instance_id=DEFAULT_SCANNER_INSTANCE_ID,
        )
    assert exc_info.value.code == "command_expired"


def test_verify_command_rejects_wrong_instance():
    command = build_signed_command(scanner_instance_id="instance-for-someone-else")
    with pytest.raises(CommandVerificationError) as exc_info:
        verify_command(
            command,
            raw_activation_token=DEFAULT_ACTIVATION_TOKEN,
            local_scanner_instance_id=DEFAULT_SCANNER_INSTANCE_ID,
        )
    assert exc_info.value.code == "scanner_instance_mismatch"


def test_verify_command_skips_instance_check_when_local_id_unknown():
    """Credentials saved before CA-04.1 have no stored instance id yet —
    verification must still run (signature/expiry), just without the
    wrong-instance check, rather than crashing on a missing value."""
    command = build_signed_command(scanner_instance_id="some-instance")
    verify_command(command, raw_activation_token=DEFAULT_ACTIVATION_TOKEN, local_scanner_instance_id=None)


def test_verify_command_rejects_a_key_derived_from_the_wrong_activation_token():
    """A relay that knows the command's shape but not the real activation
    token cannot produce a signature that verifies."""
    command = build_signed_command(activation_token="the-real-token")
    with pytest.raises(CommandVerificationError) as exc_info:
        verify_command(command, raw_activation_token="a-guessed-token", local_scanner_instance_id=DEFAULT_SCANNER_INSTANCE_ID)
    assert exc_info.value.code == "command_signature_invalid"


def test_derive_command_signing_key_differs_per_instance():
    key_a = derive_command_signing_key("same-token", "instance-a")
    key_b = derive_command_signing_key("same-token", "instance-b")
    assert key_a != key_b
    assert len(key_a) == 32

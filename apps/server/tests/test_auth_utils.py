from src.core.services.auth_service import (
    hash_password,
    verify_password,
    hash_refresh_token,
    sign_state_payload,
    verify_state_payload,
)


def test_password_hash_roundtrip():
    password = "SufficientlyLongPassword!"
    stored = hash_password(password)
    assert verify_password(password, stored) is True
    assert verify_password("wrong", stored) is False


def test_refresh_token_hash_is_deterministic():
    token = "test-token"
    assert hash_refresh_token(token) == hash_refresh_token(token)


def test_state_token_roundtrip():
    payload = {"state": "abc123", "nonce": "xyz"}
    token = sign_state_payload(payload)
    decoded = verify_state_payload(token)
    assert decoded["state"] == "abc123"
    assert decoded["nonce"] == "xyz"

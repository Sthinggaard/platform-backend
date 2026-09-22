"""_validate_production_secrets: production must never start with a known
placeholder or a too-short secret (security audit, 2026-07-16 — the old
exact-string blocklist missed the literal dev value committed in
apps/server/.env, despite that file's comment claiming it was blocked)."""

from __future__ import annotations

from types import SimpleNamespace

import pytest
from pydantic import SecretStr

from src.core.config import Environment, _validate_production_secrets

STRONG_SECRET = "x" * 40


def _settings(*, environment=Environment.PRODUCTION, jwt_secret=STRONG_SECRET, secret_key=STRONG_SECRET, enc_key=STRONG_SECRET):
    return SimpleNamespace(
        environment=environment,
        auth=SimpleNamespace(jwt_secret=SecretStr(jwt_secret) if jwt_secret is not None else None),
        secret_key=SecretStr(secret_key) if secret_key is not None else None,
        encryption=SimpleNamespace(encryption_key=SecretStr(enc_key) if enc_key is not None else None),
    )


def test_does_not_validate_outside_production():
    _validate_production_secrets(_settings(environment=Environment.DEVELOPMENT, jwt_secret="short"))


def test_strong_secrets_pass_in_production():
    _validate_production_secrets(_settings())


@pytest.mark.parametrize(
    "value",
    [
        "change-me-in-production",
        "change-me-in-production-use-32-bytes",
        "risklence-dev-only-jwt-secret-do-not-use-in-prod",
        "",
    ],
)
def test_rejects_known_placeholder_jwt_secrets_in_production(value):
    with pytest.raises(RuntimeError, match="AUTH_JWT_SECRET"):
        _validate_production_secrets(_settings(jwt_secret=value))


def test_rejects_the_actual_committed_dev_jwt_secret_in_production():
    # This exact value is committed in apps/server/.env with a comment
    # claiming "startup validation blocks it" — confirm that claim is true.
    with pytest.raises(RuntimeError, match="AUTH_JWT_SECRET"):
        _validate_production_secrets(_settings(jwt_secret="risklence-dev-only-jwt-secret-do-not-use-in-prod"))


def test_rejects_a_short_jwt_secret_even_if_not_on_the_exact_blocklist():
    with pytest.raises(RuntimeError, match="AUTH_JWT_SECRET"):
        _validate_production_secrets(_settings(jwt_secret="short-but-not-blocklisted"))


def test_rejects_placeholder_secret_key_in_production():
    with pytest.raises(RuntimeError, match="SECRET_KEY"):
        _validate_production_secrets(_settings(secret_key="change-me-in-production"))


def test_rejects_placeholder_encryption_key_in_production():
    with pytest.raises(RuntimeError, match="ENCRYPTION_KEY"):
        _validate_production_secrets(_settings(enc_key="change-me-in-production-use-32-bytes"))

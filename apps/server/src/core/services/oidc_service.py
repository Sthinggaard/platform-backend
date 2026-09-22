"""OIDC helpers for Google and Microsoft."""

from __future__ import annotations

import base64
import hashlib
import secrets
import time
from dataclasses import dataclass
from typing import Any, Dict
from urllib.parse import urlencode

import requests
from jose import JWTError, jwt

from src.core.config import settings
from src.core.exceptions import AuthenticationError, ConfigurationError
from src.core.logging_config import get_logger

logger = get_logger(__name__)


@dataclass(frozen=True)
class OidcProviderConfig:
    name: str
    auth_url: str
    token_url: str
    jwks_url: str
    issuer: str
    client_id: str
    client_secret: str
    redirect_uri: str


_JWKS_CACHE: Dict[str, dict] = {}
_JWKS_EXPIRES: Dict[str, float] = {}


def _get_google_config() -> OidcProviderConfig:
    if not (settings.auth.sso_google_client_id and settings.auth.sso_google_client_secret):
        raise ConfigurationError("SSO_GOOGLE_CLIENT_ID/SECRET not configured")
    if not settings.auth.sso_google_redirect_uri:
        raise ConfigurationError("SSO_GOOGLE_REDIRECT_URI not configured")
    return OidcProviderConfig(
        name="google",
        auth_url="https://accounts.google.com/o/oauth2/v2/auth",
        token_url="https://oauth2.googleapis.com/token",
        jwks_url="https://www.googleapis.com/oauth2/v3/certs",
        issuer="https://accounts.google.com",
        client_id=settings.auth.sso_google_client_id,
        client_secret=settings.auth.sso_google_client_secret.get_secret_value(),
        redirect_uri=settings.auth.sso_google_redirect_uri,
    )


def _get_microsoft_config() -> OidcProviderConfig:
    if not (settings.auth.sso_ms_client_id and settings.auth.sso_ms_client_secret):
        raise ConfigurationError("SSO_MS_CLIENT_ID/SECRET not configured")
    if not settings.auth.sso_ms_redirect_uri:
        raise ConfigurationError("SSO_MS_REDIRECT_URI not configured")
    tenant_mode = settings.auth.sso_ms_tenant_mode or "common"
    base = f"https://login.microsoftonline.com/{tenant_mode}/oauth2/v2.0"
    return OidcProviderConfig(
        name="microsoft",
        auth_url=f"{base}/authorize",
        token_url=f"{base}/token",
        jwks_url="https://login.microsoftonline.com/common/discovery/v2.0/keys",
        issuer="https://login.microsoftonline.com/",
        client_id=settings.auth.sso_ms_client_id,
        client_secret=settings.auth.sso_ms_client_secret.get_secret_value(),
        redirect_uri=settings.auth.sso_ms_redirect_uri,
    )


def get_provider_config(provider: str) -> OidcProviderConfig:
    if provider == "google":
        return _get_google_config()
    if provider == "microsoft":
        return _get_microsoft_config()
    raise ConfigurationError("Unknown OIDC provider")


def build_pkce_pair() -> tuple[str, str]:
    verifier = secrets.token_urlsafe(48)
    challenge = base64.urlsafe_b64encode(
        hashlib.sha256(verifier.encode("utf-8")).digest()
    ).rstrip(b"=").decode("utf-8")
    return verifier, challenge


def build_authorization_url(provider: str, state: str, nonce: str, code_challenge: str) -> str:
    config = get_provider_config(provider)
    params = {
        "client_id": config.client_id,
        "response_type": "code",
        "redirect_uri": config.redirect_uri,
        "scope": "openid email profile",
        "state": state,
        "nonce": nonce,
        "code_challenge": code_challenge,
        "code_challenge_method": "S256",
    }
    if provider == "microsoft":
        params["prompt"] = "select_account"
    return f"{config.auth_url}?{urlencode(params)}"


def exchange_code(provider: str, code: str, code_verifier: str) -> dict:
    config = get_provider_config(provider)
    payload = {
        "client_id": config.client_id,
        "client_secret": config.client_secret,
        "grant_type": "authorization_code",
        "code": code,
        "redirect_uri": config.redirect_uri,
        "code_verifier": code_verifier,
    }
    resp = requests.post(config.token_url, data=payload, timeout=10)
    if resp.status_code != 200:
        logger.warning("oidc_token_exchange_failed", provider=provider, status=resp.status_code)
        raise AuthenticationError("SSO token exchange failed")
    return resp.json()


def _fetch_jwks(provider: str) -> dict:
    cache_key = provider
    if cache_key in _JWKS_CACHE and time.time() < _JWKS_EXPIRES.get(cache_key, 0):
        return _JWKS_CACHE[cache_key]
    config = get_provider_config(provider)
    resp = requests.get(config.jwks_url, timeout=10)
    if resp.status_code != 200:
        raise AuthenticationError("Failed to fetch OIDC JWKS")
    data = resp.json()
    _JWKS_CACHE[cache_key] = data
    _JWKS_EXPIRES[cache_key] = time.time() + 300
    return data


def _resolve_key(provider: str, kid: str | None) -> dict | None:
    if not kid:
        return None
    jwks = _fetch_jwks(provider).get("keys", [])
    for key in jwks:
        if key.get("kid") == kid:
            return {
                "kty": key.get("kty"),
                "kid": key.get("kid"),
                "use": key.get("use"),
                "n": key.get("n"),
                "e": key.get("e"),
            }
    return None


def verify_id_token(provider: str, id_token: str, nonce: str) -> Dict[str, Any]:
    config = get_provider_config(provider)
    try:
        header = jwt.get_unverified_header(id_token)
        key = _resolve_key(provider, header.get("kid"))
        if not key:
            raise AuthenticationError("Invalid SSO token key")
        claims = jwt.decode(
            id_token,
            key,
            algorithms=["RS256"],
            audience=config.client_id,
            issuer=None,
            options={"verify_iss": False},
        )
    except JWTError as exc:
        raise AuthenticationError("Invalid SSO token") from exc

    if claims.get("nonce") != nonce:
        raise AuthenticationError("SSO nonce mismatch")

    if provider == "google":
        issuer = claims.get("iss")
        if issuer not in (config.issuer, "accounts.google.com"):
            raise AuthenticationError("Invalid SSO issuer")
    if provider == "microsoft":
        tid = claims.get("tid")
        if not tid:
            raise AuthenticationError("Missing tenant claim")
        issuer = claims.get("iss") or ""
        expected = f"https://login.microsoftonline.com/{tid}/v2.0"
        if issuer != expected:
            raise AuthenticationError("Invalid SSO issuer")

    return claims

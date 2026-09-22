"""CA-07.6 (#240) — the redaction primitive, because there was not one.

The epic's exit criterion is that *readiness is visible without secrets*, and
the repo-first inspection for CA-07.6 found **no redaction anywhere in the
codebase** — so this is built and asserted rather than assumed.

It is a second line, not the first. CA-07.2's rule is that the platform
*cannot receive* a credential: ``AccessConnector`` has no ``encrypted_credentials``,
no ``token_hash``, and no other column that could carry secret material even
reversibly. Redaction exists for everything downstream of that guarantee which
is **not** shaped by a model — free-text notes a person typed, a failure message
a Collector sent back, the metadata bag on an audit event. Those are the places a
secret can still arrive, because nothing about their shape prevents it.

Two deliberate design choices:

* **Key-based, not value-based.** Guessing whether a *value* looks like a secret
  means a regex for "things that resemble a token", which both misses real
  secrets and redacts innocent identifiers. Redacting by *key* is decidable, and
  a caller who names a field ``password`` has told us what it holds.
* **Redaction never removes the key.** A vanished field reads as "there was
  nothing here", which is a different and misleading fact. The key stays with
  ``[redacted]`` as its value, so a reader — and an auditor — can see that
  something was held back rather than that nothing existed.
"""

from __future__ import annotations

from typing import Any

#: What a redacted value reads as. One definition, so a test can assert it and a
#: reader always sees the same word.
REDACTED = "[redacted]"

#: Substrings that mark a key as secret-bearing. Matched case-insensitively
#: against the whole key, so ``apiToken``, ``api_token`` and ``API_TOKEN`` all
#: match on ``token``.
#:
#: ``fingerprint`` is deliberately **absent**. ``AccessConnector.credential_fingerprint``
#: is a fingerprint of a credential the platform never held — it identifies
#: *which* key the Collector is using without being derived from anything
#: reversible — and redacting it would hide the one field that lets a person
#: confirm the right credential is in place.
_SECRET_KEY_MARKERS: tuple[str, ...] = (
    "password",
    "passphrase",
    "secret",
    "token",
    "credential",
    "private_key",
    "privatekey",
    "api_key",
    "apikey",
    "access_key",
    "accesskey",
    "authorization",
    "auth_header",
    "session_key",
    "sessionkey",
    "client_secret",
    "clientsecret",
)

#: Keys that contain a marker but are not secrets. Checked before the markers,
#: because ``credential_model`` says *where a credential may live* and
#: ``credential_fingerprint`` says *which one is in use* — redacting either
#: removes the readiness this story exists to make visible.
_NOT_SECRET_KEYS: frozenset[str] = frozenset(
    {
        "credential_model",
        "credential_fingerprint",
        "credential_username",
        "permitted_credential_models",
        "token_expires_at",
        "credential_model_reason",
    }
)


def is_secret_key(key: str) -> bool:
    """Whether a field name says the value is secret-bearing."""
    lowered = key.strip().lower()
    if lowered in _NOT_SECRET_KEYS:
        return False
    return any(marker in lowered for marker in _SECRET_KEY_MARKERS)


def redact(value: Any) -> Any:
    """Return ``value`` with every secret-bearing entry replaced by ``REDACTED``.

    Walks dicts, lists and tuples so an audit event's nested metadata bag is
    covered rather than only its top level — a secret one level down is still a
    secret in the log. Scalars pass through untouched: without a key there is
    nothing to decide on, and guessing from the value is the value-based
    approach this module rejects.
    """
    if isinstance(value, dict):
        return {
            key: REDACTED if is_secret_key(str(key)) else redact(inner)
            for key, inner in value.items()
        }
    if isinstance(value, list):
        return [redact(item) for item in value]
    if isinstance(value, tuple):
        return tuple(redact(item) for item in value)
    return value

"""Step 4.2 Part 2 — evidence payload storage.

Resolved with Søren (2026-07-21, DISC-17): local filesystem behind this
Protocol first (DISC-23), DigitalOcean Spaces as a second registered
implementation once a real Space existed (DISC-23b, resolved 2026-07-23) —
``EvidencePackage.raw_evidence_reference`` never depended on which backend
was configured, and switching the active one was a registry change here,
never a redesign of anything that calls ``get_evidence_storage_backend``.

Same Protocol + registry shape as every other provider abstraction in this
domain (``organization_registry_provider.py``, ``discovery_normalization_service``).
"""

from __future__ import annotations

import hashlib
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol
from uuid import uuid4

import boto3
from botocore.exceptions import BotoCoreError, ClientError

from src.core.config import settings

_ENV_LOCAL_STORAGE_DIR = "DISCOVERY_EVIDENCE_LOCAL_STORAGE_DIR"
_DEV_DEFAULT_STORAGE_DIR = "var/discovery-evidence"

_ENV_SPACES_BUCKET = "DISCOVERY_EVIDENCE_SPACES_BUCKET"
_ENV_SPACES_REGION = "DISCOVERY_EVIDENCE_SPACES_REGION"
_ENV_SPACES_ENDPOINT = "DISCOVERY_EVIDENCE_SPACES_ENDPOINT"
_ENV_SPACES_KEY = "DISCOVERY_EVIDENCE_SPACES_KEY"
_ENV_SPACES_SECRET = "DISCOVERY_EVIDENCE_SPACES_SECRET"


@dataclass(frozen=True)
class StoredEvidence:
    reference: str
    integrity_hash: str | None


class EvidenceStorageBackend(Protocol):
    backend_id: str

    def store(self, *, organization_id: int, payload: bytes, evidence_format: str) -> StoredEvidence: ...

    def retrieve(self, *, reference: str) -> bytes: ...


class EvidenceStorageError(RuntimeError):
    """Raised when a payload cannot be persisted — never silently
    swallowed; the caller marks the EvidencePackage STORAGE_FAILED."""


class LocalFilesystemBackend:
    """Writes evidence under a local directory. Never used in production
    without an explicit opt-in — production is expected to have
    DigitalOceanSpacesBackend configured instead (see
    _digitalocean_spaces_config below)."""

    backend_id = "local_filesystem"

    def __init__(self, base_dir: str | None = None) -> None:
        configured = base_dir or (os.getenv(_ENV_LOCAL_STORAGE_DIR) or "").strip()
        if not configured:
            if settings.is_production:
                raise EvidenceStorageError(
                    f"{_ENV_LOCAL_STORAGE_DIR} is required in production — configure a real "
                    "evidence storage backend rather than falling back to local disk."
                )
            configured = _DEV_DEFAULT_STORAGE_DIR
        self._base_dir = Path(configured)

    def store(self, *, organization_id: int, payload: bytes, evidence_format: str) -> StoredEvidence:
        org_dir = self._base_dir / str(organization_id)
        try:
            org_dir.mkdir(parents=True, exist_ok=True)
            file_name = f"{uuid4()}.{evidence_format}"
            file_path = org_dir / file_name
            file_path.write_bytes(payload)
        except OSError as exc:
            raise EvidenceStorageError(f"Failed to write evidence payload: {exc}") from exc
        integrity_hash = hashlib.sha256(payload).hexdigest()
        return StoredEvidence(reference=str(file_path), integrity_hash=integrity_hash)

    def retrieve(self, *, reference: str) -> bytes:
        try:
            return Path(reference).read_bytes()
        except OSError as exc:
            raise EvidenceStorageError(f"Failed to read evidence payload: {exc}") from exc


class DigitalOceanSpacesBackend:
    """DISC-23b. DO Spaces is S3-compatible, so this is a thin boto3 S3
    client pointed at the Space's own regional endpoint — no DO-specific
    SDK needed. One object per evidence payload, keyed
    ``{organization_id}/{uuid}.{evidence_format}`` (mirrors
    LocalFilesystemBackend's own path shape, so a package's
    raw_evidence_reference stays structurally similar across backends even
    though one is a filesystem path and the other an s3:// URI)."""

    backend_id = "digitalocean_spaces"

    def __init__(self, *, bucket: str, region: str, endpoint_url: str, access_key: str, secret_key: str) -> None:
        self._bucket = bucket
        self._client = boto3.client(
            "s3",
            region_name=region,
            endpoint_url=endpoint_url,
            aws_access_key_id=access_key,
            aws_secret_access_key=secret_key,
        )

    def store(self, *, organization_id: int, payload: bytes, evidence_format: str) -> StoredEvidence:
        key = f"{organization_id}/{uuid4()}.{evidence_format}"
        integrity_hash = hashlib.sha256(payload).hexdigest()
        try:
            self._client.put_object(Bucket=self._bucket, Key=key, Body=payload)
        except (BotoCoreError, ClientError) as exc:
            raise EvidenceStorageError(f"Failed to upload evidence payload to DigitalOcean Spaces: {exc}") from exc
        return StoredEvidence(reference=f"s3://{self._bucket}/{key}", integrity_hash=integrity_hash)

    def retrieve(self, *, reference: str) -> bytes:
        prefix = f"s3://{self._bucket}/"
        if not reference.startswith(prefix):
            raise EvidenceStorageError(f"Reference {reference!r} does not belong to this Space's bucket.")
        key = reference[len(prefix) :]
        try:
            response = self._client.get_object(Bucket=self._bucket, Key=key)
            return response["Body"].read()
        except (BotoCoreError, ClientError) as exc:
            raise EvidenceStorageError(f"Failed to download evidence payload from DigitalOcean Spaces: {exc}") from exc


def _digitalocean_spaces_config() -> dict[str, str] | None:
    """None unless every DISCOVERY_EVIDENCE_SPACES_* var is set — a
    partially-configured Space (e.g. bucket set but no key) falls back to
    the local backend in dev, or fails LocalFilesystemBackend's own
    production guard, rather than silently ignoring the partial config."""
    values = {
        "bucket": (os.getenv(_ENV_SPACES_BUCKET) or "").strip(),
        "region": (os.getenv(_ENV_SPACES_REGION) or "").strip(),
        "endpoint_url": (os.getenv(_ENV_SPACES_ENDPOINT) or "").strip(),
        "access_key": (os.getenv(_ENV_SPACES_KEY) or "").strip(),
        "secret_key": (os.getenv(_ENV_SPACES_SECRET) or "").strip(),
    }
    if all(values.values()):
        return values
    return None


# Lazily populated per backend_id — never built eagerly at import time,
# so importing this module never itself requires either backend's
# credentials (or LocalFilesystemBackend's production guard) to already be
# satisfied. Tests monkeypatch this dict directly to inject a disposable
# backend instance (e.g. LocalFilesystemBackend pointed at a temp dir).
_BACKENDS_BY_ID: dict[str, EvidenceStorageBackend] = {}


def get_evidence_storage_backend() -> EvidenceStorageBackend:
    """DigitalOceanSpacesBackend when DISCOVERY_EVIDENCE_SPACES_* is fully
    configured; LocalFilesystemBackend otherwise. The caller
    (discovery_execution_command_service.record_provider_execution_result)
    never knows or cares which — switching backends is a registry change
    here, not a caller-side change."""
    spaces_config = _digitalocean_spaces_config()
    if spaces_config is not None:
        if DigitalOceanSpacesBackend.backend_id not in _BACKENDS_BY_ID:
            _BACKENDS_BY_ID[DigitalOceanSpacesBackend.backend_id] = DigitalOceanSpacesBackend(**spaces_config)
        return _BACKENDS_BY_ID[DigitalOceanSpacesBackend.backend_id]

    if LocalFilesystemBackend.backend_id not in _BACKENDS_BY_ID:
        _BACKENDS_BY_ID[LocalFilesystemBackend.backend_id] = LocalFilesystemBackend()
    return _BACKENDS_BY_ID[LocalFilesystemBackend.backend_id]

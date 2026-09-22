"""Step 4.2 Part 2 — DISC-23/23b: the EvidenceStorageBackend registry.
LocalFilesystemBackend, DigitalOceanSpacesBackend (boto3 client mocked —
no real network calls), and get_evidence_storage_backend's selection logic
(Spaces when fully configured, local filesystem otherwise)."""

from __future__ import annotations

import hashlib
from unittest.mock import MagicMock

import pytest
from botocore.exceptions import ClientError

from src.core.services import evidence_storage_backend as backend_module
from src.core.services.evidence_storage_backend import (
    DigitalOceanSpacesBackend,
    EvidenceStorageError,
    LocalFilesystemBackend,
    get_evidence_storage_backend,
)

_SPACES_ENV = {
    "DISCOVERY_EVIDENCE_SPACES_BUCKET": "risklence-discovery-evidence",
    "DISCOVERY_EVIDENCE_SPACES_REGION": "ams3",
    "DISCOVERY_EVIDENCE_SPACES_ENDPOINT": "https://ams3.digitaloceanspaces.com",
    "DISCOVERY_EVIDENCE_SPACES_KEY": "test-key",
    "DISCOVERY_EVIDENCE_SPACES_SECRET": "test-secret",
}


@pytest.fixture(autouse=True)
def _reset_backend_cache(monkeypatch):
    """Every test gets a clean slate — get_evidence_storage_backend caches
    its chosen backend per process, which would otherwise leak state
    between tests that flip between local/Spaces configuration."""
    monkeypatch.setattr(backend_module, "_BACKENDS_BY_ID", {})


def test_local_filesystem_backend_writes_file_and_returns_hash(tmp_path):
    backend = LocalFilesystemBackend(base_dir=str(tmp_path))
    result = backend.store(organization_id=7, payload=b"hello evidence", evidence_format="json")

    assert result.integrity_hash == hashlib.sha256(b"hello evidence").hexdigest()
    from pathlib import Path

    written = Path(result.reference)
    assert written.exists()
    assert written.read_bytes() == b"hello evidence"
    assert written.parent.name == "7"


def test_local_filesystem_backend_retrieves_what_it_stored(tmp_path):
    backend = LocalFilesystemBackend(base_dir=str(tmp_path))
    stored = backend.store(organization_id=7, payload=b"hello evidence", evidence_format="json")

    assert backend.retrieve(reference=stored.reference) == b"hello evidence"


def test_local_filesystem_backend_retrieve_raises_when_file_missing(tmp_path):
    backend = LocalFilesystemBackend(base_dir=str(tmp_path))
    with pytest.raises(EvidenceStorageError):
        backend.retrieve(reference=str(tmp_path / "does-not-exist.json"))


def test_digitalocean_spaces_backend_uploads_via_boto3_client(monkeypatch):
    mock_client = MagicMock()
    monkeypatch.setattr(backend_module.boto3, "client", MagicMock(return_value=mock_client))

    backend = DigitalOceanSpacesBackend(
        bucket="risklence-discovery-evidence",
        region="ams3",
        endpoint_url="https://ams3.digitaloceanspaces.com",
        access_key="test-key",
        secret_key="test-secret",
    )
    result = backend.store(organization_id=7, payload=b"<nmaprun/>", evidence_format="nmap_xml")

    mock_client.put_object.assert_called_once()
    call_kwargs = mock_client.put_object.call_args.kwargs
    assert call_kwargs["Bucket"] == "risklence-discovery-evidence"
    assert call_kwargs["Body"] == b"<nmaprun/>"
    assert call_kwargs["Key"].startswith("7/")
    assert call_kwargs["Key"].endswith(".nmap_xml")
    assert result.reference == f"s3://risklence-discovery-evidence/{call_kwargs['Key']}"
    assert result.integrity_hash == hashlib.sha256(b"<nmaprun/>").hexdigest()


def test_digitalocean_spaces_backend_retrieves_via_get_object(monkeypatch):
    mock_body = MagicMock()
    mock_body.read.return_value = b"<nmaprun/>"
    mock_client = MagicMock()
    mock_client.get_object.return_value = {"Body": mock_body}
    monkeypatch.setattr(backend_module.boto3, "client", MagicMock(return_value=mock_client))

    backend = DigitalOceanSpacesBackend(
        bucket="risklence-discovery-evidence",
        region="ams3",
        endpoint_url="https://ams3.digitaloceanspaces.com",
        access_key="test-key",
        secret_key="test-secret",
    )
    payload = backend.retrieve(reference="s3://risklence-discovery-evidence/7/abc.nmap_xml")

    assert payload == b"<nmaprun/>"
    mock_client.get_object.assert_called_once_with(Bucket="risklence-discovery-evidence", Key="7/abc.nmap_xml")


def test_digitalocean_spaces_backend_retrieve_rejects_reference_from_another_bucket(monkeypatch):
    monkeypatch.setattr(backend_module.boto3, "client", MagicMock(return_value=MagicMock()))
    backend = DigitalOceanSpacesBackend(
        bucket="risklence-discovery-evidence",
        region="ams3",
        endpoint_url="https://ams3.digitaloceanspaces.com",
        access_key="test-key",
        secret_key="test-secret",
    )
    with pytest.raises(EvidenceStorageError):
        backend.retrieve(reference="s3://some-other-bucket/7/abc.nmap_xml")


def test_digitalocean_spaces_backend_wraps_client_errors(monkeypatch):
    mock_client = MagicMock()
    mock_client.put_object.side_effect = ClientError({"Error": {"Code": "403", "Message": "Forbidden"}}, "PutObject")
    monkeypatch.setattr(backend_module.boto3, "client", MagicMock(return_value=mock_client))

    backend = DigitalOceanSpacesBackend(
        bucket="risklence-discovery-evidence",
        region="ams3",
        endpoint_url="https://ams3.digitaloceanspaces.com",
        access_key="test-key",
        secret_key="test-secret",
    )
    with pytest.raises(EvidenceStorageError):
        backend.store(organization_id=7, payload=b"data", evidence_format="json")


def test_selects_local_filesystem_when_spaces_not_configured(monkeypatch, tmp_path):
    for key in _SPACES_ENV:
        monkeypatch.delenv(key, raising=False)
    monkeypatch.setenv("DISCOVERY_EVIDENCE_LOCAL_STORAGE_DIR", str(tmp_path))

    backend = get_evidence_storage_backend()
    assert isinstance(backend, LocalFilesystemBackend)


def test_selects_digitalocean_spaces_when_fully_configured(monkeypatch):
    for key, value in _SPACES_ENV.items():
        monkeypatch.setenv(key, value)
    monkeypatch.setattr(backend_module.boto3, "client", MagicMock(return_value=MagicMock()))

    backend = get_evidence_storage_backend()
    assert isinstance(backend, DigitalOceanSpacesBackend)


def test_falls_back_to_local_when_spaces_config_is_only_partial(monkeypatch, tmp_path):
    for key in _SPACES_ENV:
        monkeypatch.delenv(key, raising=False)
    monkeypatch.setenv("DISCOVERY_EVIDENCE_SPACES_BUCKET", "risklence-discovery-evidence")
    # region/endpoint/key/secret deliberately left unset
    monkeypatch.setenv("DISCOVERY_EVIDENCE_LOCAL_STORAGE_DIR", str(tmp_path))

    backend = get_evidence_storage_backend()
    assert isinstance(backend, LocalFilesystemBackend)

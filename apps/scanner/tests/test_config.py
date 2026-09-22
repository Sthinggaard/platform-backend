from pathlib import Path

import pytest

from scanner_agent.config import ScannerCredentials, load_credentials, save_credentials


def test_save_and_load_credentials_round_trip(tmp_path: Path):
    credentials = ScannerCredentials(base_url="https://api.example.com", activation_token="tok_abc123")
    save_credentials(credentials, config_dir=tmp_path)

    loaded = load_credentials(config_dir=tmp_path)

    assert loaded == credentials


def test_load_credentials_missing_file_raises(tmp_path: Path):
    with pytest.raises(FileNotFoundError):
        load_credentials(config_dir=tmp_path / "does-not-exist")


def test_save_credentials_restricts_file_permissions(tmp_path: Path):
    credentials = ScannerCredentials(base_url="https://api.example.com", activation_token="tok_abc123")
    path = save_credentials(credentials, config_dir=tmp_path)

    assert oct(path.stat().st_mode)[-3:] == "600"


def test_save_and_load_credentials_round_trip_with_scanner_instance_id(tmp_path: Path):
    """CA-04.1 — scanner_instance_id is captured at activate time so `poll`
    can reject a wrong-instance command locally."""
    credentials = ScannerCredentials(
        base_url="https://api.example.com", activation_token="tok_abc123", scanner_instance_id="instance-123"
    )
    save_credentials(credentials, config_dir=tmp_path)

    loaded = load_credentials(config_dir=tmp_path)

    assert loaded == credentials


def test_load_credentials_defaults_scanner_instance_id_to_none_for_old_files(tmp_path: Path):
    """A credentials.json saved before CA-04.1 has no scanner_instance_id
    key at all — it must load, not crash, with that field simply unset."""
    path = tmp_path / "credentials.json"
    tmp_path.mkdir(parents=True, exist_ok=True)
    path.write_text('{"base_url": "https://api.example.com", "activation_token": "tok_abc123"}')

    loaded = load_credentials(config_dir=tmp_path)

    assert loaded.scanner_instance_id is None

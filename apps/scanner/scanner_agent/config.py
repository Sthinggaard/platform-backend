"""Local credential storage for the Risklence Scanner CLI.

The activation token is issued once by the platform (copied from the
Evidence Source setup screen) and persisted here so later commands
(heartbeat / validate-tools / test-scan) don't need it re-entered.
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass
from pathlib import Path

DEFAULT_CONFIG_DIR = Path(os.environ.get("RISKLENCE_SCANNER_HOME", str(Path.home() / ".risklence-scanner")))
CREDENTIALS_FILENAME = "credentials.json"


@dataclass(frozen=True)
class ScannerCredentials:
    base_url: str
    activation_token: str
    # CA-04.1 — captured from the activate command's own heartbeat response.
    # Needed locally so `poll` can reject a "wrong instance" command (a
    # command whose scanner_instance_id doesn't match this one) instead of
    # blindly trusting whatever the platform claims to have sent. None for
    # credentials saved before this shipped, until the next `activate`.
    scanner_instance_id: str | None = None


def credentials_path(config_dir: Path = DEFAULT_CONFIG_DIR) -> Path:
    return config_dir / CREDENTIALS_FILENAME


def save_credentials(credentials: ScannerCredentials, config_dir: Path = DEFAULT_CONFIG_DIR) -> Path:
    config_dir.mkdir(parents=True, exist_ok=True)
    path = credentials_path(config_dir)
    path.write_text(
        json.dumps(
            {
                "base_url": credentials.base_url,
                "activation_token": credentials.activation_token,
                "scanner_instance_id": credentials.scanner_instance_id,
            }
        )
    )
    path.chmod(0o600)
    return path


def load_credentials(config_dir: Path = DEFAULT_CONFIG_DIR) -> ScannerCredentials:
    path = credentials_path(config_dir)
    if not path.exists():
        raise FileNotFoundError(f"No scanner credentials found at {path}. Run `risklence-scanner activate` first.")
    data = json.loads(path.read_text())
    return ScannerCredentials(
        base_url=data["base_url"],
        activation_token=data["activation_token"],
        scanner_instance_id=data.get("scanner_instance_id"),
    )

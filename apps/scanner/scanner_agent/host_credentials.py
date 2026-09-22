"""CA-08.2 (#290) — how the Collector logs in, held only by the Collector.

CA-07.2 settled the rule this module exists to keep: **the platform cannot
receive a credential, not merely doesn't.** That is a claim about the shape of
the system, so the credential for a host lives here, on the operator's own
machine, in a file the platform has never seen and has nowhere to put.

What that means concretely, and why each part matters:

- **A record names a key file; it never contains key material.** The private key
  stays wherever the operator already keeps it, with whatever passphrase and
  permissions they already chose. Copying it into our file would make this a
  second place a key can leak from.
- **Nothing in this module reads from an inspection envelope.** The envelope
  arrives from the platform; a lookup keyed by anything inside it would be a
  path for the platform to influence which credential is used. The connector id
  is the key, and it is checked against records the operator wrote.
- **There is no setter that takes a secret over the wire.** Records are written
  by the operator, through the CLI, on the machine.

Deliberately mirrors ``config.py``'s file idiom — same directory, same 0600, so
an operator has one place to look and one thing to back up.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path

from scanner_agent.config import DEFAULT_CONFIG_DIR

HOST_CREDENTIALS_FILENAME = "host-credentials.json"


def _resolve(config_dir: Path | None) -> Path:
    """Where the records live, decided when asked rather than when imported.

    ``DEFAULT_CONFIG_DIR`` is read at call time on purpose. Binding it as a
    default argument — the idiom in ``config.py`` — freezes it at import, so
    ``RISKLENCE_SCANNER_HOME`` set by a wrapper script after the module loads is
    silently ignored, and no test can point the store somewhere safe.
    """
    return config_dir if config_dir is not None else DEFAULT_CONFIG_DIR


class HostCredentialError(RuntimeError):
    """No usable way to reach this host — a fact about setup, not a crash."""


@dataclass(frozen=True)
class HostCredential:
    """Everything needed to open a session, and nothing secret.

    ``identity_file`` is a path. If it is ever tempting to add a
    ``private_key``/``password`` field here, that is the moment CA-07.2 stops
    being structural — the whole point is that this record can be read by
    anyone who already owns the machine and still discloses nothing new.
    """

    connector_id: str
    host: str
    username: str
    identity_file: str | None = None
    port: int = 22

    def destination(self) -> str:
        return f"{self.username}@{self.host}"


def host_credentials_path(config_dir: Path | None = None) -> Path:
    return _resolve(config_dir) / HOST_CREDENTIALS_FILENAME


def save_host_credential(
    credential: HostCredential, config_dir: Path | None = None
) -> Path:
    """Write or replace one record, on this machine, by the operator."""
    path = host_credentials_path(config_dir)
    path.parent.mkdir(parents=True, exist_ok=True)

    records = _read_all(path)
    records[credential.connector_id] = {
        "host": credential.host,
        "username": credential.username,
        "identity_file": credential.identity_file,
        "port": credential.port,
    }
    path.write_text(json.dumps(records, indent=2, sort_keys=True))
    path.chmod(0o600)
    return path


def load_host_credential(
    connector_id: str, config_dir: Path | None = None
) -> HostCredential:
    """The credential for one connector, or a refusal that says what to do.

    Raises rather than returning ``None``: an inspection that silently proceeds
    without a credential would fall back to whatever the ambient SSH
    configuration happens to allow, which is precisely an unbounded inspection.
    """
    path = host_credentials_path(config_dir)
    records = _read_all(path)
    record = records.get(connector_id)
    if record is None:
        raise HostCredentialError(
            f"No host credential is configured for connector {connector_id}. "
            f"Add one with `risklence-scanner add-host-credential` on this machine — "
            f"the platform cannot supply it."
        )

    identity_file = record.get("identity_file")
    if identity_file is not None and not Path(identity_file).expanduser().exists():
        raise HostCredentialError(
            f"The key file configured for connector {connector_id} is not there: {identity_file}"
        )

    return HostCredential(
        connector_id=connector_id,
        host=record["host"],
        username=record["username"],
        identity_file=identity_file,
        port=int(record.get("port", 22)),
    )


def is_world_readable(config_dir: Path | None = None) -> bool:
    """Whether the record file is readable beyond its owner.

    Worth reporting even though the file holds no key material: it still
    discloses which accounts on which hosts this Collector can reach, which is a
    map worth having. Returned rather than warned about here, so the CLI decides
    how to say it and this module keeps doing one job.
    """
    path = host_credentials_path(config_dir)
    return path.exists() and bool(path.stat().st_mode & 0o077)


def _read_all(path: Path) -> dict[str, dict]:
    if not path.exists():
        return {}
    return json.loads(path.read_text())

"""CA-08.2 (#290) — the Collector logs in, and cannot exceed what was signed.

The tests that carry the weight:

- ``test_the_remote_shell_receives_exactly_the_argv_the_server_signed`` — the
  bug this module was written to avoid. ``ssh`` hands its arguments to the
  remote login shell, so an unquoted ``${Package}`` would be expanded away and
  a *different* command from the approved one would run, silently.
- ``test_an_unsigned_inspection_never_reaches_subprocess`` — option C's whole
  claim, asserted rather than assumed.
- ``test_a_failed_login_is_a_fact_about_the_artefact_not_an_exception`` — the
  criterion, in one line.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import shlex
import subprocess
from datetime import datetime, timedelta, timezone

import pytest

from scanner_agent.command_signing import (
    CommandVerificationError,
    derive_command_signing_key,
    verify_inspection,
)
from scanner_agent.host_credentials import (
    HostCredential,
    HostCredentialError,
    load_host_credential,
    save_host_credential,
)
from scanner_agent.host_inspection import build_ssh_command, run_inspection

TOKEN = "activation-token-value"
INSTANCE = "scanner-1"
CONNECTOR = "connector-1"


def _signed(argv: list[str], **overrides) -> dict:
    now = datetime.now(timezone.utc)
    inspection = {
        "signature_version": "v1-verification",
        "scanner_instance_id": INSTANCE,
        "run_id": "run-1",
        "organization_id": 1,
        "asset_id": 10,
        "connector_id": CONNECTOR,
        "capability": "read_os_version",
        "argv": argv,
        "issued_at": now.isoformat(),
        "expires_at": (now + timedelta(seconds=300)).isoformat(),
    }
    inspection.update(overrides)

    # Signed exactly the way the server does — compact separators, sorted keys,
    # signatureVersion inside the payload.
    payload = json.dumps(
        {
            "signatureVersion": inspection["signature_version"],
            "runId": inspection["run_id"],
            "organizationId": inspection["organization_id"],
            "assetId": inspection["asset_id"],
            "connectorId": inspection["connector_id"],
            "capability": inspection["capability"],
            "argv": list(inspection["argv"]),
            "issuedAt": inspection["issued_at"],
            "expiresAt": inspection["expires_at"],
        },
        sort_keys=True,
        separators=(",", ":"),
    )
    key = derive_command_signing_key(TOKEN, inspection["scanner_instance_id"])
    inspection["signature"] = hmac.new(key, payload.encode(), hashlib.sha256).hexdigest()
    return inspection


def _credential() -> HostCredential:
    return HostCredential(
        connector_id=CONNECTOR, host="db-01.internal", username="risklence", port=22
    )


class _Completed:
    def __init__(self, returncode: int, stdout: str = "", stderr: str = "") -> None:
        self.returncode = returncode
        self.stdout = stdout
        self.stderr = stderr


# --- The quoting problem ---------------------------------------------------


def test_the_remote_shell_receives_exactly_the_argv_the_server_signed():
    """The defect this module exists to avoid.

    ``ssh`` does not carry an argv to the far side — it joins its arguments and
    the remote login shell re-parses the result. Unquoted, dpkg's own format
    string ``-f=${Package}`` would be expanded by *that* shell into nothing, and
    the command that ran would not be the command that was approved.
    """
    argv = ["dpkg-query", "-W", "-f=${Package}\t${Version}\n"]
    command = build_ssh_command(argv, credential=_credential(), timeout=30)

    remote = command[-1]
    # Round-trip through a shell parser: what the far side would actually run.
    assert shlex.split(remote) == argv
    assert "${Package}" in remote  # survived, rather than being expanded away


def test_a_hostile_looking_argument_cannot_break_out_of_its_element():
    argv = ["cat", "/etc/os-release; rm -rf /"]
    command = build_ssh_command(argv, credential=_credential(), timeout=30)
    assert shlex.split(command[-1]) == argv


# --- Nothing runs unverified -----------------------------------------------


def test_an_unsigned_inspection_never_reaches_subprocess(monkeypatch):
    called = False

    def _fail(*args, **kwargs):
        nonlocal called
        called = True
        raise AssertionError("subprocess must not run for an unverified inspection")

    monkeypatch.setattr(subprocess, "run", _fail)

    inspection = _signed(["cat", "/etc/os-release"])
    inspection["signature"] = "0" * 64

    with pytest.raises(CommandVerificationError):
        run_inspection(
            inspection,
            credential=_credential(),
            raw_activation_token=TOKEN,
            local_scanner_instance_id=INSTANCE,
        )
    assert called is False


def test_a_tampered_argv_invalidates_the_signature():
    inspection = _signed(["cat", "/etc/os-release"])
    inspection["argv"] = ["cat", "/etc/shadow"]

    with pytest.raises(CommandVerificationError, match="signature"):
        verify_inspection(
            inspection, raw_activation_token=TOKEN, local_scanner_instance_id=INSTANCE
        )


def test_a_discovery_signature_cannot_be_presented_as_an_inspection():
    """Domain separation, from the Collector's side.

    The signing key is shared with discovery on purpose, so the version string
    inside the payload is the only thing keeping the two apart.
    """
    inspection = _signed(["cat", "/etc/os-release"])
    inspection["signature_version"] = "v1"

    with pytest.raises(CommandVerificationError, match="not signed for deep verification"):
        verify_inspection(
            inspection, raw_activation_token=TOKEN, local_scanner_instance_id=INSTANCE
        )


def test_an_expired_inspection_is_refused():
    past = datetime.now(timezone.utc) - timedelta(seconds=10)
    inspection = _signed(["cat", "/etc/os-release"], expires_at=past.isoformat())

    with pytest.raises(CommandVerificationError, match="expired"):
        verify_inspection(
            inspection, raw_activation_token=TOKEN, local_scanner_instance_id=INSTANCE
        )


def test_an_inspection_for_another_collector_is_refused():
    inspection = _signed(["cat", "/etc/os-release"], scanner_instance_id="scanner-2")

    with pytest.raises(CommandVerificationError, match="not issued for this scanner"):
        verify_inspection(
            inspection, raw_activation_token=TOKEN, local_scanner_instance_id=INSTANCE
        )


def test_a_credential_for_a_different_connector_is_refused(monkeypatch):
    monkeypatch.setattr(subprocess, "run", lambda *a, **k: _Completed(0, "ok"))
    inspection = _signed(["cat", "/etc/os-release"])
    other = HostCredential(connector_id="connector-2", host="h", username="u")

    with pytest.raises(HostCredentialError, match="connector-2"):
        run_inspection(
            inspection,
            credential=other,
            raw_activation_token=TOKEN,
            local_scanner_instance_id=INSTANCE,
        )


# --- Failures are facts about the artefact ---------------------------------


def test_a_failed_login_is_reported_rather_than_raised(monkeypatch):
    """CA-08.2's criterion, from the Collector's side.

    A host that refuses the credential must come back as a *result*. An
    exception is how a platform reports its own failures, and "we could not log
    in to this host" is not one of those — it is something the organisation
    needs to act on. What it *means* is the engine's to decide.
    """
    monkeypatch.setattr(
        subprocess,
        "run",
        lambda *a, **k: _Completed(255, stderr="risklence@db-01: Permission denied (publickey)."),
    )

    result = run_inspection(
        _signed(["cat", "/etc/os-release"]),
        credential=_credential(),
        raw_activation_token=TOKEN,
        local_scanner_instance_id=INSTANCE,
    )

    assert result.exit_code == 255
    assert "Permission denied" in result.stderr


def test_a_successful_inspection_returns_what_the_host_said(monkeypatch):
    monkeypatch.setattr(
        subprocess, "run", lambda *a, **k: _Completed(0, stdout='NAME="Debian GNU/Linux"')
    )

    result = run_inspection(
        _signed(["cat", "/etc/os-release"]),
        credential=_credential(),
        raw_activation_token=TOKEN,
        local_scanner_instance_id=INSTANCE,
    )

    assert result.exit_code == 0
    assert "Debian" in result.stdout


def test_a_timeout_is_a_reported_fact_rather_than_a_crash(monkeypatch):
    def _timeout(*args, **kwargs):
        raise subprocess.TimeoutExpired(cmd="ssh", timeout=1)

    monkeypatch.setattr(subprocess, "run", _timeout)

    result = run_inspection(
        _signed(["cat", "/etc/os-release"]),
        credential=_credential(),
        raw_activation_token=TOKEN,
        local_scanner_instance_id=INSTANCE,
    )
    assert result.timed_out is True
    assert result.exit_code is None


def test_the_collector_reaches_no_conclusion_about_what_happened():
    """The naivety rule, asserted so it cannot quietly come back.

    Søren, 2026-08-24: the Collector collects, the engine reads. A field named
    ``outcome`` (or a ``succeeded`` shortcut) reappearing on this result is the
    Collector deciding what an attempt meant.

    ``credential_findings`` is here on purpose and is the one exception, added
    by #296. The rule is *naive about meaning, never naive about secrets*:
    recognising that a value is a credential is not deciding what an artefact
    **is**, and it has to happen on this side because CA-07.2 says the platform
    cannot receive one. It carries a setting name and a rule name — never a
    value, which the test below asserts.
    """
    from dataclasses import fields

    from scanner_agent import host_inspection

    names = {f.name for f in fields(host_inspection.InspectionResult)}
    assert names == {
        "run_id",
        "capability",
        "stdout",
        "stderr",
        "exit_code",
        "timed_out",
        "credential_findings",
    }
    assert not hasattr(host_inspection, "classify_outcome")
    assert not [n for n in dir(host_inspection) if n.startswith("OUTCOME_")]


# --- The credential stays here ---------------------------------------------


def test_a_credential_record_holds_no_key_material(tmp_path):
    save_host_credential(
        HostCredential(
            connector_id=CONNECTOR,
            host="db-01.internal",
            username="risklence",
            identity_file=None,
        ),
        config_dir=tmp_path,
    )
    written = (tmp_path / "host-credentials.json").read_text().lower()

    for forbidden in ("private", "begin rsa", "begin openssh", "password", "passphrase", "secret"):
        assert forbidden not in written, forbidden


def test_the_credential_file_is_not_world_readable(tmp_path):
    path = save_host_credential(_credential(), config_dir=tmp_path)
    assert path.stat().st_mode & 0o077 == 0


def test_a_missing_credential_says_the_platform_cannot_supply_it(tmp_path):
    with pytest.raises(HostCredentialError, match="platform cannot supply it"):
        load_host_credential("connector-nope", config_dir=tmp_path)


def test_the_inspection_envelope_carries_nowhere_to_put_a_credential():
    """CA-07.2, asserted from this side of the wire.

    The Collector never reads a credential out of what the platform sent, so the
    envelope having no such field is not merely true today — it is the property
    that keeps the rule structural.
    """
    inspection = _signed(["cat", "/etc/os-release"])
    for forbidden in ("password", "private_key", "identity_file", "username", "credential"):
        assert forbidden not in inspection, forbidden


def test_the_cli_stores_a_path_and_never_the_key_itself(tmp_path, monkeypatch):
    """The operator's entry point, and the promise it has to keep.

    ``--identity-file`` takes a path. The command must not read the file, so a
    key that exists is recorded by reference and a key that does not exist is
    still recorded — this command configures, it does not validate reachability.
    """
    from click.testing import CliRunner

    from scanner_agent import host_credentials
    from scanner_agent.cli import cli

    real_before = _real_config_snapshot()

    key = tmp_path / "id_ed25519"
    key.write_text("-----BEGIN OPENSSH PRIVATE KEY-----\nsecret-material\n")

    # Both, deliberately. The env var is what DEFAULT_CONFIG_DIR is *built*
    # from, and the attribute is what a call actually reads — an earlier version
    # of this test set only the attribute while the module still bound the
    # default at import, so it wrote into the developer's real
    # ~/.risklence-scanner and merged an entry into their live credential file.
    monkeypatch.setenv("RISKLENCE_SCANNER_HOME", str(tmp_path / "cfg"))
    monkeypatch.setattr(host_credentials, "DEFAULT_CONFIG_DIR", tmp_path / "cfg")

    result = CliRunner().invoke(
        cli,
        [
            "add-host-credential",
            "--connector-id", CONNECTOR,
            "--host", "db-01.internal",
            "--username", "risklence",
            "--identity-file", str(key),
        ],
    )

    assert result.exit_code == 0, result.output

    # Nothing outside the sandbox, asserted rather than hoped for: this turns a
    # silent write to the developer's real config into a failing test.
    assert (tmp_path / "cfg" / "host-credentials.json").exists(), "nothing written to the sandbox"
    assert _real_config_snapshot() == real_before, "the test wrote to the real ~/.risklence-scanner"

    written = (tmp_path / "cfg" / "host-credentials.json").read_text()
    assert str(key) in written
    assert "secret-material" not in written
    assert "BEGIN OPENSSH" not in written


def _real_config_snapshot() -> str | None:
    """What the developer's actual credential file holds, if anything.

    Exists because this test once wrote into it for real — see the comment in
    the test above. Compared before and after so the damage is caught by the
    suite rather than found by hand weeks later.
    """
    from pathlib import Path

    real = Path.home() / ".risklence-scanner" / "host-credentials.json"
    return real.read_text() if real.exists() else None


def test_a_credential_read_from_a_config_file_never_reaches_the_report(monkeypatch):
    """#296, end to end on this side of the wire.

    The whole chain: a real config file comes back from the host, and what
    ``run_inspection`` returns — which is precisely what gets transmitted —
    holds no credential, while still saying one was there.
    """
    secret = "hunter2-do-not-transmit"
    monkeypatch.setattr(
        subprocess,
        "run",
        lambda *a, **k: _Completed(0, stdout=f"user = admin\npassword = {secret}\nlisten 80;"),
    )

    inspection = _signed(["cat", "/etc/nginx/nginx.conf"], capability="read_service_config")
    inspection["config_target"] = "nginx"

    result = run_inspection(
        inspection,
        credential=_credential(),
        raw_activation_token=TOKEN,
        local_scanner_instance_id=INSTANCE,
    )

    assert secret not in result.stdout
    assert secret not in result.stderr
    assert "password = [redacted]" in result.stdout
    # Still reported, because it is a weakness in the customer's environment.
    assert result.credential_findings == (
        {"target": "nginx", "setting": "password", "kind": "secret_setting"},
    )
    # And nothing anywhere in the object carries it.
    assert secret not in repr(result)


def test_output_from_other_capabilities_is_not_run_through_the_redactor(monkeypatch):
    """Only configuration is redacted, and only because it holds settings.

    Running a config redactor over a package list would be a slower way of
    finding nothing, and would risk mangling evidence the read was granted for.
    """
    monkeypatch.setattr(
        subprocess, "run", lambda *a, **k: _Completed(0, stdout="password-manager\t1.2.3")
    )

    result = run_inspection(
        _signed(["dpkg-query", "-W"], capability="read_installed_packages"),
        credential=_credential(),
        raw_activation_token=TOKEN,
        local_scanner_instance_id=INSTANCE,
    )

    assert result.stdout == "password-manager\t1.2.3"
    assert result.credential_findings == ()

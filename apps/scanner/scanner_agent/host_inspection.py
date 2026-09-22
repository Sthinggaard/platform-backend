"""CA-08.2 (#290) — the Collector authenticates into a host and runs one bounded read.

This is the primitive the repo did not have. ``nmap_runner``, ``nuclei_runner``
and ``subfinder_runner`` look at a host from outside; nothing logged into one.

**No new dependency.** ``paramiko`` and ``asyncssh`` both pull in
``cryptography``, ``bcrypt`` and ``pynacl``, and this bundle deliberately ships
three runtime dependencies (``click``, ``requests``, ``defusedxml``) because it
is small, signed and security-reviewed (CA-03). CA-04.1 already made this trade
once, reimplementing HKDF on ``hmac``/``hashlib`` rather than adding
``cryptography`` for one function. So the transport is the system ``ssh``
binary, invoked as argv — which is also better reviewed than any Python SSH
library, and which the operator already configures, audits and rotates keys for.

**The subtlety that decides whether option C survives the hop.** ``ssh host cmd
arg arg`` does *not* pass an argv to the remote side: OpenSSH joins the
arguments with spaces and the remote sshd runs the result through the login
shell. So the server's careful argv tuple would be re-parsed by a shell we do
not control — and ``dpkg-query -f=${Package}`` would have ``${Package}``
expanded to nothing before ``dpkg-query`` ever saw it. Every element is
therefore shell-quoted here (``_remote_command``), which restores exactly the
argv the server signed. Getting this wrong does not fail loudly; it silently
runs a *different* command from the one that was approved, which is the one
outcome option C exists to prevent.

**Nothing runs unverified.** ``run_inspection`` calls ``verify_inspection``
first, always. The claim "an unsigned command cannot run" is only true because
of that line.

**One exception to the naivety rule, and it is deliberate: secrets.** Output
from ``read_service_config`` is redacted here, on the machine that read it,
before anything is transmitted (#296). CA-07.2's rule is that the platform
*cannot receive* a credential — redacting on the server would mean it had
already crossed the wire. Recognising a secret is not the same as reaching a
conclusion about what an artefact *is*, which stays the engine's job.

**This module reaches no conclusions.** Søren, 2026-08-24: the Collector stays
naive, and the engine reads what it collected — the pattern ``nmap_runner``
already follows, returning raw NMAP XML for the server's evidence adapter to
parse. An earlier cut of this file classified exit codes into
``authentication_failed`` / ``permission_denied_on_host`` here, which was the
Collector deciding what an attempt *meant*. That now lives in the server's
``verification_outcome_service``; what leaves here is an exit status, whatever
was written to stderr, and whether the process returned at all.

The one thing the Collector is **not** naive about is secrets. CA-07.2's rule is
that the platform *cannot* receive a credential, so redaction has to happen
before the wire, not after it (#296, CA-08.6). Naive about meaning, never naive
about secrets.
"""

from __future__ import annotations

import shlex
import subprocess
from dataclasses import dataclass
from pathlib import Path

from scanner_agent.command_signing import verify_inspection
from scanner_agent.config_redaction import redact_configuration
from scanner_agent.host_credentials import HostCredential, HostCredentialError

DEFAULT_INSPECTION_TIMEOUT_SECONDS = 30.0


class SshNotAvailableError(RuntimeError):
    """No ssh binary on PATH — a Collector installation problem, not a host fact."""


@dataclass(frozen=True)
class InspectionResult:
    """What happened, in terms that describe the artefact rather than us."""

    run_id: str
    capability: str
    stdout: str
    stderr: str
    #: ``None`` only when the process never returned — see ``timed_out``.
    exit_code: int | None
    #: #296 — that a credential was present in what was read, never what it was.
    #: Empty for every capability but ``read_service_config``.
    credential_findings: tuple[dict, ...] = ()
    #: A fact only this side can know: the process did not finish in time.
    #: Reported rather than interpreted, like everything else here.
    timed_out: bool = False


def run_inspection(
    inspection: dict,
    *,
    credential: HostCredential,
    raw_activation_token: str,
    local_scanner_instance_id: str | None,
    timeout: float = DEFAULT_INSPECTION_TIMEOUT_SECONDS,
) -> InspectionResult:
    """Verify, connect, run the approved command, and report what came of it.

    Raises only for things that are genuinely ours: an unverifiable instruction
    (``CommandVerificationError``) or a missing ``ssh``. Every *host* problem
    comes back as an ``InspectionResult`` with an outcome, because CA-08.2's
    criterion is that a failure to authenticate is a fact about the artefact and
    not a platform error — and an exception is how a platform reports its own
    failures.
    """
    verify_inspection(
        inspection,
        raw_activation_token=raw_activation_token,
        local_scanner_instance_id=local_scanner_instance_id,
    )

    if credential.connector_id != inspection["connector_id"]:
        # The operator's record and the signed instruction disagree about which
        # host this is. Refusing rather than preferring either one: a mismatch
        # here means somebody's configuration is wrong, and guessing would log
        # in to a machine nobody approved for this run.
        raise HostCredentialError(
            f"Credential is for connector {credential.connector_id}, but this inspection "
            f"is for {inspection['connector_id']}."
        )

    argv = list(inspection["argv"])
    command = build_ssh_command(argv, credential=credential, timeout=timeout)

    try:
        completed = subprocess.run(
            command, capture_output=True, text=True, timeout=timeout + 5.0
        )
    except FileNotFoundError as exc:  # ssh itself is missing
        raise SshNotAvailableError(
            "The ssh client is not installed on this Collector, so no host can be inspected."
        ) from exc
    except subprocess.TimeoutExpired:
        return InspectionResult(
            run_id=inspection["run_id"],
            capability=inspection["capability"],
            stdout="",
            stderr="",
            exit_code=None,
            timed_out=True,
        )

    stdout, findings = _scrub(inspection, completed.stdout)
    return InspectionResult(
        run_id=inspection["run_id"],
        capability=inspection["capability"],
        stdout=stdout,
        stderr=completed.stderr,
        exit_code=completed.returncode,
        credential_findings=findings,
    )


def _scrub(inspection: dict, stdout: str) -> tuple[str, tuple[dict, ...]]:
    """Take every credential out of configuration output, here, before the wire.

    Applied by capability rather than by sniffing the content: only
    ``read_service_config`` reads a file whose whole purpose is to hold
    settings, and running a redactor over a package list would be a slower way
    of finding nothing. If a later capability starts reading files, it joins
    this check — and until it does, its output is not carried at all
    (``OUTPUT_SAFE_BEFORE_REDACTION`` on the platform).
    """
    if inspection.get("capability") != "read_service_config":
        return stdout, ()

    result = redact_configuration(stdout, target=inspection.get("config_target") or "")
    return result.text, tuple(
        {"target": f.target, "setting": f.setting, "kind": f.kind} for f in result.findings
    )


def build_ssh_command(
    argv: list[str], *, credential: HostCredential, timeout: float
) -> list[str]:
    """The local argv that runs the remote argv, with nothing left to a shell.

    ``BatchMode=yes`` matters more than it looks: without it, ssh prompts for a
    passphrase or password and an unattended Collector hangs until the timeout
    rather than reporting that it could not authenticate.

    ``StrictHostKeyChecking=accept-new`` trusts a host key the first time and
    refuses it if it ever changes. ``no`` would accept a changed key silently,
    which is the shape of a machine-in-the-middle; ``yes`` would mean no host
    could ever be inspected until an operator had logged in by hand first.
    """
    command = [
        "ssh",
        "-o", "BatchMode=yes",
        "-o", "StrictHostKeyChecking=accept-new",
        "-o", f"ConnectTimeout={int(timeout)}",
        "-o", "LogLevel=ERROR",
        "-p", str(credential.port),
    ]
    if credential.identity_file:
        # IdentitiesOnly stops ssh-agent from silently offering some other key
        # and succeeding with a credential nobody recorded for this connector.
        command += [
            "-i", str(Path(credential.identity_file).expanduser()),
            "-o", "IdentitiesOnly=yes",
        ]
    command.append(credential.destination())
    command.append(_remote_command(argv))
    return command


def _remote_command(argv: list[str]) -> str:
    """Re-quote the server's argv so the remote login shell reproduces it exactly.

    See the module docstring: this is the line that keeps the approved command
    and the executed command the same thing.
    """
    return " ".join(shlex.quote(element) for element in argv)


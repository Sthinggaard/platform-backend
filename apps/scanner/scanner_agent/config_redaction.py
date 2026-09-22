"""#296 — a credential in deployed configuration, redacted here and reported as a finding.

Two things happen in this module, and keeping them together is the point.

**It redacts before the wire.** CA-07.2's rule is that the platform *cannot
receive* a credential, not merely that it doesn't ask for one. Redacting on the
server would mean the credential had already crossed the network and been held,
however briefly, in a place the rule says it can never be. So it happens on the
Collector, on the machine that read the file, and the value never leaves.

**It still tells the organisation.** Søren, 2026-08-24: a credential sitting in
plaintext in a readable configuration file is a weakness in the *client's*
environment. It was true before we looked, we did not cause it, and redacting it
silently would mean the platform knew about a real exposure and said nothing.

The tension between those two, and how it is resolved: reporting the finding is
proof we read the thing we promised never to hold. So a finding carries the
**shape** — which setting, on which service, matching which kind of secret — and
never the value, never a fragment of it, and never enough to reconstruct it.

This is the one place the Collector is deliberately **not** naive. It reaches no
conclusion about what an artefact *is* — that is the engine's job — but it must
recognise a secret, because the alternative is transmitting one.

**Key-based first, like CA-07.6.** Guessing whether a *value* looks secret means
a regex for "things that resemble a token", which both misses real secrets and
redacts innocent identifiers. Configuration is mostly ``key = value``, so the key
is available and the decision is decidable. Two value patterns are matched as
well — a PEM block and a connection string with inline credentials — because
neither has a key to be found by, and both are unmistakable.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

#: What a redacted value reads as. Matches the server's ``REDACTED`` exactly:
#: the two are mirrored across the bundle boundary for the same reason
#: ``CommandRejectionCode`` is, and a reader should see one word, not two.
REDACTED = "[redacted]"

#: Substrings that mark a configuration key as secret-bearing. Deliberately the
#: same vocabulary as the server's ``_SECRET_KEY_MARKERS``; divergence between
#: them would mean a key redacted in an audit log and printed in a config read.
_SECRET_KEY_MARKERS = (
    "password",
    "passwd",
    "secret",
    "token",
    "apikey",
    "api_key",
    "private_key",
    "privatekey",
    "credential",
    "auth",
    "passphrase",
    "access_key",
    "client_secret",
)

#: ``key = value`` / ``key: value`` / ``key value``, which covers nginx, apache,
#: postgresql.conf, systemd units and .env alike.
_ASSIGNMENT = re.compile(
    r"^(?P<indent>\s*)(?P<key>[A-Za-z_][A-Za-z0-9_.\-]*)(?P<sep>\s*[:=]\s*|\s+)(?P<value>\S.*?)\s*$"
)

#: A private key block. No key names it, and nothing else looks like this.
_PEM_BEGIN = re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----")
_PEM_END = re.compile(r"-----END [A-Z ]*PRIVATE KEY-----")

#: ``scheme://user:password@host`` — the credential is inside the value, so no
#: key would ever reveal it.
_CONNECTION_STRING = re.compile(r"(?P<scheme>[a-zA-Z][a-zA-Z0-9+.\-]*://)(?P<user>[^:/@\s]+):(?P<secret>[^@/\s]+)@")


@dataclass(frozen=True)
class CredentialFinding:
    """That a secret was present, and nothing about what it was.

    ``setting`` is the configuration key — ``password``, ``client_secret``. It
    is the name of a field, not its contents, and naming it is what makes the
    finding actionable: "your nginx config stores a password in plaintext" is
    something a person can go and fix.
    """

    #: Which approved target the file was, e.g. ``nginx``.
    target: str
    #: The configuration key, or a description where there was no key.
    setting: str
    #: Which rule matched, so the finding can say why it believes this.
    kind: str


@dataclass(frozen=True)
class RedactionResult:
    text: str
    findings: tuple[CredentialFinding, ...]

    @property
    def found_credentials(self) -> bool:
        return bool(self.findings)


def redact_configuration(text: str, *, target: str) -> RedactionResult:
    """Strip every credential out of one configuration file, and say what was there.

    The returned text is what may cross the wire. The findings are what the
    organisation is told. Neither carries a value.
    """
    findings: list[CredentialFinding] = []
    lines: list[str] = []
    in_pem = False

    for line in (text or "").splitlines():
        if in_pem:
            if _PEM_END.search(line):
                in_pem = False
                lines.append(REDACTED if not line.strip().startswith("---") else line)
            continue

        if _PEM_BEGIN.search(line):
            in_pem = True
            findings.append(
                CredentialFinding(target=target, setting="private key block", kind="pem_private_key")
            )
            lines.append(line)
            lines.append(REDACTED)
            continue

        connection = _CONNECTION_STRING.search(line)
        if connection:
            findings.append(
                CredentialFinding(
                    target=target,
                    setting="connection string",
                    kind="connection_string_password",
                )
            )
            line = _CONNECTION_STRING.sub(
                lambda m: f"{m.group('scheme')}{m.group('user')}:{REDACTED}@", line
            )
            lines.append(line)
            continue

        match = _ASSIGNMENT.match(line)
        if match and _is_secret_key(match.group("key")):
            findings.append(
                CredentialFinding(
                    target=target, setting=match.group("key"), kind="secret_setting"
                )
            )
            # The key stays, with REDACTED as its value. A vanished line reads
            # as "there was nothing here", which is a different and misleading
            # fact — the same reasoning CA-07.6 records about its own redaction.
            # The file's own spacing and punctuation, reproduced verbatim, so a
            # redacted line still reads as configuration rather than as damage.
            lines.append(
                f"{match.group('indent')}{match.group('key')}"
                f"{match.group('sep')}{REDACTED}"
            )
            continue

        lines.append(line)

    return RedactionResult(text="\n".join(lines), findings=tuple(findings))


def _is_secret_key(key: str) -> bool:
    lowered = key.lower()
    return any(marker in lowered for marker in _SECRET_KEY_MARKERS)


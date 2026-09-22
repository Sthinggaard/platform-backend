"""#296 — a credential in deployed configuration never leaves the machine that read it.

The test that carries the weight is
``test_no_secret_value_survives_into_anything_that_crosses_the_wire``. Everything
else here is detail; that one is the promise.

CA-07.2's rule is that the platform *cannot receive* a credential, not merely
that it does not ask for one. Redacting on the server would mean the value had
already crossed the network — so it happens here, and these tests are what makes
that a property rather than an intention.
"""

from __future__ import annotations

import pytest

from scanner_agent.config_redaction import REDACTED, redact_configuration

SECRET = "hunter2-do-not-transmit"

NGINX = f"""
user www-data;
worker_processes auto;
# a comment mentioning password, which is not an assignment
password {SECRET};
proxy_pass http://backend;
"""

ENV_FILE = f"""
DATABASE_URL=postgres://app:{SECRET}@db:5432/appdb
API_TOKEN={SECRET}
PUBLIC_URL=https://example.com
CLIENT_SECRET: {SECRET}
"""

PEM = f"""
ssl_certificate /etc/ssl/cert.pem;
-----BEGIN RSA PRIVATE KEY-----
{SECRET}
MIIEowIBAAKCAQEA
-----END RSA PRIVATE KEY-----
listen 443 ssl;
"""


@pytest.mark.parametrize("source", [NGINX, ENV_FILE, PEM], ids=["nginx", "env", "pem"])
def test_no_secret_value_survives_into_anything_that_crosses_the_wire(source):
    """The promise, in one assertion, over every shape of config we handle."""
    result = redact_configuration(source, target="nginx")

    assert SECRET not in result.text
    # And not in the findings either — reporting the exposure must not become
    # the way the value escapes.
    for finding in result.findings:
        assert SECRET not in finding.setting
        assert SECRET not in finding.kind
        assert SECRET not in finding.target


def test_a_secret_setting_keeps_its_key_so_the_gap_is_visible():
    """A vanished line reads as "there was nothing here", which is a lie.

    Same reasoning CA-07.6 records about its own redaction: the key stays, the
    value is replaced, and a reader can see that something was held back.
    """
    result = redact_configuration(f"password = {SECRET}", target="nginx")

    assert result.text == f"password = {REDACTED}"
    assert result.findings[0].setting == "password"


def test_the_file_still_reads_as_configuration_afterwards():
    """Redaction that mangles the file makes the rest of it unreadable too."""
    result = redact_configuration(
        "  client_secret: abc\nAPI_TOKEN=xyz\nlisten 80;", target="nginx"
    )

    assert result.text.splitlines() == [
        f"  client_secret: {REDACTED}",
        f"API_TOKEN={REDACTED}",
        "listen 80;",
    ]


def test_a_password_inside_a_connection_string_is_found_without_a_key():
    """No key names it, so key-based matching alone would miss it entirely."""
    result = redact_configuration(
        f"DATABASE_URL=postgres://app:{SECRET}@db:5432/appdb", target="postgresql"
    )

    assert SECRET not in result.text
    # The rest of the URL survives: which database, as which user, on which host
    # is exactly what makes the finding actionable.
    assert "postgres://app:" in result.text
    assert "@db:5432/appdb" in result.text
    assert result.findings[0].kind == "connection_string_password"


def test_an_entire_private_key_block_is_removed_not_just_its_first_line():
    result = redact_configuration(PEM, target="nginx")

    assert SECRET not in result.text
    assert "MIIEowIBAAKCAQEA" not in result.text
    assert result.findings[0].kind == "pem_private_key"
    # The surrounding configuration is untouched.
    assert "listen 443 ssl;" in result.text


def test_ordinary_settings_are_left_alone():
    """Over-redaction destroys the evidence the read was granted for."""
    source = "user www-data;\nworker_processes auto;\nlisten 80;"
    assert redact_configuration(source, target="nginx").text == source
    assert redact_configuration(source, target="nginx").findings == ()


def test_a_key_is_matched_however_it_is_spelled():
    for key in ("password", "PASSWORD", "db_password", "clientSecret", "API_KEY"):
        result = redact_configuration(f"{key} = {SECRET}", target="nginx")
        assert SECRET not in result.text, key
        assert result.findings, key


def test_empty_output_is_not_a_finding():
    result = redact_configuration("", target="nginx")
    assert result.text == ""
    assert result.found_credentials is False

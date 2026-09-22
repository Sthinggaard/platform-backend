"""The first parser that produces a vulnerability (#108's missing input).

Nuclei has run against the pinned template pack for a while — the Collector's
own CLI said so and then threw the output away: *"no evidence is attached. The
job still completes for real."* So the platform held 69 evidence packages and
**zero findings**, while CA-09V, which is built on vulnerability input, had
none at all.

Nothing downstream needed building. `risk_intelligence_normalization_service`
has read a host record's ``findings`` list since it was written
(``_FINDING_KEYS``); only the parser was missing.
"""

from __future__ import annotations

import json

from src.core.services.discovery_execution_evidence_adapter import (
    SUPPORTED_EVIDENCE_PARSER_KEYS,
    _parse_nuclei_jsonl,
)


def jsonl(*entries: dict) -> bytes:
    return ("\n".join(json.dumps(entry) for entry in entries)).encode("utf-8")


LOG4J = {
    "template-id": "CVE-2021-44228",
    "type": "http",
    "host": "https://billing.example.com",
    "matched-at": "https://billing.example.com/api",
    "ip": "10.0.0.4",
    "info": {
        "name": "Apache Log4j2 Remote Code Execution",
        "severity": "critical",
        "description": "Log4j2 JNDI features do not protect against attacker-controlled LDAP.",
        "classification": {"cve-id": ["CVE-2021-44228"], "cvss-score": 10.0},
    },
}


def test_the_parser_is_registered_so_a_package_is_actually_dispatched_to_it():
    # A registered parser that nothing selects is how Subfinder's sat unused
    # while every Subfinder package stayed pending forever.
    assert ("json", "nuclei") in SUPPORTED_EVIDENCE_PARSER_KEYS


def test_a_finding_carries_the_owning_tool_s_own_words():
    [host] = _parse_nuclei_jsonl(jsonl(LOG4J))

    assert host["hostname"] == "billing.example.com"
    assert host["ip"] == "10.0.0.4"
    [finding] = host["findings"]
    assert finding["severity"] == "critical"
    assert finding["name"] == "Apache Log4j2 Remote Code Execution"
    assert finding["cve_ids"] == ["CVE-2021-44228"]
    assert finding["cvss_score"] == 10.0


def test_the_url_is_not_stored_as_a_hostname():
    """`https://x/a` and `https://x/b` are one host.

    A target is a URL for an http template. Storing it as a hostname is how a
    name that is not a name gets into an inventory an executive approves.
    """
    [host] = _parse_nuclei_jsonl(
        jsonl(
            LOG4J,
            {**LOG4J, "template-id": "exposed-env", "matched-at": "https://billing.example.com/.env",
             "info": {"name": "Exposed .env", "severity": "high"}},
        )
    )

    assert host["hostname"] == "billing.example.com"
    assert len(host["findings"]) == 2


def test_severity_is_never_invented():
    """A template without a severity is left to the normaliser's default.

    Guessing one here would put a judgement the tool did not make into a field
    that reads as though it did.
    """
    [host] = _parse_nuclei_jsonl(jsonl({**LOG4J, "info": {"name": "Something"}}))

    assert "severity" not in host["findings"][0]


def test_one_bad_line_does_not_discard_the_scan():
    raw = b"\n".join([json.dumps(LOG4J).encode(), b"{not json", b"", json.dumps(
        {**LOG4J, "host": "https://crm.example.com", "ip": None, "matched-at": "https://crm.example.com/"}
    ).encode()])

    hosts = _parse_nuclei_jsonl(raw)

    assert sorted(host["hostname"] for host in hosts) == ["billing.example.com", "crm.example.com"]


def test_the_same_template_at_the_same_place_is_one_finding():
    [host] = _parse_nuclei_jsonl(jsonl(LOG4J, LOG4J))

    assert len(host["findings"]) == 1


def test_a_port_is_dropped_from_the_host():
    [host] = _parse_nuclei_jsonl(jsonl({**LOG4J, "host": "billing.example.com:8443", "ip": None}))
    assert host["hostname"] == "billing.example.com"
    assert host["ip"] is None


def test_an_address_is_recorded_as_an_address_and_never_as_a_name():
    """🐞 The duplicate-artefact bug, at its source.

    A bare IP used to be written into `hostname`, which made it a *strong*
    identifier no existing artefact carried — so identity resolution missed at
    step 1 and never reached the weak address match that would have found the
    host immediately. Every scan therefore minted a new artefact and a conflict
    for a person to resolve.
    """
    [v4] = _parse_nuclei_jsonl(jsonl({**LOG4J, "host": "192.168.50.152", "ip": None}))
    assert v4["hostname"] is None
    assert v4["ip"] == "192.168.50.152"


def test_an_ipv6_address_loses_the_url_brackets():
    """`[2001:db8::1]` is how the address is written inside a URL. Keeping the
    brackets would stop the host matching itself when nmap reports it plainly."""
    [v6] = _parse_nuclei_jsonl(jsonl({**LOG4J, "host": "[2001:db8::1]:443", "ip": None}))
    assert v6["hostname"] is None
    assert v6["ip"] == "2001:db8::1"


def test_a_vulnerability_observation_says_it_cannot_establish_identity():
    """A scan pointed at hosts discovery already found cannot be the thing that
    proves one exists. Normalisation reads this and refuses to create an
    artefact from it."""
    [host] = _parse_nuclei_jsonl(jsonl({**LOG4J, "host": "192.168.50.152", "ip": None}))
    assert host["establishesIdentity"] is False


def test_a_scan_that_found_nothing_produces_no_hosts():
    # "We scanned and found nothing" is a real outcome and not an asset —
    # BUG-DISC-14's ruling, which this parser must not undo.
    assert _parse_nuclei_jsonl(b"") == []
    assert _parse_nuclei_jsonl(b"\n\n") == []

"""CA-09V — the one judgement that decides 82% of a nuclei scan's runtime.

Counted on the live Collector's pinned v10.4.7 pack, 2026-09-07: 13,510
templates, of which ``http`` is 11,137. Skipping that tree on a host with no web
server is the difference between a scan that finishes and the 606-second,
zero-byte run this work exists to fix.

Because the saving is that large, the risk is symmetrical: a rule that skipped
``http`` on a host that *does* serve HTTP would hide real vulnerabilities while
reporting a completed scan. So the negative cases here matter more than the
positive ones, and the service shapes are taken from this organisation's own
fingerprint data rather than invented.
"""

from __future__ import annotations

import pytest

from src.core.services.discovery_template_scoping import (
    BASELINE_TREES,
    HTTP_TREE,
    UNREACHABLE_TREES,
    scope_templates_for_host,
)


def _svc(port: int, service: str | None = None) -> dict:
    return {"port": port, "protocol": "tcp", "service": service}


# --- The tree lists themselves ---------------------------------------------


def test_the_baseline_and_http_trees_do_not_overlap() -> None:
    assert HTTP_TREE not in BASELINE_TREES


def test_unreachable_trees_are_never_scoped_in() -> None:
    """They are excluded on protocol grounds, not on evidence, so no fingerprint
    can bring them back. A remote host scan cannot match a cloud-API, local-file,
    code-analysis, DAST or headless template."""
    for services in ([], [_svc(80, "http")], [_svc(22, "ssh")], None):
        scope = scope_templates_for_host(services)
        assert not set(scope.trees) & set(UNREACHABLE_TREES)


# --- HTTP present: the tree must run ---------------------------------------


@pytest.mark.parametrize(
    "service_name",
    ["http", "https", "http-proxy", "https-alt", "http-alt", "ssl/http", "www"],
)
def test_a_named_http_service_runs_the_http_tree(service_name: str) -> None:
    """Every one of these appears in real nmap output; `https-alt`,
    `http-proxy` and `http` are all in this organisation's own scan data."""
    scope = scope_templates_for_host([_svc(9999, service_name)])
    assert scope.http_included
    assert HTTP_TREE in scope.trees


@pytest.mark.parametrize("port", [80, 443, 8080, 8443, 3000, 8888])
def test_a_known_http_port_runs_the_http_tree_even_when_unnamed(port: int) -> None:
    """A port nmap could not name is not evidence of absence. These are where a
    web server actually lives, so an unnamed service on one is treated as HTTP
    rather than scoped away."""
    scope = scope_templates_for_host([_svc(port, None)])
    assert scope.http_included, f"port {port} must not lose the http tree"


def test_one_http_service_among_many_is_enough() -> None:
    """The real pi-local fingerprint: ssh, http, https-alt, rpcbind, nagios."""
    scope = scope_templates_for_host(
        [
            _svc(22, "ssh"),
            _svc(80, "http"),
            _svc(111, "rpcbind"),
            _svc(5666, "nagios-nsca"),
            _svc(8443, "https-alt"),
        ]
    )
    assert scope.http_included


# --- HTTP absent: the tree is skipped, and it says so -----------------------


def test_a_host_with_no_web_server_skips_the_http_tree() -> None:
    scope = scope_templates_for_host([_svc(22, "ssh"), _svc(111, "rpcbind")])
    assert not scope.http_included
    assert HTTP_TREE not in scope.trees
    assert set(scope.trees) == set(BASELINE_TREES)


def test_a_skipped_http_tree_says_what_it_saw_instead() -> None:
    """The saving is invisible unless the scan says what it did not run. A
    silent 82% reduction is the same defect class as a timeout reported as a
    clean scan."""
    scope = scope_templates_for_host([_svc(22, "ssh"), _svc(111, "rpcbind")])
    assert "not run" in scope.reason
    assert "ssh" in scope.reason and "rpcbind" in scope.reason


def test_tcpwrapped_on_an_unremarkable_port_skips_http() -> None:
    """⚠️ The deliberate edge, and the one place a real web server could hide.

    `tcpwrapped` means nmap connected and the service never answered a probe —
    seen but unnamed. Under the ruling (skip what has no evidence) that is not
    evidence of HTTP. Four of this organisation's fourteen fingerprinted hosts
    are in exactly this state, so it is a live choice, not a hypothetical.
    """
    scope = scope_templates_for_host([_svc(4444, "tcpwrapped"), _svc(9100, "tcpwrapped")])
    assert not scope.http_included
    assert "tcpwrapped" in scope.reason


def test_tcpwrapped_on_a_web_port_still_runs_http() -> None:
    """The port rule is what stops the edge above from swallowing a web server
    that merely refused to answer nmap's probe."""
    scope = scope_templates_for_host([_svc(443, "tcpwrapped")])
    assert scope.http_included


# --- No fingerprint: never scope on a guess ---------------------------------


def test_a_host_never_fingerprinted_runs_the_full_reachable_pack() -> None:
    """An absence of evidence is not evidence of absence. Scoping down here
    would be exactly the guess the ruling forbids, so the host pays full price
    until fingerprinting has actually looked at it."""
    scope = scope_templates_for_host(None)
    assert scope.http_included
    assert "No service fingerprint" in scope.reason


def test_a_host_with_no_open_port_is_scoped_to_nothing() -> None:
    """⚠️ The branch that carries almost all of the runtime, and the one this
    rule got wrong first time by treating `[]` like `None`.

    An empty service list is a *positive* observation — nmap looked and found
    nothing open — not an unknown. Nuclei connects to ports, so with none open
    no template can match, and running the pack buys a guaranteed-empty result
    at full price. Measured on this organisation: 263 of 269 hosts.
    """
    scope = scope_templates_for_host([])
    assert scope.trees == ()
    assert not scope.http_included
    assert "no open port" in scope.reason


def test_nothing_open_and_never_looked_do_not_read_the_same() -> None:
    """The two are one character apart in the data and opposite in meaning."""
    never_looked = scope_templates_for_host(None)
    nothing_open = scope_templates_for_host([])
    assert never_looked.trees and not nothing_open.trees
    assert never_looked.reason != nothing_open.reason


def test_a_fingerprint_of_only_malformed_entries_is_treated_as_no_evidence() -> None:
    """Junk in the services list must not read as "no HTTP here" — that would
    turn a parsing failure into a silent coverage cut."""
    scope = scope_templates_for_host([{"port": None, "service": None}])
    assert not scope.http_included, (
        "an entry carrying neither a usable port nor a name is not HTTP evidence"
    )
    assert "nothing identifiable" in scope.reason


# --- Shapes the fingerprint really arrives in -------------------------------


def test_a_port_arriving_as_a_string_is_still_a_port() -> None:
    scope = scope_templates_for_host([{"port": "8080", "service": None}])
    assert scope.http_included


def test_a_non_dict_entry_does_not_crash_the_scope() -> None:
    """One malformed entry must never cost the whole host its scan."""
    scope = scope_templates_for_host(["nonsense", None, _svc(80, "http")])  # type: ignore[list-item]
    assert scope.http_included


def test_service_names_are_matched_case_insensitively() -> None:
    scope = scope_templates_for_host([_svc(9999, "HTTPS")])
    assert scope.http_included


def test_every_scope_carries_a_reason() -> None:
    """`reason` is what travels onto the scan result, so it is never optional."""
    for services in (None, [], [_svc(80, "http")], [_svc(22, "ssh")]):
        assert scope_templates_for_host(services).reason.strip()

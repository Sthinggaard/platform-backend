"""CA-08.2 — the engine reads what the Collector collected.

These tests moved here from the agent suite when Søren ruled that the Collector
stays naive (2026-08-24). They are the same assertions; what changed is which
side of the wire is allowed to reach the conclusion.

The distinction the whole module turns on: **only ssh's own exit 255 is a login
problem.** Any other non-zero status came from the far side, which means the
login worked — and reporting that as an authentication failure would send
somebody to rotate a key that works.
"""

from __future__ import annotations

import pytest

from src.core.constants.verification_inspection_enums import (
    INSPECTION_ARTEFACT_FACTS,
    InspectionOutcome,
)
from src.core.services.verification_outcome_service import classify_inspection_outcome


@pytest.mark.parametrize(
    "exit_code,stderr,expected",
    [
        (0, "", InspectionOutcome.SUCCEEDED),
        # ssh's own failures.
        (255, "risklence@db-01: Permission denied (publickey).", InspectionOutcome.AUTHENTICATION_FAILED),
        (255, "Host key verification failed.", InspectionOutcome.AUTHENTICATION_FAILED),
        (255, "Too many authentication failures", InspectionOutcome.AUTHENTICATION_FAILED),
        (255, "ssh: connect to host db-01 port 22: No route to host", InspectionOutcome.HOST_UNREACHABLE),
        (255, "ssh: connect to host db-01 port 22: Connection timed out", InspectionOutcome.HOST_UNREACHABLE),
        # Past the login, so these describe the host.
        (127, "bash: dpkg-query: command not found", InspectionOutcome.COMMAND_NOT_AVAILABLE),
        (1, "cat: /etc/shadow: Permission denied", InspectionOutcome.PERMISSION_DENIED_ON_HOST),
        (1, "cat: /etc/nginx/nginx.conf: No such file or directory", InspectionOutcome.COMMAND_FAILED),
        (2, "", InspectionOutcome.COMMAND_FAILED),
    ],
)
def test_an_attempt_is_classified_as_a_fact_about_the_host(exit_code, stderr, expected):
    assert classify_inspection_outcome(exit_code=exit_code, stderr=stderr) == expected.value


def test_a_remote_failure_is_never_read_as_a_login_failure():
    """The most expensive mistake this module can make.

    A remote command exiting non-zero got *in*. Calling that an authentication
    failure sends an operator to replace a credential that is working perfectly.
    """
    for exit_code, stderr in ((1, "cat: no such file"), (127, "command not found"), (2, "")):
        assert (
            classify_inspection_outcome(exit_code=exit_code, stderr=stderr)
            != InspectionOutcome.AUTHENTICATION_FAILED.value
        )


def test_a_missing_file_is_not_reported_as_a_missing_command():
    """Both say "no such file or directory"; they need different people.

    Matching that phrase for COMMAND_NOT_AVAILABLE would report a missing
    nginx.conf as a missing `cat`. Exit 127 already identifies a missing binary.
    """
    assert (
        classify_inspection_outcome(
            exit_code=1, stderr="cat: /etc/nginx/nginx.conf: No such file or directory"
        )
        == InspectionOutcome.COMMAND_FAILED.value
    )


def test_a_timeout_wins_over_whatever_else_was_captured():
    assert (
        classify_inspection_outcome(exit_code=None, stderr="", timed_out=True)
        == InspectionOutcome.TIMED_OUT.value
    )
    assert (
        classify_inspection_outcome(exit_code=255, stderr="Permission denied", timed_out=True)
        == InspectionOutcome.TIMED_OUT.value
    )


def test_no_result_at_all_is_not_claimed_as_anything_specific():
    assert (
        classify_inspection_outcome(exit_code=None, stderr="")
        == InspectionOutcome.HOST_UNREACHABLE.value
    )


def test_every_failure_outcome_describes_the_artefact_not_the_platform():
    """CA-08.2's criterion, as a property of the vocabulary itself.

    Every non-success outcome must be something an organisation can act on. A
    member appearing here that names a platform fault — ``internal_error``,
    ``engine_failure`` — would let a platform problem impersonate a fact about
    somebody's estate.
    """
    failures = {
        member.value
        for member in InspectionOutcome
        if member is not InspectionOutcome.SUCCEEDED
    }
    # TIMED_OUT is about the attempt rather than the artefact, and is named as
    # such rather than folded into the artefact facts.
    assert failures - {InspectionOutcome.TIMED_OUT.value} == set(INSPECTION_ARTEFACT_FACTS)


def test_the_collector_holds_no_copy_of_this_logic():
    """The naivety rule, asserted from the side that now owns the decision.

    Its twin lives in the agent suite. Both exist because the tempting fix for
    "the engine has not classified this yet" is to classify it on the Collector.
    """
    import ast
    from pathlib import Path

    # tests -> apps/server -> apps
    agent = Path(__file__).resolve().parents[2] / "scanner" / "scanner_agent" / "host_inspection.py"
    assert agent.exists(), agent

    # Parsed rather than grepped. The module's docstring names these outcomes
    # while explaining why they no longer live there, and a substring search
    # cannot tell that apart from the code coming back.
    tree = ast.parse(agent.read_text())
    outcomes = {member.value for member in InspectionOutcome}

    assigned_strings = {
        node.value.value
        for node in ast.walk(tree)
        if isinstance(node, ast.Assign) and isinstance(node.value, ast.Constant)
        and isinstance(node.value.value, str)
    }
    assert assigned_strings & outcomes == set(), assigned_strings & outcomes

    functions = {
        node.name for node in ast.walk(tree) if isinstance(node, ast.FunctionDef)
    }
    assert not [name for name in functions if "classif" in name], functions

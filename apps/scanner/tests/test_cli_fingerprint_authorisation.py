"""CA-07.1 slice 1 — the Collector reads its scan depth from the command
envelope's approved profile, never from a local setting.

`profile` is `run.profile_snapshot`, built by the server from the organisation's
approved `ScannerProfile`. A Collector-side switch would be a second, local
answer to a question the organisation has already decided — and could widen a
scan beyond what was approved with nothing recording that it happened.
"""

from scanner_agent.cli import _fingerprinting_approved


def test_an_approved_profile_authorises_fingerprinting():
    assert _fingerprinting_approved({"profile": {"allowsFingerprinting": True}}) is True


def test_a_profile_that_withholds_it_is_respected():
    assert _fingerprinting_approved({"profile": {"allowsFingerprinting": False}}) is False


def test_a_missing_profile_is_not_a_permissive_one():
    """An older server that sends no profile must get the old scan depth, not a
    deeper one nobody approved."""
    assert _fingerprinting_approved({}) is False
    assert _fingerprinting_approved({"profile": None}) is False


def test_a_malformed_profile_is_not_a_permissive_one():
    assert _fingerprinting_approved({"profile": "allowsFingerprinting"}) is False
    assert _fingerprinting_approved({"profile": []}) is False


def test_only_a_real_true_authorises():
    """A truthy string is how an authorisation check quietly stops meaning
    anything — the envelope is JSON from the network, not a Python literal."""
    assert _fingerprinting_approved({"profile": {"allowsFingerprinting": "false"}}) is False
    assert _fingerprinting_approved({"profile": {"allowsFingerprinting": 1}}) is False
    assert _fingerprinting_approved({"profile": {"allowsFingerprinting": None}}) is False

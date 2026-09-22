"""What a Collector must contain to be capable of its job at all.

#299. The image published to GHCR on 2026-07-19 shipped with five modules —
``api_client``, ``cli``, ``config``, ``nmap_runner``, ``tool_checks``. It was
missing ``command_signing``, so it could not verify a signed command and every
discovery it was handed was rejected; and missing ``nuclei_runner`` and
``subfinder_runner``, so it carried both binaries and could run neither.

The publish workflow's existing guard checks that the bundled **tools** are
present, and correctly reports ``nuclei_templates: MISSING`` for that image. What
it could not see is a *truncated agent package*: binaries on disk say nothing
about whether the code that drives them came along.

So the guard is completed here rather than widened there. A missing module is a
packaging failure, and packaging failures belong to a test that runs on every
change, not only to the smoke test of a release nobody may run for weeks.
"""

from __future__ import annotations

import importlib
import pkgutil

import pytest

import scanner_agent

#: Every module the platform depends on a Collector having, and what breaks
#: without it. Named individually rather than compared against a directory
#: listing: a list that regenerates itself from what is present cannot notice
#: that something is absent.
REQUIRED_MODULES = {
    "api_client": "nothing can be sent to or fetched from the platform",
    "cli": "there is no way to run it",
    "command_signing": "signed commands cannot be verified, so every discovery is rejected",
    "config": "the credential cannot be stored or read",
    "config_redaction": "a credential in configuration would be transmitted, not redacted",
    "health_checks": "readiness cannot be reported",
    "host_credentials": "there is no way to reach a host for deep verification",
    "host_inspection": "deep verification cannot run",
    "nmap_runner": "discovery cannot scan",
    "nuclei_runner": "the nuclei binary ships with nothing to drive it",
    "service": "it cannot be installed as a service",
    "subfinder_runner": "the subfinder binary ships with nothing to drive it",
    "system_info": "the Collector cannot describe the machine it runs on",
    "tool_checks": "tool validation cannot be reported, so it can never become ready",
}


@pytest.mark.parametrize("module,consequence", sorted(REQUIRED_MODULES.items()))
def test_the_agent_ships_every_module_it_needs(module: str, consequence: str):
    """A truncated package is a Collector that cannot do its job.

    The consequence is in the failure message on purpose: "module missing" is
    not actionable, and the reason each one matters is exactly what a person
    reading a red build needs.
    """
    present = {m.name for m in pkgutil.iter_modules(scanner_agent.__path__)}
    assert module in present, f"scanner_agent.{module} is missing — {consequence}"
    # Present on disk is not the same as importable.
    importlib.import_module(f"scanner_agent.{module}")


def test_signed_command_verification_is_actually_callable():
    """The single most consequential absence, asserted by behaviour.

    The published image did not merely lack this module — a Collector without it
    rejects every command the platform signs, which is discovery not working at
    all rather than working less well.
    """
    from scanner_agent.command_signing import verify_command, verify_inspection

    assert callable(verify_command)
    assert callable(verify_inspection)

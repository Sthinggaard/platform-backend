"""UX-DISC-06 — telling someone their Collector has stopped, and how to start it.

The architecture is deliberately unchanged: the Collector runs on customer
infrastructure and polls outbound, and Risklence never starts a process inside a
customer network. The only thing missing was the affordance for the one failure
a user cannot diagnose from the screen — which is why the tests that matter here
are about *what is not said*: no command where the user cannot run one, and no
restart advice for a Collector somebody deliberately stopped.
"""

from __future__ import annotations

import pytest

from src.core.constants.evidence_scanner_enums import ScannerInstallationMethod
from src.core.model_defs.evidence_scanner import ScannerInstance
from src.core.services.evidence_scanner_service import resolve_collector_restart_guidance


def _instance(**overrides) -> ScannerInstance:
    values = dict(
        name="collector-01",
        installation_method=ScannerInstallationMethod.DOCKER.value,
        os_name=None,
        architecture=None,
    )
    values.update(overrides)
    return ScannerInstance(**values)


class TestCommandMatchesTheInstall:
    @pytest.mark.parametrize(
        "method,expected",
        [
            (ScannerInstallationMethod.DOCKER.value, "docker start risklence-scanner"),
            (ScannerInstallationMethod.LOCAL_CLI.value, "risklence-scanner run"),
            (ScannerInstallationMethod.SERVER.value, "sudo systemctl start risklence-scanner"),
        ],
    )
    def test_each_install_method_gets_its_own_command(self, method, expected):
        # A generic instruction is not actionable: someone who installed via
        # Docker cannot run a CLI command, and being shown the wrong one costs
        # them the time it takes to find out it is wrong.
        assert resolve_collector_restart_guidance(_instance(installation_method=method)).command == expected

    def test_a_consultant_assisted_install_offers_no_command(self):
        # Printing a command they cannot run reads as "you have not done this"
        # rather than "this is not yours to do".
        guidance = resolve_collector_restart_guidance(
            _instance(installation_method=ScannerInstallationMethod.CONSULTANT_ASSISTED.value)
        )

        assert guidance.command is None
        assert guidance.self_service is False

    def test_an_unrecognised_install_method_is_not_guessed_at(self):
        # A wrong command sends someone to a terminal to be told the binary does
        # not exist — worse than saying plainly that we do not know.
        guidance = resolve_collector_restart_guidance(_instance(installation_method="something_new"))

        assert guidance.command is None

    def test_a_missing_install_method_does_not_crash_the_panel(self):
        assert resolve_collector_restart_guidance(_instance(installation_method="")).command is None


class TestNamingTheMachine:
    def test_the_machine_is_named_with_what_the_agent_reported(self):
        guidance = resolve_collector_restart_guidance(
            _instance(os_name="Ubuntu 24.04", architecture="aarch64")
        )

        assert guidance.host_label == "collector-01 (Ubuntu 24.04 · aarch64)"

    def test_it_degrades_to_the_name_rather_than_claiming_a_platform(self):
        # os_name/architecture are null until a heartbeat from an agent build
        # that reports them, and are never fabricated for older instances.
        assert resolve_collector_restart_guidance(_instance()).host_label == "collector-01"

    def test_partial_platform_information_is_still_used(self):
        guidance = resolve_collector_restart_guidance(_instance(os_name="Debian 12"))

        assert guidance.host_label == "collector-01 (Debian 12)"

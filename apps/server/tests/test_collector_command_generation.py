"""The exact commands the product hands an operator.

Søren, 2026-08-24: *"the message is useless i need to be able to do
something"*. A blocking reason a person cannot act on is the same as no reason
at all, so these are generated rather than described — and generated commands
need testing precisely because nobody reads them until they fail on somebody's
machine.
"""

from __future__ import annotations

from src.core.constants.evidence_scanner_enums import ScannerInstallationMethod
from src.core.services.evidence_scanner_service import (
    SCANNER_NETWORK_FLAGS,
    generate_activation_command,
    generate_collector_command,
)

DOCKER = ScannerInstallationMethod.DOCKER.value


class TestNetworkCapability:
    """Søren approved asking customers for NET_RAW on 2026-08-25, against the
    alternative of requesting SSH credentials to learn what an ARP reply gives
    free. The rule is that we ask for it only where it is used."""

    def test_a_scan_is_granted_the_network_it_needs_to_see(self):
        command = generate_collector_command("test-scan", installation_method=DOCKER)

        assert SCANNER_NETWORK_FLAGS in command
        assert command.startswith("docker run --rm --cap-add=NET_RAW --network host ")

    def test_a_local_self_check_is_not_granted_anything(self):
        """`validate-tools` touches nothing outside the container. Handing it a
        privilege it does not use would teach operators that Risklence asks for
        more than it needs — and the next request would be trusted less."""
        command = generate_collector_command("validate-tools", installation_method=DOCKER)

        assert "NET_RAW" not in command
        assert "--network" not in command

    def test_activation_is_not_granted_anything_either(self):
        command = generate_activation_command(activation_token="tok-1", installation_method=DOCKER)

        assert "NET_RAW" not in command

    def test_a_command_line_install_is_unchanged_by_any_of_this(self):
        """Capabilities are a container concept. A CLI install inherits whatever
        the operator's own account holds, and inventing docker flags for it
        would produce a command that cannot run."""
        assert generate_collector_command("test-scan") == "risklence-scanner test-scan"

    def test_the_volume_survives_the_new_flags(self):
        """Regression guard: the flags are inserted ahead of `-v`, and losing
        the named volume means the Collector activates and forgets on exit."""
        command = generate_collector_command("test-scan", installation_method=DOCKER)

        assert "-v risklence-scanner-data:/root/.risklence-scanner" in command


class TestWhichAddressTheCollectorIsToldToUse:
    """Moved here from `RiskScannerActivationGuide.test.tsx`, which used to
    compose the command itself. The rules did not disappear with that
    duplication — they belong beside `generate_activation_command`, which is
    now the only definition."""

    def test_a_docker_collector_is_given_the_containers_view_of_the_platform(self, monkeypatch):
        """127.0.0.1 inside a container means the container, not the host. A
        Docker Collector told to reach the API on loopback talks to itself."""
        from src.core.services import evidence_scanner_service as service

        monkeypatch.setattr(service.settings, "scanner_api_base_url", "http://127.0.0.1:8000", raising=False)
        monkeypatch.setattr(
            service.settings, "scanner_docker_api_base_url", "http://host.docker.internal:8000", raising=False
        )

        command = generate_activation_command(activation_token="tok-1", installation_method=DOCKER)

        assert "--base-url http://host.docker.internal:8000" in command

    def test_it_falls_back_to_the_public_origin_when_no_override_is_set(self, monkeypatch):
        """In production both are the public origin — a real hostname resolves
        identically inside and outside a container — so the override is only
        ever needed when the API and the Collector share a machine."""
        from src.core.services import evidence_scanner_service as service

        monkeypatch.setattr(service.settings, "scanner_api_base_url", "https://api.risklence.com", raising=False)
        monkeypatch.setattr(service.settings, "scanner_docker_api_base_url", None, raising=False)

        command = generate_activation_command(activation_token="tok-1", installation_method=DOCKER)

        assert "--base-url https://api.risklence.com" in command

    def test_a_command_line_install_is_always_told_the_public_origin(self, monkeypatch):
        """It runs on the operator's own machine, so the container override
        would send it somewhere that does not exist from there."""
        from src.core.services import evidence_scanner_service as service

        monkeypatch.setattr(service.settings, "scanner_api_base_url", "https://api.risklence.com", raising=False)
        monkeypatch.setattr(
            service.settings, "scanner_docker_api_base_url", "http://host.docker.internal:8000", raising=False
        )

        command = generate_activation_command(activation_token="tok-1")

        assert command == "risklence-scanner activate --base-url https://api.risklence.com --token tok-1"

"""CA-08.4 (#292) — verification determines identity where discovery could not.

The story this closes, in one line from a real discovery run::

    192.168.1.33 · Web service · Application · http, http-alt, http-proxy, ssh

Port 8080 reads ``http-proxy`` whether it is Plane, Jenkins or a coffee machine.
The test that matters most here is
``test_a_container_image_names_what_a_port_scan_could_not`` — that is #249,
answered.

The other load-bearing one is
``test_configuration_output_is_never_carried_before_redaction_exists``. Until
#296 lands, the output of ``read_service_config`` must not leave the Collector,
and "we chose not to look" must be distinguishable from "we looked and found
nothing".
"""

from __future__ import annotations

import json

import pytest

from src.core.constants.artefact_identity_evidence_enums import (
    IDENTITY_BASIS_PRECEDENCE,
    ArtefactIdentityBasis,
    ArtefactIdentityUndetermined,
)
from src.core.constants.permission_profile_enums import ConnectorCapability
from src.core.constants.verification_command_templates import (
    COMMAND_TEMPLATES,
    OUTPUT_SAFE_BEFORE_REDACTION,
)
from src.core.services.verification_identity_service import identity_from_inspection

OS_VERSION = ConnectorCapability.READ_OS_VERSION.value
SOCKETS = ConnectorCapability.READ_LISTENING_SOCKET_OWNER.value
INSPECT = ConnectorCapability.INSPECT_CONTAINER.value
LIST_CONTAINERS = ConnectorCapability.LIST_CONTAINERS.value
PACKAGES = ConnectorCapability.READ_INSTALLED_PACKAGES.value


# --- #249, answered --------------------------------------------------------


def test_a_container_image_names_what_a_port_scan_could_not():
    """The whole point of the epic.

    Discovery saw ``http-proxy`` on 8080. The image says what it actually is.
    """
    output = json.dumps(
        [{"Id": "abc123", "Config": {"Image": "makeplane/plane-frontend:v0.23.1"}}]
    )
    identity = identity_from_inspection(capability=INSPECT, stdout=output)

    assert identity.determined
    assert identity.name == "makeplane/plane-frontend:v0.23.1"
    assert identity.basis == ArtefactIdentityBasis.CONTAINER_IMAGE.value


def test_the_process_holding_the_port_names_a_service_not_in_a_container():
    output = 'LISTEN 0 511 0.0.0.0:8080 0.0.0.0:* users:(("nginx",pid=1234,fd=6))'
    identity = identity_from_inspection(capability=SOCKETS, stdout=output)

    assert identity.name == "nginx"
    assert identity.basis == ArtefactIdentityBasis.LISTENING_PROCESS.value


def test_a_proxy_holding_the_port_is_not_treated_as_the_answer():
    """``docker-proxy`` looks like an answer and tells a person nothing.

    Recording it would satisfy "identity determined" while leaving the reader
    exactly where they started — which is the failure #249 describes.
    """
    output = 'LISTEN 0 4096 0.0.0.0:8080 0.0.0.0:* users:(("docker-proxy",pid=900,fd=4))'
    identity = identity_from_inspection(capability=SOCKETS, stdout=output)

    assert not identity.determined
    assert identity.undetermined_reason == (
        ArtefactIdentityUndetermined.VERIFIED_NOTHING_IDENTIFYING.value
    )


def test_a_bare_digest_is_not_an_identity():
    """Docker reports a digest for an untagged image. It names nothing readable."""
    output = json.dumps([{"Config": {"Image": "sha256:9f2a4c1e77b3"}}])
    assert not identity_from_inspection(capability=INSPECT, stdout=output).determined


def test_os_release_names_the_host_when_nothing_else_did():
    output = 'PRETTY_NAME="Debian GNU/Linux 12 (bookworm)"\nNAME="Debian GNU/Linux"\n'
    identity = identity_from_inspection(capability=OS_VERSION, stdout=output)

    assert identity.name == "Debian GNU/Linux 12 (bookworm)"
    assert identity.basis == ArtefactIdentityBasis.OS_RELEASE.value


# --- An empty result is a finding, not a gap -------------------------------


def test_verification_that_establishes_nothing_says_so():
    """CA-08.4's own words, and the reason this has its own reason code.

    "We went inside, with approval, and it still would not say" must not be
    reported as "nobody has looked closely" — that would invite asking for the
    approval somebody already gave.
    """
    identity = identity_from_inspection(capability=OS_VERSION, stdout="")

    assert not identity.determined
    assert identity.undetermined_reason == (
        ArtefactIdentityUndetermined.VERIFIED_NOTHING_IDENTIFYING.value
    )
    assert "from the inside" in identity.explanation


def test_a_capability_that_reads_something_real_but_names_nothing():
    """The package list is evidence. It is not an identity, and does not pretend."""
    identity = identity_from_inspection(
        capability=PACKAGES, stdout="nginx\t1.22.1\nopenssl\t3.0.11\n"
    )
    assert not identity.determined


def test_unparseable_output_is_undetermined_rather_than_an_error():
    """A host can return anything. None of it may raise."""
    for capability in (INSPECT, LIST_CONTAINERS, SOCKETS, OS_VERSION):
        identity = identity_from_inspection(capability=capability, stdout="}{ not json \x00")
        assert not identity.determined


# --- Precedence -------------------------------------------------------------


def test_verified_evidence_outranks_anything_read_from_the_network():
    """Otherwise deep verification costs a decision and changes nothing visible.

    A web page can title itself anything; the image a container was built from
    cannot.
    """
    order = [basis.value for basis in IDENTITY_BASIS_PRECEDENCE]

    for verified in (
        ArtefactIdentityBasis.CONTAINER_IMAGE,
        ArtefactIdentityBasis.LISTENING_PROCESS,
        ArtefactIdentityBasis.OS_RELEASE,
    ):
        for networked in (
            ArtefactIdentityBasis.HTTP_TITLE,
            ArtefactIdentityBasis.TLS_CERTIFICATE,
            ArtefactIdentityBasis.SERVICE_PRODUCT,
            ArtefactIdentityBasis.HARDWARE_VENDOR,
        ):
            assert order.index(verified.value) < order.index(networked.value)


def test_every_basis_is_ranked():
    """A basis missing from the precedence tuple can never win, silently."""
    assert {basis.value for basis in ArtefactIdentityBasis} == {
        basis.value for basis in IDENTITY_BASIS_PRECEDENCE
    }


# --- Redaction boundary -----------------------------------------------------


def test_configuration_output_is_carried_only_because_it_is_redacted_first():
    """This assertion was the reverse until #296, and the change is the story.

    Deployed configuration is where credentials live, so its output stayed on
    the Collector while there was no way to strip them. It is carried now
    because ``scanner_agent/config_redaction.py`` removes the values *before*
    the wire — CA-07.2 means the platform cannot receive one, so redacting here
    would already be too late.

    Its membership therefore depends on code in another package entirely, which
    is why it is asserted from both sides.
    """
    assert ConnectorCapability.READ_SERVICE_CONFIG.value in OUTPUT_SAFE_BEFORE_REDACTION


def test_the_process_table_output_is_still_not_carried():
    """``ps`` output carries command lines, and command lines carry passwords.

    Not solved by #296 and deliberately left out: redacting a command line is
    not the decidable key-based problem a configuration file is. ``--password=x``
    has a key; ``mysql -phunter2`` does not, and neither does an argument whose
    meaning depends on the program reading it.
    """
    assert (
        ConnectorCapability.READ_RUNNING_PROCESSES.value not in OUTPUT_SAFE_BEFORE_REDACTION
    )


def test_the_allow_list_only_names_capabilities_that_can_actually_run():
    """A capability on the list with no command is a rule nothing enforces."""
    for capability in OUTPUT_SAFE_BEFORE_REDACTION:
        assert capability in COMMAND_TEMPLATES, capability


def test_a_language_runtime_is_not_an_identity():
    """Found by running this against a real host, not by imagining a case.

    A box running Plane, Immich and Grafana identified itself as "java" — true,
    and exactly as useless as the ``http-proxy`` that #249 was raised about. It
    also *replaced* a good "Debian GNU/Linux 13 (trixie)", because
    LISTENING_PROCESS outranks OS_RELEASE: precedence ranks classes of evidence
    and cannot rank how informative one instance happens to be, so uninformative
    ones must never enter as answers.
    """
    for runtime in ("java", "python3", "node", "gunicorn", "beam.smp", "sh"):
        output = f'LISTEN 0 511 0.0.0.0:8080 0.0.0.0:* users:(("{runtime}",pid=1,fd=6))'
        identity = identity_from_inspection(capability=SOCKETS, stdout=output)
        assert not identity.determined, runtime


def test_an_informative_process_later_in_the_list_still_wins():
    """A runtime on the first line must not hide a real name on the second."""
    output = (
        'LISTEN 0 511 0.0.0.0:8080 0.0.0.0:* users:(("java",pid=1,fd=6))\n'
        'LISTEN 0 511 0.0.0.0:443 0.0.0.0:* users:(("nginx",pid=2,fd=7))'
    )
    identity = identity_from_inspection(capability=SOCKETS, stdout=output)
    assert identity.name == "nginx"

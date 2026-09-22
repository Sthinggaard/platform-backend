"""BUG-DISC-15 — a discovered artefact is classified from evidence, or not at all.

The rule this replaces recorded whether the scan found ports, not what the thing
is: any open port meant "Application", none meant "Network", and `type` read a
key nmap never emits so every artefact was a "Service". Søren's own router,
answering DNS and serving a web admin page, came out as "Service · Application".
"""

from __future__ import annotations

import pytest

from src.core.constants.osi import OSILayer, layer_short_label
from src.core.services.artefact_classification_service import (
    ArtefactCandidacy,
    ArtefactType,
    ObservedService,
    classify_host_record,
    derive_candidacy,
)


def _host(*service_names: str) -> dict:
    return {"ip": "192.168.1.1", "services": [{"service": n} for n in service_names]}


# --- the motivating case ---------------------------------------------------------------


def test_a_host_answering_dns_and_serving_a_web_page_is_not_called_an_application():
    """Søren's router. DNS says network infrastructure, HTTP says application —
    a router with an admin page and a web server that also runs DNS look
    identical from outside, so neither is asserted. What is *not* in doubt is
    that a host is there, and the services it answered on go on the row."""
    result = classify_host_record(_host("domain", "http", "https"))

    assert result.asset_type == "Observed host"
    assert result.layer == OSILayer.L1_PHYSICAL.value
    assert result.observed == ("domain", "http", "https")


def test_open_ports_alone_never_make_something_an_application():
    """The old rule's entire logic: has ports -> Application."""
    result = classify_host_record(_host("sip", "rtsp"))

    assert result.asset_type == "Observed host"
    assert result.layer == OSILayer.L1_PHYSICAL.value
    # Unrecognised is not unknowable — the reviewer still gets the evidence.
    assert result.observed == ("rtsp", "sip")


def test_a_host_with_nothing_open_is_still_a_host():
    """The old rule called this "Network". Calling it "Unknown" was no better —
    something answered, so a host is there; it just is not doing anything we can
    see."""
    result = classify_host_record({"ip": "192.168.1.11", "services": []})

    assert result.asset_type == "Observed host"
    assert result.layer == OSILayer.L1_PHYSICAL.value
    assert result.observed == ()


# --- what the evidence does support ------------------------------------------------------


def test_a_web_server_is_classified_from_its_own_services():
    result = classify_host_record(_host("http", "https"))

    # The canonical OSILayer id is what gets stored; turning it into a name is
    # the reading side's job.
    assert (result.layer, result.asset_type) == (OSILayer.L5_APPLICATION.value, "Web service")
    assert result.observed == ("http", "https")


def test_an_administrative_path_does_not_decide_what_a_host_is():
    """SSH sits on almost everything. A database server is a database, not a
    remote-access endpoint, because someone can log into it."""
    result = classify_host_record(_host("postgresql", "ssh"))

    assert (result.layer, result.asset_type) == (OSILayer.L6_DATA.value, "Database")
    # Observed lists everything seen, including the administrative path that
    # did not decide the class.
    assert result.observed == ("postgresql", "ssh")


def test_an_administrative_path_is_still_reported_when_it_is_all_there_is():
    """Real and useful — something is reachable and manageable — and it is all
    the evidence supports."""
    result = classify_host_record(_host("ssh"))

    # A host you can log into is infrastructure; SSH says a machine is there,
    # not what it is for.
    assert (result.layer, result.asset_type) == (OSILayer.L1_PHYSICAL.value, "Remote access")


@pytest.mark.parametrize(
    ("services", "expected"),
    [
        (("snmp",), (OSILayer.L2_NETWORK.value, "Network device")),
        (("ldap",), (OSILayer.L7_GOVERNANCE.value, "Identity service")),
        (("mongodb",), (OSILayer.L6_DATA.value, "Database")),
    ],
)
def test_single_purpose_hosts_are_classified(services, expected):
    result = classify_host_record(_host(*services))

    assert (result.layer, result.asset_type) == expected


# --- honesty about the answer -------------------------------------------------------------


def test_a_generic_class_still_carries_the_evidence_behind_it():
    """The whole point of the floor: "Observed host · Infrastructure" alone is
    close to useless, and it is the observed services that make the row worth
    reading."""
    assert classify_host_record(_host("sip")).observed == ("sip",)


def test_malformed_evidence_does_not_crash_a_normalisation():
    """Host records are free-form JSON assembled from scanner output."""
    for malformed in ({"services": "not-a-list"}, {"services": [None, 42, {"service": None}]}, {}):
        result = classify_host_record(malformed)
        assert result.asset_type == "Observed host"
        assert result.observed == ()


# --- the stored value and the shown value are different things ----------------------------


def test_every_layer_a_classification_can_produce_renders_as_a_name():
    """A row must never show "L5". Each id the classifier can emit resolves to a
    short name, and Unknown stays Unknown."""
    for services, expected_name in [
        (("http",), "Application"),
        (("mysql",), "Data"),
        (("snmp",), "Network"),
        (("ldap",), "Governance"),
        (("ssh",), "Infrastructure"),
        (("sip",), "Infrastructure"),
    ]:
        result = classify_host_record(_host(*services))
        assert layer_short_label(result.layer) == expected_name, services


def test_a_legacy_free_text_layer_still_renders_rather_than_breaking_the_row():
    """This column held words before the canonical ids, and those rows are still
    in the database."""
    assert layer_short_label("Hardware") == "Hardware"


class TestCandidacy:
    """Can a business service depend on this at all?

    The rule that makes a 500-artefact estate reviewable, so the cases that
    matter most are the ones where getting it wrong hides something real.
    """

    def test_a_host_with_nothing_listening_cannot_be_depended_on(self):
        # The single biggest reduction on a real estate: most of what a scan
        # finds are devices that answered and expose nothing.
        assert derive_candidacy([]) is ArtefactCandidacy.ENDPOINT

    def test_a_web_server_is_service_bearing(self):
        assert derive_candidacy(["http", "https"]) is ArtefactCandidacy.SERVICE_BEARING

    def test_a_dns_server_is_service_bearing_even_though_it_is_infrastructure(self):
        # "Can something depend on this?" is not the same question as "what is
        # it?" — a gateway serving DNS is depended on by everything.
        assert derive_candidacy(["domain"]) is ArtefactCandidacy.SERVICE_BEARING

    def test_a_printer_is_an_endpoint(self):
        assert derive_candidacy(["ipp", "printer"]) is ArtefactCandidacy.ENDPOINT

    def test_a_host_reachable_only_over_ssh_is_not_called_an_endpoint(self):
        # It could be a jump host, which is a real dependency. Hiding it would
        # be worse than leaving it in the list.
        assert derive_candidacy(["ssh"]) is ArtefactCandidacy.UNDETERMINED

    def test_an_unrecognised_listening_service_is_not_called_an_endpoint(self):
        # A wrong ENDPOINT hides a dependency behind a collapsed section; a
        # wrong UNDETERMINED only leaves a row on screen a moment longer.
        assert derive_candidacy(["some-vendor-daemon"]) is ArtefactCandidacy.UNDETERMINED

    def test_one_real_service_outweighs_endpoint_signatures(self):
        # A workstation that also serves an application is still something that
        # can be depended on.
        assert derive_candidacy(["mdns", "ipp", "http"]) is ArtefactCandidacy.SERVICE_BEARING

    def test_an_endpoint_signature_beside_an_admin_path_stays_an_endpoint_only_if_all_agree(self):
        # ssh is neither a purpose service nor an endpoint signature, so this
        # cannot be claimed as an endpoint.
        assert derive_candidacy(["mdns", "ssh"]) is ArtefactCandidacy.UNDETERMINED

    def test_service_names_are_matched_regardless_of_case_or_padding(self):
        assert derive_candidacy(["  HTTP  "]) is ArtefactCandidacy.SERVICE_BEARING

    def test_malformed_evidence_cannot_crash_a_discovery_run(self):
        assert derive_candidacy(["", "   "]) is ArtefactCandidacy.ENDPOINT

    def test_classification_carries_the_candidacy_it_derived(self):
        result = classify_host_record({"services": [{"service": "postgresql"}]})
        assert result.candidacy == ArtefactCandidacy.SERVICE_BEARING.value

    def test_a_host_whose_purpose_evidence_conflicts_is_still_depend_able(self):
        # The class falls back to the floor because DNS and web disagree, but
        # both are things something can depend on — candidacy must not inherit
        # the classifier's uncertainty about *what* it is.
        result = classify_host_record(
            {"services": [{"service": "domain"}, {"service": "http"}]}
        )
        assert result.asset_type == ArtefactType.OBSERVED_HOST.value
        assert result.candidacy == ArtefactCandidacy.SERVICE_BEARING.value


# --- #249: what a service name is actually a claim about ------------------------------


class TestObservedServiceEvidence:
    """A name nmap read out of its port-number table is a restatement of the
    port number. Rendered beside a name it *probed*, a guess reaches a reviewer
    in the same voice as a finding — the defect #249 was raised for. The
    classification carries the distinction so the reading side can keep it."""

    def test_a_probed_port_and_a_looked_up_one_are_not_the_same_claim(self):
        result = classify_host_record(
            {
                "services": [
                    {"port": 8080, "service": "http-proxy", "method": "table"},
                    {"port": 443, "service": "https", "method": "probed"},
                ]
            }
        )

        assert result.observed_evidence == (
            ObservedService(name="http-proxy", port=8080, probed=False),
            ObservedService(name="https", port=443, probed=True),
        )

    def test_evidence_is_kept_per_port_where_the_names_are_de_duplicated(self):
        # `observed` answers "what is this thing", so one `http` is enough.
        # Evidence answers "where do I go and look", and two ports serving the
        # web are two places.
        result = classify_host_record(
            {
                "services": [
                    {"port": 80, "service": "http", "method": "probed"},
                    {"port": 8080, "service": "http", "method": "probed"},
                ]
            }
        )

        assert result.observed == ("http",)
        assert [item.port for item in result.observed_evidence] == [80, 8080]

    def test_an_evidence_document_that_never_recorded_the_method_claims_no_probe(self):
        # Every unknown in this domain resolves downward: never claim a probe
        # that cannot be shown to have happened.
        result = classify_host_record({"services": [{"port": 22, "service": "ssh"}]})

        assert result.observed_evidence == (ObservedService(name="ssh", port=22, probed=False),)

    def test_a_port_number_nmap_did_not_record_is_reported_as_missing(self):
        result = classify_host_record({"services": [{"service": "https", "method": "probed"}]})

        assert result.observed_evidence == (ObservedService(name="https", port=None, probed=True),)

    def test_malformed_evidence_cannot_crash_a_discovery_run(self):
        result = classify_host_record(
            {
                "services": [
                    "not-a-dict",
                    {"port": 80},
                    {"service": "   ", "port": 81},
                    {"service": "HTTPS", "port": 443, "method": "probed"},
                ]
            }
        )

        assert result.observed_evidence == (ObservedService(name="https", port=443, probed=True),)

    def test_a_host_with_nothing_open_carries_no_evidence(self):
        assert classify_host_record({"services": []}).observed_evidence == ()

    def test_the_evidence_survives_every_classification_outcome(self):
        # Three separate returns compose an ArtefactClassification — the floor,
        # a single match, and a conflict. A reviewer's evidence must not depend
        # on which one the host happened to take.
        service = {"port": 53, "service": "domain", "method": "probed"}
        conflicting = {"port": 443, "service": "https", "method": "probed"}

        floor = classify_host_record({"services": [{"port": 22, "service": "ssh", "method": "probed"}]})
        matched = classify_host_record({"services": [service]})
        conflicted = classify_host_record({"services": [service, conflicting]})

        assert floor.observed_evidence and matched.observed_evidence
        assert len(conflicted.observed_evidence) == 2

"""CA-07.1 slice 1 — naming an artefact from scan evidence, and saying honestly
when it cannot be named.

The regression these tests exist for is a real discovery run in which one host
was a Plane instance and another a monitoring dashboard, and the surface rendered
them identically because every chip on the row was an nmap port-number nickname.
"""

from src.core.constants.artefact_identity_evidence_enums import (
    ArtefactIdentityBasis,
    ArtefactIdentityUndetermined,
)
from src.core.services.artefact_identity_evidence_service import determine_identity, stored_identity


def _host(services=None, **extra):
    return {"hostname": None, "ip": "192.168.1.33", "services": services or [], "findings": [], **extra}


def _web_port(port=8080, **extra):
    base = {"port": port, "protocol": "tcp", "service": "http-proxy", "product": None, "version": None}
    base.update(extra)
    return base


# --- The case that started this ------------------------------------------


def test_plane_and_a_monitor_on_adjacent_addresses_are_told_apart():
    """The original defect: both were 'Web service · Application · http-proxy'."""
    plane = determine_identity(_host([_web_port(scripts={"http-title": "Plane"})]))
    monitor = determine_identity(_host([_web_port(port=3000, scripts={"http-title": "Grafana"})]))

    assert plane.name == "Plane"
    assert monitor.name == "Grafana"
    assert plane.name != monitor.name


# --- Precedence ------------------------------------------------------------


def test_http_title_wins_over_the_web_server_it_runs_on():
    """`-sV` sees nginx; the title sees the application. The application is the
    answer to 'what is this?' — the reverse proxy in front of it is not."""
    identity = determine_identity(
        _host([_web_port(product="nginx", version="1.25.3", scripts={"http-title": "Plane"})])
    )
    assert identity.name == "Plane"
    assert identity.basis == ArtefactIdentityBasis.HTTP_TITLE.value


def test_certificate_names_the_host_when_no_title_is_served():
    identity = determine_identity(
        _host(
            [
                _web_port(
                    port=443,
                    service="https",
                    scripts={"ssl-cert": "Subject: commonName=vault.internal.example.com\nIssuer: ..."},
                )
            ]
        )
    )
    assert identity.name == "vault.internal.example.com"
    assert identity.basis == ArtefactIdentityBasis.TLS_CERTIFICATE.value


def test_product_and_version_name_a_non_web_service():
    identity = determine_identity(
        _host([{"port": 5432, "service": "postgresql", "product": "PostgreSQL DB", "version": "15.4"}])
    )
    assert identity.name == "PostgreSQL DB 15.4"
    assert identity.basis == ArtefactIdentityBasis.SERVICE_PRODUCT.value


def test_hardware_vendor_names_a_host_with_nothing_listening():
    """The 'Also on the network' bucket: 11 rows that read only as an IP. A
    vendor OUI does not say what the box does, but 'HP device' is something a
    person can decide about and '192.168.1.45' is not."""
    identity = determine_identity(_host(vendor="Hewlett Packard"))
    assert identity.name == "Hewlett Packard"
    assert identity.basis == ArtefactIdentityBasis.HARDWARE_VENDOR.value


# --- Titles that are not names ---------------------------------------------


def test_an_error_page_title_is_not_an_identity():
    """'502 Bad Gateway' looks like an identity and is a transient condition —
    it would be wrong the moment the service recovered."""
    identity = determine_identity(_host([_web_port(scripts={"http-title": "502 Bad Gateway"})]))
    assert identity.name is None


def test_a_default_server_page_is_not_an_identity():
    identity = determine_identity(_host([_web_port(scripts={"http-title": "Welcome to nginx!"})]))
    assert identity.name is None


def test_nmap_redirect_commentary_is_not_part_of_the_name():
    identity = determine_identity(
        _host([_web_port(scripts={"http-title": "Plane (request redirected to /login)"})])
    )
    assert identity.name == "Plane"


def test_a_certificate_subject_that_is_an_ip_names_nothing_new():
    identity = determine_identity(
        _host([_web_port(port=443, scripts={"ssl-cert": "Subject: commonName=192.168.1.33"})])
    )
    assert identity.name is None


# --- The distinction CA-07.1 depends on ------------------------------------


def test_nothing_listening_is_not_a_case_for_deeper_access():
    identity = determine_identity(_host([]))
    assert identity.undetermined_reason == ArtefactIdentityUndetermined.NOTHING_LISTENING.value


def test_a_host_that_was_never_probed_says_so_rather_than_unknown():
    """The failure this prevents: telling a person 'we cannot determine what
    this is, grant SSH access' about a host that would answer its own name over
    an unauthenticated request, because version detection never ran."""
    identity = determine_identity(_host([_web_port()]), fingerprinting_ran=False)
    assert identity.undetermined_reason == ArtefactIdentityUndetermined.NOT_PROBED.value
    assert "has not been examined closely enough" in identity.explanation


def test_a_probed_host_that_yields_nothing_is_the_genuine_remainder():
    identity = determine_identity(
        _host([{"port": 9000, "service": "cslistener", "product": None, "scripts": {}}]),
        fingerprinting_ran=True,
    )
    assert identity.undetermined_reason == ArtefactIdentityUndetermined.PROBED_NOTHING_IDENTIFYING.value


def test_an_unknown_scan_depth_never_claims_the_host_was_probed():
    """Inference may only ever under-claim: guessing 'probed' would manufacture
    an argument for credentials nobody established was needed."""
    identity = determine_identity(_host([_web_port()]))
    assert identity.undetermined_reason == ArtefactIdentityUndetermined.NOT_PROBED.value


# --- #249 slice 2: the scan's own record is preferred to the guess -----------


def test_a_recorded_probe_is_believed_over_the_downward_guess():
    """The whole point of slice 2. Before this, a host that was genuinely
    probed and yielded nothing came back as NOT_PROBED — because the guess
    reads 'no product anywhere' as 'nobody looked'. The scan now says what it
    did, and that is a fact rather than an inference."""
    identity = determine_identity(_host([_web_port()], fingerprinting_ran=True))
    assert identity.undetermined_reason == ArtefactIdentityUndetermined.PROBED_NOTHING_IDENTIFYING.value
    assert "was examined and answered" in identity.explanation


def test_a_recorded_shallow_scan_is_believed_too():
    identity = determine_identity(_host([_web_port()], fingerprinting_ran=False))
    assert identity.undetermined_reason == ArtefactIdentityUndetermined.NOT_PROBED.value


def test_an_explicit_argument_still_outranks_the_recorded_value():
    """A caller who knows from the approved profile keeps the last word — the
    recorded value fills the gap, it does not take over."""
    identity = determine_identity(_host([_web_port()], fingerprinting_ran=True), fingerprinting_ran=False)
    assert identity.undetermined_reason == ArtefactIdentityUndetermined.NOT_PROBED.value


def test_a_host_with_nothing_listening_is_unaffected_by_a_recorded_probe():
    """Probing an address where nothing answered does not make it a candidate
    for deeper access: there is still nothing there to reach."""
    identity = determine_identity(_host([], fingerprinting_ran=True))
    assert identity.undetermined_reason == ArtefactIdentityUndetermined.NOTHING_LISTENING.value


def test_a_determined_identity_carries_no_undetermined_reason():
    identity = determine_identity(_host([_web_port(scripts={"http-title": "Plane"})]))
    assert identity.determined is True
    assert identity.undetermined_reason is None
    assert identity.explanation is None


# --- Shape -----------------------------------------------------------------


def test_malformed_evidence_is_survived_rather_than_raised():
    """Scan evidence is authored by whatever answered on a customer network."""
    assert determine_identity({"services": "not-a-list"}).name is None
    assert determine_identity({"services": ["not-a-dict", None]}).name is None
    assert determine_identity({"services": [{"scripts": "not-a-dict"}]}).name is None
    assert determine_identity({}).undetermined_reason == ArtefactIdentityUndetermined.NOTHING_LISTENING.value


def test_whitespace_only_evidence_does_not_become_a_name():
    assert determine_identity(_host([_web_port(product="   ")], vendor="  ")).name is None


# --- nmap saying "there is no name" must never become the name ---------------


def test_a_page_with_no_title_does_not_become_the_artefacts_name():
    """Found on a real inventory, 2026-08-25: two artefacts were *named*
    "Site doesn't have a title (text/html)". That is nmap reporting the absence
    of a title, rendered as though it were one — worse than an unnamed row,
    because it looks like an answer."""
    identity = determine_identity(
        _host([_web_port(scripts={"http-title": "Site doesn't have a title (text/html)."})]),
        fingerprinting_ran=True,
    )
    assert identity.name is None
    assert identity.undetermined_reason == ArtefactIdentityUndetermined.PROBED_NOTHING_IDENTIFYING.value


def test_the_no_title_note_is_rejected_whatever_content_type_it_names():
    """nmap interpolates the content type, so no fixed-string list can catch
    them all — which is why the literal set missed this one."""
    for content_type in ("text/html", "text/html; charset=utf-8", "application/json"):
        identity = determine_identity(
            _host([_web_port(scripts={"http-title": f"Site doesn't have a title ({content_type})."})]),
            fingerprinting_ran=True,
        )
        assert identity.name is None, content_type


def test_a_real_title_that_merely_starts_with_digits_is_kept():
    """The filter must not overreach: dropping a real name is the one failure a
    guard against junk names must not introduce."""
    identity = determine_identity(_host([_web_port(scripts={"http-title": "404 Tech Blog"})]))
    assert identity.name == "404 Tech Blog"


# --- Reading back what was determined -------------------------------------
#
# One reader, because two surfaces ask the same question — the standing
# inventory and the discovery review list. An artefact reading "Unidentified
# device" on one page and `192.168.1.20` on the other is one record
# contradicting itself (#249).


def test_a_determined_identity_is_read_back_whole():
    resolved = stored_identity(
        {
            "networkAddress": "192.168.1.20",
            "identity": {
                "name": "Uvicorn",
                "basis": "service_product",
                "undeterminedReason": None,
                "explanation": None,
            },
        }
    )

    assert resolved == {
        "network_address": "192.168.1.20",
        "identity_name": "Uvicorn",
        "identity_basis": "service_product",
        "identity_undetermined_reason": None,
        "identity_explanation": None,
    }


def test_the_explanation_is_read_rather_than_recomposed():
    """It was written by `DeterminedIdentity` at ingestion. Rebuilding the
    sentence in a second place is how two versions of what the platform told
    somebody start to disagree."""
    sentence = "Nothing on this device identified itself when it was scanned."
    resolved = stored_identity(
        {"identity": {"name": None, "undeterminedReason": "probed_nothing_identifying", "explanation": sentence}}
    )

    assert resolved["identity_explanation"] == sentence
    assert resolved["identity_undetermined_reason"] == "probed_nothing_identifying"


def test_an_artefact_ingested_before_ca_07_1_reports_nothing_established():
    """`intent` is a JSON column that predates the identity block, so an older
    artefact simply has no such key. That must render as "we have not
    established this" rather than raise."""
    assert stored_identity({"observedServices": ["https"]}) == {
        "network_address": None,
        "identity_name": None,
        "identity_basis": None,
        "identity_undetermined_reason": None,
        "identity_explanation": None,
    }


def test_an_absent_or_malformed_intent_is_survived_rather_than_raised():
    for intent in (None, "not-a-dict", {"identity": "not-a-dict"}):
        assert stored_identity(intent)["identity_name"] is None


def test_a_blank_address_is_not_an_address():
    # Whitespace is not "where it sits", and rendering it would put an empty
    # chip on the row where a fact should be.
    assert stored_identity({"networkAddress": "   "})["network_address"] is None


# ── CA-09A.2 — "nothing is here" is not "we were not allowed to look" ────────


def test_a_silent_address_is_not_called_empty_when_we_could_not_look():
    """The conflation `NET_RAW` was approved to end. Nothing answered, and the
    Collector positively reported it cannot see hardware addresses — so
    HARDWARE_VENDOR, the only basis that can name a silent device, was
    unreachable by construction. Saying "nothing answered, so there was nothing
    to identify it by" would state as a finding what is really an admission."""
    identity = determine_identity({"ip": "10.0.0.5", "services": []}, hardware_addresses_visible=False)

    assert identity.name is None
    assert identity.undetermined_reason == ArtefactIdentityUndetermined.HARDWARE_NOT_VISIBLE.value
    assert "cannot see hardware addresses" in (identity.explanation or "")


def test_nobody_having_said_is_not_the_same_as_a_no():
    """`None` is a third answer. A Collector that has never reported its
    capability has not told us it cannot look, and upgrading that silence into
    "we could not look" is the same guess as the one this story removes, only
    pointing the other way."""
    identity = determine_identity({"ip": "10.0.0.6", "services": []})

    assert identity.undetermined_reason == ArtefactIdentityUndetermined.NOTHING_LISTENING.value


def test_the_capability_is_read_off_the_host_record_when_the_caller_is_silent():
    """The same ladder `fingerprinting_ran` climbs — the caller's word first,
    then what the evidence adapter recorded. The adapter stamps it once per
    package, since it is a property of the Collector rather than of a host."""
    identity = determine_identity(
        {"ip": "10.0.0.7", "services": [], "hardware_addresses_visible": False}
    )

    assert identity.undetermined_reason == ArtefactIdentityUndetermined.HARDWARE_NOT_VISIBLE.value


def test_a_vendor_names_a_device_that_answers_nothing():
    """The point of the whole story. A Sonos speaker with every port closed is
    unnameable by every other basis — no banner, no certificate, no page title,
    no product — and reads as a bare address forever. Its MAC vendor names it.

    The vendor string is real: taken from an ARP sweep of a live /24, where 10
    of the 12 devices holding a MAC resolved a vendor this way."""
    identity = determine_identity(
        {"ip": "192.168.50.31", "services": [], "vendor": "Sonos", "hardware_addresses_visible": True}
    )

    assert identity.name == "Sonos"
    assert identity.basis == ArtefactIdentityBasis.HARDWARE_VENDOR.value
    assert identity.undetermined_reason is None


# ── #324 — a name, not the sentence around it ───────────────────────────────


def test_a_page_title_gives_up_its_tagline():
    """Live on org 7: `Plane | Simple, extensible, open-source project
    management tool` — a browser tab written for a browser tab, standing in an
    inventory as the name of an asset."""
    identity = determine_identity(
        {
            "ip": "10.0.0.6",
            "services": [
                {
                    "port": 80,
                    "service": "http",
                    "scripts": {
                        "http-title": "Plane | Simple, extensible, open-source project management tool"
                    },
                }
            ],
        }
    )

    assert identity.name == "Plane"


def test_a_qualifier_is_not_a_tagline_and_survives():
    """`Grafana - Prod` and `app-01 | eu-west` are names with qualifiers, not
    pitches. Trimming them would lose the half that distinguishes one row from
    another."""
    for title in ("Grafana - Prod", "app-01 | eu-west"):
        identity = determine_identity(
            {"ip": "10.0.0.7", "services": [{"port": 80, "service": "http", "scripts": {"http-title": title}}]}
        )
        assert identity.name == title


def test_the_untrimmed_title_is_still_the_evidence():
    """The name is trimmed; the claim stays auditable. A reader has to be able
    to see exactly what was read off the page."""
    full = "Plane | Simple, extensible, open-source project management tool"
    identity = determine_identity(
        {"ip": "10.0.0.8", "services": [{"port": 80, "service": "http", "scripts": {"http-title": full}}]}
    )

    assert identity.name == "Plane"
    assert identity.evidence == full


def test_a_certificate_subject_gives_up_its_scaffolding():
    """Live on org 7: `RT-BE50-D604 Server Certificate`. The router is called
    `RT-BE50-D604`; the rest describes the certificate, not the device."""
    identity = determine_identity(
        {
            "ip": "192.168.50.1",
            "services": [
                {
                    "port": 443,
                    "service": "https",
                    "scripts": {"ssl-cert": "Subject: commonName=RT-BE50-D604 Server Certificate"},
                }
            ],
        }
    )

    assert identity.name == "RT-BE50-D604"


def test_a_certificate_subject_that_is_a_hostname_is_left_alone():
    """`www.asusrouter.com` came back correct from the same scan. A trim that
    breaks the cases already working is not a fix."""
    identity = determine_identity(
        {
            "ip": "192.168.50.226",
            "services": [
                {
                    "port": 443,
                    "service": "https",
                    "scripts": {"ssl-cert": "Subject: commonName=www.asusrouter.com"},
                }
            ],
        }
    )

    assert identity.name == "www.asusrouter.com"

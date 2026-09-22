"""CA-07.1 slice 1 — which of the several things a host can be called ends up
on the row a person reads.

Two rules, and they pull in opposite directions:

- A name the organisation already gave a host (its DNS) beats anything a scan
  infers about it. Replacing `app.example.com` with `nginx 1.24.0` reports what
  software serves the host and loses what the host is.
- Where there is no such name — a bare `192.168.1.33` on a flat network — what
  the scan determined is the only thing standing between the reviewer and a row
  they cannot read.
"""

from src.core.services.risk_intelligence_normalization_service import _display_name, _host_label


def _named(name: str) -> dict:
    return {"hostname": name, "ip": "192.168.1.33", "services": []}


def _unnamed() -> dict:
    return {"hostname": None, "ip": "192.168.1.33", "services": []}


def test_a_resolved_hostname_beats_what_the_scan_inferred():
    assert (
        _display_name(_named("app.example.com"), identity_name="nginx 1.24.0", host_label="app.example.com")
        == "app.example.com"
    )


def test_a_determined_identity_names_a_host_dns_never_named():
    """The reported case: 192.168.1.33 was Plane and the row could not say so."""
    assert _display_name(_unnamed(), identity_name="Plane", host_label="192.168.1.33") == "Plane"


def test_an_address_remains_the_last_resort():
    assert _display_name(_unnamed(), identity_name=None, host_label="192.168.1.33") == "192.168.1.33"


def test_the_matching_identifier_is_not_the_display_name():
    """`_host_label` feeds identity matching and the canonical identity key. If
    naming an application changed it, renaming would read as a new artefact
    arriving rather than the same one being understood better."""
    host = _unnamed()
    assert _host_label(host, fallback="fallback") == "192.168.1.33"
    assert _display_name(host, identity_name="Plane", host_label="192.168.1.33") == "Plane"
    # The identifier is unmoved by the name.
    assert _host_label(host, fallback="fallback") == "192.168.1.33"


def test_a_host_with_neither_name_nor_address_falls_back():
    assert _host_label({"services": []}, fallback="collector-3") == "collector-3"

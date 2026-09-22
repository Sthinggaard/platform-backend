"""CA-09A.4 (#316) — what deep verification learned reaches the matcher."""

from src.core.constants.artefact_identity_evidence_enums import ArtefactIdentityBasis
from src.core.model_defs.assets_runtime import Asset, ConnectivityStatus
from src.core.services.artefact_matching import (
    ENGINE_CONFIDENCE_CAP,
    IDENTITY_HINT_CONFIDENCE_CEILING,
    IDENTITY_HINT_CONFIDENCE_FLOOR,
    NAME_HINT_CONFIDENCE,
    identity_hint_confidence,
    score_asset_against_slot,
)
from src.core.template_models import SlotTemplate


def _slot(**kw) -> SlotTemplate:
    return SlotTemplate(
        slot_id=kw.get("slot_id", "database"),
        label=kw.get("label", "Primary database"),
        matching_hints=kw.get("matching_hints", []),
        expected_asset_types=kw.get("expected_asset_types", []),
    )


def _asset(*, display_name="10.0.0.9", asset_type="Database", intent=None, provider="collector") -> Asset:
    return Asset(
        id=1,
        organization_id=1,
        display_name=display_name,
        type=asset_type,
        provider=provider,
        provider_display_name=None,
        connectivity_status=ConnectivityStatus.PENDING_VERIFICATION,
        intent=intent,
    )


def _probed(*names: str) -> dict:
    """A scanned artefact, as normalisation actually writes one: both the
    de-duplicated names and the per-port evidence."""
    return {
        "observedServices": list(names),
        "observedServiceEvidence": [{"name": n, "port": 1, "probed": True} for n in names],
    }


def _guessed(*names: str) -> dict:
    return {
        "observedServices": list(names),
        "observedServiceEvidence": [{"name": n, "port": 1, "probed": False} for n in names],
    }


def _identity(name: str, basis: ArtefactIdentityBasis) -> dict:
    return {"identity": {"name": name, "basis": basis.value}}


# ── a determined identity is evidence ───────────────────────────────────────


def test_a_slot_matches_what_the_scan_determined_not_only_the_row_title():
    """The gap this closes. `_display_name` deliberately prefers a hostname the
    organisation already gave the host, so on a named estate the determined
    identity never reached the scorer at all — an artefact the platform can name
    "PostgreSQL" was matched by a substring of "db-07.internal" or not at all."""
    intent = {**_identity("PostgreSQL 15.4", ArtefactIdentityBasis.SERVICE_PRODUCT), **_probed("postgresql")}
    match = score_asset_against_slot(
        _slot(matching_hints=["postgres"]), _asset(display_name="db-07.internal", intent=intent)
    )

    assert match is not None
    assert match.evidence == "identity"
    assert match.matched_hint == "postgres"


def test_the_reason_names_the_evidence_so_a_reviewer_can_disagree_with_the_claim():
    """A reviewer who disagrees has to be able to argue with *what was read*.
    "We read that off its security certificate" is arguable; "confidence 0.68"
    is not — it offers nothing to push back on."""
    intent = {**_identity("payments.internal", ArtefactIdentityBasis.TLS_CERTIFICATE), **_probed("https")}
    match = score_asset_against_slot(
        _slot(matching_hints=["payments"]), _asset(intent=intent)
    )

    assert "payments.internal" in match.reason
    assert "from its security certificate" in match.reason
    assert "not yet confirmed" in match.reason


def test_stronger_evidence_is_worth_more_and_the_order_is_not_restated_here():
    """`IDENTITY_BASIS_PRECEDENCE` is the single definition of which evidence
    wins. The weights interpolate across it, so adding a basis there changes
    this without anyone editing a second table."""
    strongest = identity_hint_confidence(ArtefactIdentityBasis.CONTAINER_IMAGE.value)
    middle = identity_hint_confidence(ArtefactIdentityBasis.TLS_CERTIFICATE.value)
    weakest = identity_hint_confidence(ArtefactIdentityBasis.HARDWARE_VENDOR.value)

    assert strongest == IDENTITY_HINT_CONFIDENCE_CEILING
    assert weakest == IDENTITY_HINT_CONFIDENCE_FLOOR
    assert strongest > middle > weakest


def test_a_vendor_name_is_the_weakest_identity_and_ranks_below_a_display_name():
    """"Sonos" matching a hint says the manufacturer is Sonos — not that the
    thing fulfils a capability. It must not outrank evidence about the host."""
    assert identity_hint_confidence(ArtefactIdentityBasis.HARDWARE_VENDOR.value) < NAME_HINT_CONFIDENCE


def test_an_unplaceable_basis_is_not_credited():
    """A basis this build does not know cannot be ranked, so it gets the floor
    rather than the benefit of the doubt."""
    assert identity_hint_confidence("something_new") == IDENTITY_HINT_CONFIDENCE_FLOOR
    assert identity_hint_confidence(None) == IDENTITY_HINT_CONFIDENCE_FLOOR


def test_a_stronger_signal_still_wins_over_identity():
    """Provider evidence remains the strongest thing an artefact offers. This
    story adds a surface; it does not reorder the ones already there."""
    intent = {**_identity("Anything", ArtefactIdentityBasis.CONTAINER_IMAGE), **_probed("postgresql")}
    match = score_asset_against_slot(
        _slot(matching_hints=["stripe"]),
        _asset(provider="stripe", intent=intent),
    )

    assert match.evidence == "provider"


# ── a guessed port is not evidence ──────────────────────────────────────────


def test_a_database_slot_does_not_match_a_port_number_pretending_to_be_a_database():
    """`Asset.type` is derived from the observed services, so a type-only match
    on an unprobed service means the slot was filled because something answered
    on 5432. That is precisely the noise CA-09A exists to stop feeding the
    matcher — 253 of 268 rows on the first real estate were exactly this."""
    match = score_asset_against_slot(
        _slot(expected_asset_types=["Database"]),
        _asset(asset_type="Database", intent=_guessed("postgresql")),
    )

    assert match is None


def test_the_same_slot_matches_once_the_port_was_actually_asked():
    match = score_asset_against_slot(
        _slot(expected_asset_types=["Database"]),
        _asset(asset_type="Database", intent=_probed("postgresql")),
    )

    assert match is not None
    assert match.evidence == "type"
    assert "probed the service behind that" in match.reason


def test_an_artefact_recorded_before_the_probed_flag_is_not_given_the_benefit_of_the_doubt():
    """`observedServiceEvidence` postdates `observedServices`. An older artefact
    cannot say whether anything was probed, and the guard exists precisely so an
    unearned certainty never reaches a suggestion — so silence is a no."""
    match = score_asset_against_slot(
        _slot(expected_asset_types=["Database"]),
        _asset(asset_type="Database", intent={"observedServices": ["postgresql"]}),
    )

    assert match is None


def test_the_guard_never_suppresses_a_hint_match():
    """A hint matching the name is evidence in its own right and does not rest
    on the type at all. Refusing it would lose real matches to a guard aimed at
    something else."""
    match = score_asset_against_slot(
        _slot(matching_hints=["postgres"], expected_asset_types=["Database"]),
        _asset(display_name="postgres-primary", asset_type="Database", intent=_guessed("postgresql")),
    )

    assert match is not None
    assert match.matched_hint == "postgres"


def test_an_asset_a_person_entered_is_never_suppressed_by_a_guard_meant_for_scan_noise():
    """Søren, 2026-08-27: the hand-entered assets *"were put in as dummy data for
    the business process and service to have something to assign in the beginning
    when the scanner was not setup. They are not only noise."*

    He is right, and the first version of this guard was wrong about it. Those
    rows carry no observed services at all, so "was any service probed?" answers
    no — and refusing them would have silently removed 66 assets from matching,
    including Stripe, Okta and Cloudflare WAF. A row somebody accountable typed
    is *stronger* evidence than any scan, not weaker. The guard asks whether a
    scan decided this type, and only then whether it earned it."""
    match = score_asset_against_slot(
        _slot(expected_asset_types=["Database"]),
        _asset(display_name="Primary Postgres", asset_type="Database", intent=None, provider="PostgreSQL"),
    )

    assert match is not None
    assert match.evidence == "type"


def test_a_scanned_artefact_is_still_held_to_the_probed_rule():
    """The guard has not been weakened, only aimed. An artefact whose type came
    from observed services still has to have had one of them asked."""
    assert score_asset_against_slot(
        _slot(expected_asset_types=["Database"]),
        _asset(asset_type="Database", intent=_guessed("postgresql")),
    ) is None


# ── the invariants this story inherits and must not touch ───────────────────


def test_no_identity_however_strong_reaches_full_confidence():
    """Only an accountable human decision reaches 1.0. Feeding the matcher
    better evidence must never become a route around that."""
    intent = {**_identity("exact", ArtefactIdentityBasis.CONTAINER_IMAGE), **_probed("https")}
    asset = _asset(display_name="exact", asset_type="Database", intent=intent)
    asset.connectivity_status = ConnectivityStatus.CONNECTED
    match = score_asset_against_slot(
        _slot(matching_hints=["exact"], expected_asset_types=["Database"]), asset
    )

    assert match.confidence < 1.0


# ── two readings that agree ─────────────────────────────────────────────────


def test_two_independent_readings_that_agree_make_a_stronger_claim():
    """Søren, 2026-08-27: *"the title and the TLS certificate might make the
    mapping stronger."* A certificate issued to `payments.internal` and a page
    that titles itself `payments` are different questions asked of the same
    host, and both answering the same way is evidence in a way neither is
    alone. Precedence picks a winner; it must not throw the agreement away."""
    alone = {
        "identity": {
            "name": "payments.internal",
            "basis": ArtefactIdentityBasis.TLS_CERTIFICATE.value,
            "corroboratingBases": [ArtefactIdentityBasis.TLS_CERTIFICATE.value],
        },
        **_probed("https"),
    }
    agreeing = {
        "identity": {
            "name": "payments.internal",
            "basis": ArtefactIdentityBasis.TLS_CERTIFICATE.value,
            "corroboratingBases": [
                ArtefactIdentityBasis.TLS_CERTIFICATE.value,
                ArtefactIdentityBasis.HTTP_TITLE.value,
            ],
        },
        **_probed("https"),
    }
    slot = _slot(matching_hints=["payments"])

    one = score_asset_against_slot(slot, _asset(intent=alone))
    two = score_asset_against_slot(slot, _asset(intent=agreeing))

    assert two.confidence > one.confidence
    assert "a second, independent reading of the host agrees" in two.reason
    assert "independent reading" not in one.reason


def test_agreement_still_cannot_reach_a_human_decision():
    """Corroboration strengthens a claim; it does not make one certain. No
    amount of agreeing evidence may carry an engine suggestion to where only an
    accountable person can take it."""
    intent = {
        "identity": {
            "name": "exact",
            "basis": ArtefactIdentityBasis.CONTAINER_IMAGE.value,
            "corroboratingBases": [b.value for b in ArtefactIdentityBasis],
        },
        **_probed("https"),
    }
    asset = _asset(display_name="exact", asset_type="Database", intent=intent)
    asset.connectivity_status = ConnectivityStatus.CONNECTED

    match = score_asset_against_slot(
        _slot(matching_hints=["exact"], expected_asset_types=["Database"]), asset
    )

    assert match.confidence <= ENGINE_CONFIDENCE_CAP


def test_a_certificate_now_outranks_a_page_title():
    """Søren's ruling, 2026-08-27, on the contradiction #316 surfaced. A
    certificate is issued to a name and presented as an assertion of it; a page
    can title itself anything — which is how two artefacts came to be called
    "Site doesn't have a title (text/html)"."""
    assert identity_hint_confidence(
        ArtefactIdentityBasis.TLS_CERTIFICATE.value
    ) > identity_hint_confidence(ArtefactIdentityBasis.HTTP_TITLE.value)


def test_corroboration_is_only_credited_where_the_identity_did_the_matching():
    """A provider or display-name match did not rest on the identity, so
    agreement between identity readings says nothing about it."""
    intent = {
        "identity": {
            "name": "something else",
            "basis": ArtefactIdentityBasis.TLS_CERTIFICATE.value,
            "corroboratingBases": ["tls_certificate", "http_title"],
        },
        **_probed("https"),
    }
    match = score_asset_against_slot(
        _slot(matching_hints=["stripe"]), _asset(provider="stripe", intent=intent)
    )

    assert match.evidence == "provider"
    assert "independent reading" not in match.reason

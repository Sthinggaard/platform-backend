"""CA-09A.3 (#315) — an artefact says what it does, not only what it is."""

from src.core.constants.artefact_function_enums import ArtefactFunction
from src.core.services.artefact_function_service import determine_function


def _svc(name: str, port: int, probed: bool = True) -> dict:
    return {"name": name, "port": port, "probed": probed}


def test_a_named_runtime_still_has_to_say_what_it_does_for_the_business():
    """The story in one test. "Uvicorn" is a name, not a job — it does not tell
    a reader that anything calling this host stops when the host stops, which is
    the only question a slot mapping is actually asking."""
    result = determine_function([_svc("https", 443)])

    assert result.function == ArtefactFunction.SERVES_APPLICATION.value
    assert "Answers requests" in result.statement
    assert result.evidence == ("https",)
    assert result.determined


def test_a_claim_resting_on_a_port_number_says_so():
    """#249's distinction matters more here than anywhere. A *function* reads as
    a statement about the business, so one derived from nmap's static port table
    would carry a certainty nothing earned."""
    guessed = determine_function([_svc("postgresql", 5432, probed=False)])
    probed = determine_function([_svc("postgresql", 5432, probed=True)])

    assert guessed.function == probed.function == ArtefactFunction.STORES_DATA.value
    assert guessed.probed is False
    assert "port number alone" in guessed.statement
    assert "port number alone" not in probed.statement


def test_two_purposes_that_disagree_are_reported_rather_than_resolved():
    """A router with an admin page and a web server that also runs DNS look
    identical from outside. Picking one by precedence would state a business
    fact the evidence does not support — the same rule classification already
    applies, and the disagreement is itself the finding.

    Its own answer, **not** `UNDETERMINED`: "we heard two things" and "we heard
    nothing" are different findings, and only one of them is a dead end. Both
    of the routers on the estate this was checked against land here, and
    telling their reader "nothing says what this is for" while holding evidence
    of two jobs would simply be untrue."""
    result = determine_function([_svc("domain", 53), _svc("https", 443)])

    assert result.function == ArtefactFunction.SERVES_SEVERAL_PURPOSES.value
    assert set(result.evidence) == {"domain", "https"}
    assert "more than one purpose" in result.statement
    # Still not a determined function: nothing may map on this alone.
    assert result.determined is False


def test_being_able_to_log_in_is_not_a_purpose():
    """SSH sits on almost everything. Letting it decide would classify a
    database by the fact that someone can administer it."""
    result = determine_function([_svc("ssh", 22), _svc("mysql", 3306)])

    assert result.function == ArtefactFunction.STORES_DATA.value
    assert result.evidence == ("mysql",)


def test_a_host_reachable_only_for_administration_says_exactly_that():
    """Its own answer, never folded into "serves an application": a jump host
    reported as a business service ends up inside a dependency chain."""
    result = determine_function([_svc("ssh", 22)])

    assert result.function == ArtefactFunction.ALLOWS_ADMINISTRATION.value
    assert "route into the estate" in result.statement


def test_nothing_listening_is_undetermined_not_a_verdict():
    """"We do not know" is an honest answer. "It does nothing" is a claim, and
    a wrong one hides a real dependency."""
    result = determine_function([])

    assert result.function == ArtefactFunction.UNDETERMINED.value
    assert result.determined is False
    assert "has not been ruled out" in result.statement


def test_an_unrecognised_service_does_not_invent_a_purpose():
    result = determine_function([_svc("some-vendor-daemon", 9999)])

    assert result.function == ArtefactFunction.UNDETERMINED.value


def test_an_artefact_recorded_before_the_probed_flag_still_gets_a_function():
    """`observedServiceEvidence` postdates `observedServices`. An older artefact
    has only the names, which cannot say whether anything was probed — so it is
    treated as unprobed rather than assumed to have been, and still gets an
    answer instead of nothing."""
    result = determine_function(None, observed_names=["redis"])

    assert result.function == ArtefactFunction.STORES_DATA.value
    assert result.probed is False
    assert "port number alone" in result.statement


def test_the_same_purpose_on_several_ports_is_one_finding():
    """Two ports both serving http are one job, not a disagreement."""
    result = determine_function([_svc("http", 80), _svc("https", 443), _svc("http-alt", 8080)])

    assert result.function == ArtefactFunction.SERVES_APPLICATION.value
    assert len(result.evidence) == 3

import httpx
import pytest

from src.core.config import Environment, settings
from src.core.exceptions import ConfigurationError
from src.pretenant.enrichment import (
    CvrEnrichmentClient,
    CvrNotFoundError,
    deriveSegmentation,
    normalizeCvrPayload,
)


class _FakeResponse:
    def __init__(self, status_code: int, payload):
        self.status_code = status_code
        self._payload = payload

    def json(self):
        return self._payload


@pytest.fixture(autouse=True)
def disable_cvr_stub_by_default(monkeypatch):
    monkeypatch.setattr(settings, "pretenant_cvr_stub_enabled", False)


def test_stub_mode_uses_configured_settings_without_external_provider(monkeypatch):
    monkeypatch.setattr(settings, "pretenant_cvr_stub_enabled", True)
    monkeypatch.setattr(httpx.Client, "request", lambda *args, **kwargs: pytest.fail("provider should not be called"))

    result = CvrEnrichmentClient().enrich("12345678")

    assert result.cvr == "12345678"
    assert result.legal_name == "Risklence Demo A/S"


def test_cvrapi_default_mapping(monkeypatch):
    monkeypatch.delenv("PRETENANT_CVR_STUB_ENABLED", raising=False)
    monkeypatch.setenv("PRETENANT_CVR_PROVIDER", "cvrapi")
    monkeypatch.setenv("PRETENANT_CVR_PROVIDER_USER_AGENT", "Risklence - Onboarding - test")

    def fake_request(self, method, url, headers=None, params=None, json=None):
        assert method == "GET"
        assert url == "https://cvrapi.dk/api"
        assert params == {"vat": "10103940", "country": "dk"}
        assert headers is not None
        assert headers.get("User-Agent") == "Risklence - Onboarding - test"
        return _FakeResponse(
            200,
            {
                "vat": 10103940,
                "name": "Statsministeriet, Departementet",
                "address": "Prins Jorgens Gard 11",
                "zipcode": "1218",
                "city": "Kobenhavn K",
                "industrycode": 841100,
            },
        )

    monkeypatch.setattr(httpx.Client, "request", fake_request)
    result = CvrEnrichmentClient().enrich("10103940")

    assert result.cvr == "10103940"
    assert result.legal_name == "Statsministeriet, Departementet"
    assert result.address == "Prins Jorgens Gard 11"
    assert result.postal_code == "1218"
    assert result.city == "Kobenhavn K"
    assert result.country == "DK"
    assert result.industry_code == "841100"


def test_cvrapi_error_not_found(monkeypatch):
    monkeypatch.delenv("PRETENANT_CVR_STUB_ENABLED", raising=False)
    monkeypatch.setenv("PRETENANT_CVR_PROVIDER", "cvrapi")

    def fake_request(self, method, url, headers=None, params=None, json=None):
        return _FakeResponse(200, {"error": "NOT_FOUND", "t": 0, "version": 6})

    monkeypatch.setattr(httpx.Client, "request", fake_request)

    with pytest.raises(CvrNotFoundError):
        CvrEnrichmentClient().enrich("93699332")


def test_cvrdev_mapping(monkeypatch):
    monkeypatch.delenv("PRETENANT_CVR_STUB_ENABLED", raising=False)
    monkeypatch.setenv("PRETENANT_CVR_PROVIDER", "cvrdev")
    monkeypatch.setenv("PRETENANT_CVR_PROVIDER_API_KEY", "demo-key")

    def fake_request(self, method, url, headers=None, params=None, json=None):
        assert method == "GET"
        assert url == "https://api.cvr.dev/api/cvr/virksomhed"
        assert params == {"cvr_nummer": "18738708"}
        assert headers is not None
        assert headers.get("Authorization") == "Bearer demo-key"
        return _FakeResponse(
            200,
            [
                {
                    "cvrNummer": 18738708,
                    "virksomhedMetadata": {
                        "nyesteNavn": {"navn": "Eksempel A/S"},
                        "nyesteBeliggenhedsadresse": {
                            "vejnavn": "Eksempelvej",
                            "husnummerFra": 10,
                            "postnummer": 2100,
                            "postdistrikt": "Kobenhavn O",
                            "landekode": "DK",
                        },
                        "nyesteHovedbranche": {"branchekode": "62010"},
                    },
                }
            ],
        )

    monkeypatch.setattr(httpx.Client, "request", fake_request)
    result = CvrEnrichmentClient().enrich("18738708")

    assert result.cvr == "18738708"
    assert result.legal_name == "Eksempel A/S"
    assert result.address == "Eksempelvej 10"
    assert result.postal_code == "2100"
    assert result.city == "Kobenhavn O"
    assert result.country == "DK"
    assert result.industry_code == "62010"


def test_cvrapi_industry_description_is_mapped_separately_from_code(monkeypatch):
    monkeypatch.delenv("PRETENANT_CVR_STUB_ENABLED", raising=False)
    monkeypatch.setenv("PRETENANT_CVR_PROVIDER", "cvrapi")

    def fake_request(self, method, url, headers=None, params=None, json=None):
        return _FakeResponse(
            200,
            {
                "vat": 46890001,
                "name": "Example A/S",
                "industrycode": 468900,
                "industrydesc": "Anden specialiseret engroshandel i.a.n.",
            },
        )

    monkeypatch.setattr(httpx.Client, "request", fake_request)
    result = CvrEnrichmentClient().enrich("46890001")

    assert result.industry_code == "468900"
    assert result.industry_desc == "Anden specialiseret engroshandel i.a.n."


class _FakeSettings:
    def __init__(self, environment: Environment):
        self.environment = environment
        self.pretenant_cvr_stub_enabled = False


def test_rejects_a_non_https_provider_url(monkeypatch):
    monkeypatch.delenv("PRETENANT_CVR_STUB_ENABLED", raising=False)
    monkeypatch.setenv("PRETENANT_CVR_PROVIDER_URL", "http://cvrapi.dk/api")

    with pytest.raises(ConfigurationError, match="https"):
        CvrEnrichmentClient().enrich("10103940")


def test_allows_an_unrecognised_https_host_outside_production_but_logs_it(monkeypatch):
    monkeypatch.delenv("PRETENANT_CVR_STUB_ENABLED", raising=False)
    monkeypatch.setenv("PRETENANT_CVR_PROVIDER_URL", "https://self-hosted-cvr-proxy.example.com/api")
    monkeypatch.setattr("src.pretenant.enrichment.settings", _FakeSettings(Environment.DEVELOPMENT))

    def fake_request(self, method, url, headers=None, params=None, json=None):
        assert url == "https://self-hosted-cvr-proxy.example.com/api"
        return _FakeResponse(200, {"vat": 10103940, "name": "Example"})

    monkeypatch.setattr(httpx.Client, "request", fake_request)
    result = CvrEnrichmentClient().enrich("10103940")
    assert result.legal_name == "Example"


def test_rejects_an_unrecognised_host_in_production_without_explicit_opt_in(monkeypatch):
    monkeypatch.delenv("PRETENANT_CVR_STUB_ENABLED", raising=False)
    monkeypatch.delenv("PRETENANT_CVR_PROVIDER_ALLOW_CUSTOM_HOST", raising=False)
    monkeypatch.setenv("PRETENANT_CVR_PROVIDER_URL", "https://attacker-controlled.example.com/api")
    monkeypatch.setattr("src.pretenant.enrichment.settings", _FakeSettings(Environment.PRODUCTION))

    with pytest.raises(ConfigurationError, match="not on the known allowlist"):
        CvrEnrichmentClient().enrich("10103940")


def test_allows_an_unrecognised_host_in_production_with_explicit_opt_in(monkeypatch):
    monkeypatch.delenv("PRETENANT_CVR_STUB_ENABLED", raising=False)
    monkeypatch.setenv("PRETENANT_CVR_PROVIDER_URL", "https://self-hosted-cvr-proxy.example.com/api")
    monkeypatch.setenv("PRETENANT_CVR_PROVIDER_ALLOW_CUSTOM_HOST", "true")
    monkeypatch.setattr("src.pretenant.enrichment.settings", _FakeSettings(Environment.PRODUCTION))

    def fake_request(self, method, url, headers=None, params=None, json=None):
        return _FakeResponse(200, {"vat": 10103940, "name": "Example"})

    monkeypatch.setattr(httpx.Client, "request", fake_request)
    result = CvrEnrichmentClient().enrich("10103940")
    assert result.legal_name == "Example"


def test_normalize_cvr_payload_discards_disallowed_fields():
    raw_payload = {
        "vat": 93699332,
        "name": "Organization 93699332",
        "industrycode": 62010,
        "industrydesc": "Computer programming activities",
        "companycode": 80,
        "companydesc": "Anpartsselskab",
        "employees": 12,
        "startdate": "2022-01-01",
        "enddate": None,
        "phone": "+45 1234 5678",
        "address": "Some Street 1",
        "productionunits": [
            {
                "pno": "1000000001",
                "main": True,
                "zipcode": "1001",
                "city": "Copenhagen",
                "employees": 8,
                "email": "ignore@example.com",
            }
        ],
        "version": 6,
    }

    normalized = normalizeCvrPayload(raw_payload)
    assert normalized == {
        "vat": "93699332",
        "name": "Organization 93699332",
        "industrycode": "62010",
        "industrydesc": "Computer programming activities",
        "companycode": "80",
        "companydesc": "Anpartsselskab",
        "employees": 12,
        "startdate": "2022-01-01",
        "enddate": None,
        "productionunits": [
            {
                "pno": "1000000001",
                "main": True,
                "zipcode": "1001",
                "city": "Copenhagen",
                "employees": 8,
            }
        ],
    }


def test_derive_segmentation_assigns_expected_bands():
    normalized_payload = {
        "vat": "93699332",
        "name": "Organization 93699332",
        "industrycode": "62010",
        "industrydesc": "Computer programming activities",
        "companycode": "80",
        "companydesc": "Anpartsselskab",
        "employees": 25,
        "startdate": "2020-01-01",
        "enddate": None,
        "productionunits": [
            {"pno": "1000000001", "main": True, "zipcode": "1001", "city": "Copenhagen", "employees": 25},
            {"pno": "1000000002", "main": False, "zipcode": "8000", "city": "Aarhus", "employees": 0},
        ],
    }

    segmentation = deriveSegmentation(normalized_payload)
    assert segmentation["industryCluster"] == "Information"
    assert segmentation["orgSizeBand"] == "Small"
    assert segmentation["legalFormBand"] == "ApS"
    assert segmentation["siteCount"] == 2
    assert segmentation["multiSite"] is True
    assert segmentation["lifecycleStage"] == "Mature"
    assert segmentation["dataQualityFlags"]["employeeUncertain"] is False


def test_derive_segmentation_supports_mapping_overrides(monkeypatch):
    monkeypatch.setenv(
        "PRETENANT_SEGMENTATION_INDUSTRY_CLUSTER_PREFIX_MAP_JSON",
        '{"62-63":"Digital","84":"PublicSector"}',
    )
    monkeypatch.setenv(
        "PRETENANT_SEGMENTATION_LEGAL_FORM_KEYWORDS_JSON",
        '{"LimitedCompany":["anpart","aps"],"PublicCompany":["aktie","a/s"]}',
    )
    normalized_payload = {
        "industrycode": "62010",
        "companycode": "80",
        "companydesc": "Anpartsselskab",
        "employees": 18,
        "startdate": "2020-01-01",
        "enddate": None,
        "productionunits": [],
    }

    segmentation = deriveSegmentation(normalized_payload)

    assert segmentation["industryCluster"] == "Digital"
    assert segmentation["legalFormBand"] == "LimitedCompany"


def test_derive_segmentation_ignores_invalid_mapping_override(monkeypatch):
    monkeypatch.setenv("PRETENANT_SEGMENTATION_INDUSTRY_CLUSTER_PREFIX_MAP_JSON", '{"bad":"Nope"}')
    monkeypatch.setenv("PRETENANT_SEGMENTATION_LEGAL_FORM_KEYWORDS_JSON", "invalid-json")
    normalized_payload = {
        "industrycode": "62010",
        "companycode": "80",
        "companydesc": "Anpartsselskab",
        "employees": 18,
        "startdate": "2020-01-01",
        "enddate": None,
        "productionunits": [],
    }

    segmentation = deriveSegmentation(normalized_payload)

    assert segmentation["industryCluster"] == "Information"
    assert segmentation["legalFormBand"] == "ApS"

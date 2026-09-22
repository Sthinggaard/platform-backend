from __future__ import annotations

import json
import os
import re
from dataclasses import dataclass, field
from datetime import date, datetime, timedelta, timezone
from typing import Any
from urllib.parse import urlparse

import httpx
import structlog

from src.core.config import Environment, settings
from src.core.exceptions import ConfigurationError

logger = structlog.get_logger(__name__)

# The registry hosts this client is known to work with. PRETENANT_CVR_PROVIDER_URL
# is a deliberate escape hatch for self-hosted/alternate providers — it stays
# fully env-overridable, so an unrecognised host is not blocked, only logged
# (visibility) in development, and requires an explicit opt-in in production
# (security audit, 2026-07-16: this was previously silent either way, so a
# misconfigured or tampered env var could redirect CVR lookups — which may
# include an API key/token in headers or query params — to an arbitrary host
# with no trace).
_KNOWN_CVR_PROVIDER_HOSTS = frozenset({"cvrapi.dk", "api.cvr.dev"})


class CvrNotFoundError(Exception):
    pass


class CvrTimeoutError(Exception):
    pass


_DEFAULT_INDUSTRY_CLUSTER_RANGES: tuple[tuple[int, int, str], ...] = (
    (1, 3, "Primary"),
    (10, 33, "Manufacturing"),
    (41, 43, "Construction"),
    (45, 47, "Retail"),
    (49, 53, "Transport"),
    (55, 56, "Hospitality"),
    (58, 63, "Information"),
    (64, 66, "Finance"),
    (69, 75, "ProfessionalServices"),
    (84, 84, "PublicSector"),
    (85, 85, "Education"),
    (86, 88, "Health"),
)
_DEFAULT_LEGAL_FORM_KEYWORDS: tuple[tuple[str, tuple[str, ...]], ...] = (
    ("ApS", ("anpart", "aps")),
    ("A/S", ("aktie", "a/s")),
    ("SoleProprietorship", ("enkelt",)),
)


def normalize_vat(value: str | None) -> str | None:
    if value is None:
        return None
    digits = "".join(ch for ch in str(value) if ch.isdigit())
    if len(digits) != 8:
        return None
    return digits


def _normalize_industry_code(value: str | None) -> str | None:
    if not value:
        return None
    digits = "".join(ch for ch in str(value) if ch.isdigit())
    if len(digits) < 4:
        return None
    return digits


def _extract_record(payload: Any) -> dict[str, Any] | None:
    if payload is None:
        return None
    if isinstance(payload, list):
        for item in payload:
            result = _extract_record(item)
            if result is not None:
                return result
        return None
    if isinstance(payload, dict):
        for key in ("data", "result", "organization", "organisation", "company", "Company"):
            if key in payload:
                nested = _extract_record(payload.get(key))
                if nested is not None:
                    return nested
        return payload
    return None


def _pick_string(source: dict[str, Any], *keys: str) -> str | None:
    for key in keys:
        value = source.get(key)
        if value is None:
            continue
        if isinstance(value, str):
            stripped = value.strip()
            if stripped:
                return stripped
            continue
        if isinstance(value, (int, float)):
            return str(value)
    return None


def _pick_int(source: dict[str, Any], *keys: str) -> int | None:
    for key in keys:
        value = source.get(key)
        if value is None:
            continue
        if isinstance(value, bool):
            continue
        if isinstance(value, int):
            return value
        if isinstance(value, float):
            return int(value)
        if isinstance(value, str):
            digits = "".join(ch for ch in value if ch.isdigit())
            if digits:
                return int(digits)
    return None


def _extract_dict(value: Any) -> dict[str, Any] | None:
    if isinstance(value, dict):
        return value
    return None


def _extract_first_dict(value: Any) -> dict[str, Any] | None:
    if isinstance(value, list):
        for item in value:
            if isinstance(item, dict):
                return item
    return None


def _parse_date(value: Any) -> date | None:
    if value is None:
        return None
    if isinstance(value, datetime):
        return value.date()
    if isinstance(value, date):
        return value
    if not isinstance(value, str):
        return None

    text = value.strip()
    if not text:
        return None

    if text.endswith("Z"):
        text = text[:-1] + "+00:00"

    for parser in (
        lambda v: datetime.fromisoformat(v).date(),
        lambda v: datetime.strptime(v, "%Y-%m-%d").date(),
        lambda v: datetime.strptime(v, "%d-%m-%Y").date(),
        lambda v: datetime.strptime(v, "%d/%m/%Y").date(),
    ):
        try:
            return parser(text)
        except ValueError:
            continue
    return None


def _parse_address(raw_address: Any) -> dict[str, str | None]:
    if isinstance(raw_address, str):
        text = raw_address.strip()
        return {"address": text or None, "postal_code": None, "city": None, "country": None}

    if not isinstance(raw_address, dict):
        return {"address": None, "postal_code": None, "city": None, "country": None}

    street = _pick_string(raw_address, "street", "Street", "vejnavn", "Vejnavn", "fritekst")
    house_number = _pick_string(raw_address, "houseNumber", "HouseNumber", "husnummerFra", "HusnummerFra")
    house_letter = _pick_string(raw_address, "houseLetter", "HouseLetter", "bogstavFra", "BogstavFra")
    postal_code = _pick_string(
        raw_address,
        "postalCode",
        "PostalCode",
        "zipcode",
        "Zipcode",
        "postnummer",
        "Postnummer",
    )
    city = _pick_string(
        raw_address,
        "city",
        "City",
        "postalDistrict",
        "PostalDistrict",
        "postdistrikt",
        "Postdistrikt",
        "bynavn",
        "Bynavn",
    )
    country = _pick_string(raw_address, "country", "Country", "landekode", "Landekode")

    address_parts = [part for part in (street, house_number, house_letter) if part]
    address = " ".join(address_parts) if address_parts else None
    return {
        "address": address,
        "postal_code": postal_code,
        "city": city,
        "country": country,
    }


def normalizeCvrPayload(rawPayload: Any) -> dict[str, Any]:
    record = _extract_record(rawPayload) or {}

    vat = normalize_vat(
        _pick_string(record, "vat", "Vat", "cvr", "Cvr", "cvrNumber", "cvrNummer", "CVR", "vatNumber")
    )

    production_units_raw = record.get("productionunits")
    if production_units_raw is None:
        production_units_raw = record.get("productionUnits")
    if production_units_raw is None:
        production_units_raw = record.get("ProductionUnits")

    normalized_units: list[dict[str, Any]] = []
    if isinstance(production_units_raw, list):
        for unit in production_units_raw:
            if not isinstance(unit, dict):
                continue
            normalized_units.append(
                {
                    "pno": _pick_string(unit, "pno", "Pno"),
                    "main": bool(unit.get("main")) if isinstance(unit.get("main"), bool) else False,
                    "zipcode": _pick_string(unit, "zipcode", "Zipcode", "postalCode", "PostalCode"),
                    "city": _pick_string(unit, "city", "City", "postalDistrict", "PostalDistrict"),
                    "employees": _pick_int(unit, "employees", "Employees"),
                }
            )

    return {
        "vat": vat,
        "name": _pick_string(record, "name", "Name", "legalName", "LegalName"),
        "industrycode": _pick_string(record, "industrycode", "industryCode", "IndustryCode"),
        "industrydesc": _pick_string(record, "industrydesc", "industryDescription", "IndustryDescription"),
        "companycode": _pick_string(record, "companycode", "companyCode", "CompanyCode"),
        "companydesc": _pick_string(record, "companydesc", "companyDescription", "CompanyDescription"),
        "employees": _pick_int(record, "employees", "Employees"),
        "startdate": _pick_string(record, "startdate", "startDate", "StartDate"),
        "enddate": _pick_string(record, "enddate", "endDate", "EndDate"),
        "productionunits": normalized_units,
    }


def _parse_prefix_range_token(token: str) -> tuple[int, int] | None:
    cleaned = token.strip()
    if not cleaned:
        return None
    if re.fullmatch(r"\d{1,2}", cleaned):
        value = int(cleaned)
        return value, value
    match = re.fullmatch(r"(\d{1,2})\s*-\s*(\d{1,2})", cleaned)
    if not match:
        return None
    start, end = int(match.group(1)), int(match.group(2))
    if start > end:
        return None
    return start, end


def _resolve_industry_cluster_ranges() -> list[tuple[int, int, str]]:
    raw = (os.getenv("PRETENANT_SEGMENTATION_INDUSTRY_CLUSTER_PREFIX_MAP_JSON") or "").strip()
    if not raw:
        return list(_DEFAULT_INDUSTRY_CLUSTER_RANGES)
    try:
        parsed = json.loads(raw)
    except json.JSONDecodeError:
        return list(_DEFAULT_INDUSTRY_CLUSTER_RANGES)
    if not isinstance(parsed, dict):
        return list(_DEFAULT_INDUSTRY_CLUSTER_RANGES)

    resolved: list[tuple[int, int, str]] = []
    for token, cluster_name in parsed.items():
        if not isinstance(token, str) or not isinstance(cluster_name, str):
            continue
        cluster = cluster_name.strip()
        prefix_range = _parse_prefix_range_token(token)
        if not cluster or prefix_range is None:
            continue
        resolved.append((prefix_range[0], prefix_range[1], cluster))
    return resolved or list(_DEFAULT_INDUSTRY_CLUSTER_RANGES)


def _resolve_legal_form_keywords() -> list[tuple[str, tuple[str, ...]]]:
    raw = (os.getenv("PRETENANT_SEGMENTATION_LEGAL_FORM_KEYWORDS_JSON") or "").strip()
    if not raw:
        return list(_DEFAULT_LEGAL_FORM_KEYWORDS)
    try:
        parsed = json.loads(raw)
    except json.JSONDecodeError:
        return list(_DEFAULT_LEGAL_FORM_KEYWORDS)
    if not isinstance(parsed, dict):
        return list(_DEFAULT_LEGAL_FORM_KEYWORDS)

    resolved: list[tuple[str, tuple[str, ...]]] = []
    for band_name, keywords in parsed.items():
        if not isinstance(band_name, str):
            continue
        band = band_name.strip()
        if not band:
            continue
        if isinstance(keywords, str):
            keyword_values: list[str] = [keywords]
        elif isinstance(keywords, list):
            keyword_values = [item for item in keywords if isinstance(item, str)]
        else:
            continue
        normalized_keywords = tuple(keyword.strip().lower() for keyword in keyword_values if keyword.strip())
        if not normalized_keywords:
            continue
        resolved.append((band, normalized_keywords))
    return resolved or list(_DEFAULT_LEGAL_FORM_KEYWORDS)


def _derive_industry_cluster(industry_code: str | None) -> str:
    if not industry_code:
        return "Unknown"
    digits = "".join(ch for ch in industry_code if ch.isdigit())
    if len(digits) < 2:
        return "Unknown"
    prefix = int(digits[:2])
    for start, end, cluster in _resolve_industry_cluster_ranges():
        if start <= prefix <= end:
            return cluster
    return "Other"


def _derive_legal_form_band(company_code: str | None, company_desc: str | None) -> str:
    desc = (company_desc or "").strip().lower()
    code = (company_code or "").strip()
    for band, keywords in _resolve_legal_form_keywords():
        if any(keyword in desc for keyword in keywords):
            return band
    if code:
        return f"code:{code}"
    if desc:
        return company_desc or "Unknown"
    return "Unknown"


def deriveSegmentation(normalizedPayload: dict[str, Any]) -> dict[str, Any]:
    employees = normalizedPayload.get("employees")
    employee_count = employees if isinstance(employees, int) else None

    if employee_count is None or employee_count <= 0:
        org_size_band = "Unknown"
    elif employee_count <= 9:
        org_size_band = "Micro"
    elif employee_count <= 49:
        org_size_band = "Small"
    elif employee_count <= 249:
        org_size_band = "Medium"
    else:
        org_size_band = "Large"

    end_date = _parse_date(normalizedPayload.get("enddate"))
    start_date = _parse_date(normalizedPayload.get("startdate"))

    if end_date is not None:
        lifecycle_stage = "Inactive"
    elif start_date is not None and start_date >= (datetime.now(timezone.utc).date() - timedelta(days=365)):
        lifecycle_stage = "New"
    else:
        lifecycle_stage = "Mature"

    production_units = normalizedPayload.get("productionunits")
    site_count = len(production_units) if isinstance(production_units, list) and production_units else 1
    multi_site = site_count > 1

    industry_code = normalizedPayload.get("industrycode")
    company_code = normalizedPayload.get("companycode")
    company_desc = normalizedPayload.get("companydesc")

    return {
        "industryCluster": _derive_industry_cluster(industry_code if isinstance(industry_code, str) else None),
        "orgSizeBand": org_size_band,
        "legalFormBand": _derive_legal_form_band(
            company_code if isinstance(company_code, str) else None,
            company_desc if isinstance(company_desc, str) else None,
        ),
        "siteCount": site_count,
        "multiSite": multi_site,
        "lifecycleStage": lifecycle_stage,
        "dataQualityFlags": {
            "employeeUncertain": employee_count is None or employee_count <= 0,
        },
    }


@dataclass(frozen=True)
class CvrEnrichmentResult:
    cvr: str
    legal_name: str
    trade_name: str | None = None
    address: str | None = None
    postal_code: str | None = None
    city: str | None = None
    country: str = "DK"
    industry_code: str | None = None
    industry_desc: str | None = None
    size_bracket: str | None = None
    geography: str | None = None
    enriched_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


@dataclass(frozen=True)
class CvrOrganisationLookupResult:
    vat: str
    name: str
    legal_form: str
    industry: str
    employee_count: int
    industry_cluster: str
    org_size_band: str
    legal_form_band: str
    site_count: int
    multi_site: bool
    lifecycle_stage: str
    employee_uncertain: bool


class CvrEnrichmentClient:
    _STUB_ENABLED_VALUES = {"1", "true", "yes", "on"}

    def enrich(self, cvr: str) -> CvrEnrichmentResult:
        payload, default_country = self._fetch_provider_payload(cvr)
        parsed = self._parse_provider_payload(payload, requested_cvr=cvr, default_country=default_country)
        if parsed is None:
            raise CvrNotFoundError("CVR not found")
        return parsed

    def lookup_verified_organisation(self, vat: str) -> CvrOrganisationLookupResult:
        normalized_vat = normalize_vat(vat)
        if not normalized_vat:
            raise CvrNotFoundError("CVR not found")

        payload, _ = self._fetch_provider_payload(normalized_vat)
        normalized = normalizeCvrPayload(payload)
        normalized["vat"] = normalized.get("vat") or normalized_vat

        name = normalized.get("name")
        if not isinstance(name, str) or not name.strip():
            raise CvrNotFoundError("CVR not found")

        segmentation = deriveSegmentation(normalized)
        company_desc = normalized.get("companydesc") if isinstance(normalized.get("companydesc"), str) else None
        company_code = normalized.get("companycode") if isinstance(normalized.get("companycode"), str) else None
        industry_desc = normalized.get("industrydesc") if isinstance(normalized.get("industrydesc"), str) else None
        industry_code = normalized.get("industrycode") if isinstance(normalized.get("industrycode"), str) else None
        employees = normalized.get("employees") if isinstance(normalized.get("employees"), int) else 0

        return CvrOrganisationLookupResult(
            vat=normalized_vat,
            name=name.strip(),
            legal_form=company_desc or (company_code or "Unknown"),
            industry=industry_desc or (industry_code or "Unknown"),
            employee_count=max(0, int(employees)),
            industry_cluster=str(segmentation["industryCluster"]),
            org_size_band=str(segmentation["orgSizeBand"]),
            legal_form_band=str(segmentation["legalFormBand"]),
            site_count=int(segmentation["siteCount"]),
            multi_site=bool(segmentation["multiSite"]),
            lifecycle_stage=str(segmentation["lifecycleStage"]),
            employee_uncertain=bool(segmentation["dataQualityFlags"]["employeeUncertain"]),
        )

    def _fetch_provider_payload(self, cvr: str) -> tuple[Any, str]:
        if settings.pretenant_cvr_stub_enabled:
            if cvr == "00000000":
                raise CvrNotFoundError("CVR not found")
            if cvr == "99999999":
                raise CvrTimeoutError("Simulated enrichment timeout")
            if len(cvr) == 8 and cvr.isdigit():
                return self._build_stub_payload(cvr), "DK"

        provider_mode = (os.getenv("PRETENANT_CVR_PROVIDER") or "cvrapi").strip().lower() or "cvrapi"
        provider_url = (os.getenv("PRETENANT_CVR_PROVIDER_URL") or "").strip()
        if not provider_url:
            if provider_mode == "cvrdev":
                provider_url = "https://api.cvr.dev/api/cvr/virksomhed"
            elif provider_mode == "cvrapi":
                provider_url = "https://cvrapi.dk/api"
            else:
                raise CvrTimeoutError("Enrichment client not configured")

        method = (os.getenv("PRETENANT_CVR_PROVIDER_METHOD") or "GET").strip().upper()
        timeout_seconds = self._read_timeout_seconds()
        default_query_param = "cvr_nummer" if provider_mode == "cvrdev" else "vat"
        query_param_name = (os.getenv("PRETENANT_CVR_PROVIDER_CVR_QUERY_PARAM") or default_query_param).strip() or default_query_param
        body_field_name = (os.getenv("PRETENANT_CVR_PROVIDER_CVR_BODY_FIELD") or "cvr").strip() or "cvr"
        api_key = (os.getenv("PRETENANT_CVR_PROVIDER_API_KEY") or "").strip()
        default_api_key_header = "Authorization" if provider_mode == "cvrdev" else "x-api-key"
        api_key_header = (os.getenv("PRETENANT_CVR_PROVIDER_API_KEY_HEADER") or default_api_key_header).strip() or default_api_key_header
        default_country = (os.getenv("PRETENANT_CVR_DEFAULT_COUNTRY") or "DK").strip().upper() or "DK"
        cvrapi_country = (os.getenv("PRETENANT_CVR_PROVIDER_COUNTRY") or default_country.lower()).strip().lower() or "dk"
        cvrapi_token = (os.getenv("PRETENANT_CVR_PROVIDER_TOKEN") or "").strip()
        cvrapi_user_agent = (
            os.getenv("PRETENANT_CVR_PROVIDER_USER_AGENT") or "Risklence Onboarding CVR Lookup"
        ).strip()

        headers: dict[str, str] = {}
        if api_key and provider_mode != "cvrapi":
            if api_key_header.lower() == "authorization" and not api_key.lower().startswith("bearer "):
                headers[api_key_header] = f"Bearer {api_key}"
            else:
                headers[api_key_header] = api_key
        if provider_mode == "cvrapi" and cvrapi_user_agent:
            headers["User-Agent"] = cvrapi_user_agent

        params: dict[str, str] | None = None
        json_payload: dict[str, str] | None = None
        url = provider_url
        if "{cvr}" in provider_url:
            url = provider_url.format(cvr=cvr)
        elif method == "GET":
            params = {query_param_name: cvr}
            if provider_mode == "cvrapi":
                params["country"] = cvrapi_country
                token = cvrapi_token or api_key
                if token:
                    params["token"] = token
        else:
            json_payload = {body_field_name: cvr}

        self._validate_provider_host(url)

        try:
            with httpx.Client(timeout=timeout_seconds) as client:
                response = client.request(
                    method=method,
                    url=url,
                    headers=headers or None,
                    params=params,
                    json=json_payload,
                )
        except httpx.TimeoutException as err:
            raise CvrTimeoutError("Enrichment timeout") from err
        except httpx.HTTPError as err:
            raise CvrTimeoutError("Enrichment request failed") from err

        if response.status_code == 404:
            raise CvrNotFoundError("CVR not found")
        if response.status_code >= 400:
            raise CvrTimeoutError("Enrichment service unavailable")

        try:
            payload = response.json()
        except ValueError as err:
            raise CvrTimeoutError("Invalid enrichment payload") from err

        if isinstance(payload, dict) and isinstance(payload.get("error"), str):
            provider_error = payload["error"].strip().upper()
            if provider_error in {"NOT_FOUND", "INVALID_VAT"}:
                raise CvrNotFoundError("CVR not found")
            raise CvrTimeoutError("Enrichment service unavailable")

        return payload, default_country

    def _validate_provider_host(self, url: str) -> None:
        parsed = urlparse(url)
        host = (parsed.hostname or "").lower()

        if parsed.scheme != "https":
            raise ConfigurationError(
                f"CVR registry provider URL must use https (got scheme {parsed.scheme!r})."
            )

        if host in _KNOWN_CVR_PROVIDER_HOSTS:
            return

        if settings.environment == Environment.PRODUCTION:
            if os.getenv("PRETENANT_CVR_PROVIDER_ALLOW_CUSTOM_HOST", "").strip().lower() not in {"1", "true", "yes"}:
                raise ConfigurationError(
                    f"CVR registry provider host {host!r} is not on the known allowlist "
                    f"{sorted(_KNOWN_CVR_PROVIDER_HOSTS)}. Set PRETENANT_CVR_PROVIDER_ALLOW_CUSTOM_HOST=true "
                    "to confirm this is an intentional, reviewed self-hosted/alternate provider."
                )
            logger.warning("pretenant_cvr_custom_provider_host_allowed", host=host)
        else:
            logger.warning("pretenant_cvr_custom_provider_host", host=host)

    def _read_timeout_seconds(self) -> float:
        raw = (os.getenv("PRETENANT_CVR_PROVIDER_TIMEOUT_SECONDS") or "").strip()
        if not raw:
            return 5.0
        try:
            value = float(raw)
        except ValueError as err:
            raise CvrTimeoutError("Invalid PRETENANT_CVR_PROVIDER_TIMEOUT_SECONDS") from err
        if value <= 0:
            raise CvrTimeoutError("Invalid PRETENANT_CVR_PROVIDER_TIMEOUT_SECONDS")
        return value

    def _build_stub_payload(self, cvr: str) -> dict[str, Any]:
        main_employee_count = 12 if cvr == "12345678" else 0
        return {
            "vat": cvr,
            "name": "Risklence Demo A/S" if cvr == "12345678" else f"Demo Company {cvr}",
            "address": "Demo Street 1",
            "zipcode": "1000",
            "city": "Copenhagen",
            "industrycode": "62010",
            "industrydesc": "Computer programming",
            "companycode": "80",
            "companydesc": "Anpartsselskab",
            "employees": main_employee_count,
            "startdate": "2020-01-01",
            "enddate": None,
            "productionunits": [
                {
                    "pno": "1000000001",
                    "main": True,
                    "zipcode": "1000",
                    "city": "Copenhagen",
                    "employees": main_employee_count,
                }
            ],
        }

    @classmethod
    def _parse_provider_payload(
        cls,
        payload: Any,
        *,
        requested_cvr: str,
        default_country: str,
    ) -> CvrEnrichmentResult | None:
        record = _extract_record(payload)
        if record is None:
            return None

        metadata = _extract_dict(record.get("virksomhedMetadata"))
        metadata_name = _extract_dict(metadata.get("nyesteNavn")) if metadata else None
        metadata_address = _extract_dict(metadata.get("nyesteBeliggenhedsadresse")) if metadata else None
        metadata_industry = _extract_dict(metadata.get("nyesteHovedbranche")) if metadata else None
        history_address = _extract_first_dict(record.get("beliggenhedsadresse"))
        history_industry = _extract_first_dict(record.get("hovedbranche"))

        cvr_value = normalize_vat(
            _pick_string(record, "cvr", "Cvr", "cvrNumber", "cvrNummer", "CVR", "vatNumber", "vat")
            or requested_cvr
        )
        legal_name = (
            _pick_string(record, "legalName", "LegalName", "name", "Name")
            or _pick_string(metadata_name or {}, "navn", "name", "Name")
            or _pick_string(_extract_first_dict(record.get("navne")) or {}, "navn", "name", "Name")
        )
        if not cvr_value or not legal_name:
            return None

        raw_address = record.get("address") or record.get("Address") or metadata_address or history_address
        address_value = _parse_address(raw_address)
        country = (
            _pick_string(record, "country", "Country", "countryCode", "CountryCode")
            or _pick_string(address_value, "country")
            or default_country
            or "DK"
        )
        geography = _pick_string(record, "geography", "Geography") or country
        postal_code = address_value["postal_code"] or _pick_string(record, "postalCode", "PostalCode", "zipcode", "Zipcode")
        city = address_value["city"] or _pick_string(record, "city", "City", "cityname", "cityName")
        trade_name = _pick_string(record, "tradeName", "TradeName") or _pick_string(metadata or {}, "nyesteBinavne") or legal_name
        raw_industry_value = _pick_string(record, "industry", "Industry")

        return CvrEnrichmentResult(
            cvr=cvr_value,
            legal_name=legal_name,
            trade_name=trade_name,
            address=address_value["address"],
            postal_code=postal_code,
            city=city,
            country=country,
            industry_code=(
                _normalize_industry_code(
                    _pick_string(
                        record,
                        "industryCode",
                        "IndustryCode",
                        "industrycode",
                        "industryBranchCode",
                        "IndustryBranchCode",
                    )
                )
                or _normalize_industry_code(_pick_string(metadata_industry or {}, "branchekode", "industryCode"))
                or _normalize_industry_code(_pick_string(history_industry or {}, "branchekode", "industryCode"))
                or _normalize_industry_code(raw_industry_value)
            ),
            industry_desc=(
                _pick_string(
                    record,
                    "industryDescription",
                    "IndustryDescription",
                    "industrydesc",
                    "IndustryDesc",
                )
                or _pick_string(metadata_industry or {}, "branchetekst", "industryDescription")
                or _pick_string(history_industry or {}, "branchetekst", "industryDescription")
                or (raw_industry_value if _normalize_industry_code(raw_industry_value) is None else None)
            ),
            size_bracket=_pick_string(record, "sizeBracket", "SizeBracket"),
            geography=geography,
        )

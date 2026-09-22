"""BUG-DISC-09 — the normalisation hand-off must select everything the evidence
adapter can parse.

The query hardcoded ``evidence_format == NMAP_XML``, so a Subfinder package was
never selected even though ``_parse_subfinder_text`` had been registered for it
all along. The parser existed; the query never handed it anything. Combined with
BUG-DISC-08 (nmap attached no evidence at all) nothing could ever be normalised,
so no discovery run ever produced an asset.
"""

from __future__ import annotations

import pytest
from sqlalchemy import create_engine
from sqlalchemy.dialects.postgresql import ARRAY as PgArray
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.dialects.sqlite import JSON as SqliteJSON
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool
from sqlalchemy.sql.sqltypes import ARRAY as SqlArray

from src.core.database import Base
from src.core.model_defs.discovery_execution import EvidencePackage
from src.core.model_defs.tenant_org import Organization
from src.core.services.discovery_execution_evidence_adapter import (
    SUPPORTED_EVIDENCE_PARSER_KEYS,
    _PARSERS_BY_FORMAT_AND_PROVIDER,
)

_TABLES = (Organization.__table__, EvidencePackage.__table__)


@pytest.fixture()
def db() -> Session:
    engine = create_engine("sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    for table in _TABLES:
        for column in table.columns:
            if isinstance(column.type, (SqlArray, PgArray, JSONB)):
                column.type = SqliteJSON()
    Base.metadata.create_all(engine, tables=list(_TABLES))
    session = sessionmaker(bind=engine)()
    session.add(Organization(id=1, name="Org", slug="org", country="DK"))
    session.commit()
    yield session
    session.close()


def _package(db: Session, *, provider_id: str, evidence_format: str, package_id: str) -> EvidencePackage:
    package = EvidencePackage(
        id=package_id,
        discovery_run_id="run-1",
        execution_plan_id="plan-1",
        execution_stage_id="stage-1",
        provider_execution_id=f"exec-{package_id}",
        organization_id=1,
        provider_id=provider_id,
        schema_version="1",
        raw_evidence_reference="ref",
        evidence_format=evidence_format,
        execution_metadata={},
        provenance_metadata={},
        processing_status="stored",
        normalization_status="pending",
    )
    db.add(package)
    db.commit()
    return package


def test_supported_keys_match_the_registered_parsers() -> None:
    """The hand-off selects on this set, so it must stay in step with the
    parsers the adapter actually has — that drift is the whole bug."""
    assert SUPPORTED_EVIDENCE_PARSER_KEYS == frozenset(_PARSERS_BY_FORMAT_AND_PROVIDER)


def test_subfinder_is_a_supported_parser_key() -> None:
    """Regression: a registered Subfinder parser was unreachable because the
    hand-off query only ever looked for nmap_xml."""
    assert ("text", "subfinder") in SUPPORTED_EVIDENCE_PARSER_KEYS
    assert ("nmap_xml", "nmap") in SUPPORTED_EVIDENCE_PARSER_KEYS


def test_pending_subfinder_package_is_selected(db: Session, monkeypatch) -> None:
    from src.core.services import discovery_normalization_handoff_service as handoff

    _package(db, provider_id="subfinder", evidence_format="text", package_id="pkg-subfinder")

    seen: list[str] = []

    def _fake_normalize(db_, *, organization_id, actor_user_id, source_type, execution_id):
        seen.append(execution_id)

    monkeypatch.setattr(handoff, "normalize_execution", _fake_normalize)
    handoff.process_pending_evidence_packages(db)

    assert seen == ["pkg-subfinder"], "a Subfinder package must be handed to the adapter"


def test_pending_nmap_package_is_still_selected(db: Session, monkeypatch) -> None:
    from src.core.services import discovery_normalization_handoff_service as handoff

    _package(db, provider_id="nmap", evidence_format="nmap_xml", package_id="pkg-nmap")

    seen: list[str] = []
    monkeypatch.setattr(
        handoff,
        "normalize_execution",
        lambda db_, **kw: seen.append(kw["execution_id"]),
    )
    handoff.process_pending_evidence_packages(db)

    assert seen == ["pkg-nmap"]


def test_nuclei_is_a_supported_parser_key() -> None:
    """The first parser that produces a *vulnerability* rather than an artefact.

    Until 2026-09-06 nuclei had no parser, and this file used it as its example
    of an unregistered provider — so registering one turned that test red for
    the right reason. The case it was guarding is real and is kept below; it
    just needed a pair that is genuinely unregistered.
    """
    assert ("json", "nuclei") in SUPPORTED_EVIDENCE_PARSER_KEYS


def test_package_with_no_registered_parser_is_not_selected(db: Session, monkeypatch) -> None:
    """Selection is driven by what can actually be parsed, so an unknown
    provider/format is left alone rather than handed to a missing parser."""
    from src.core.services import discovery_normalization_handoff_service as handoff

    assert ("binary", "masscan") not in SUPPORTED_EVIDENCE_PARSER_KEYS, (
        "this test needs a provider/format pair with no parser; pick another "
        "if masscan is ever registered"
    )
    _package(db, provider_id="masscan", evidence_format="binary", package_id="pkg-masscan")

    seen: list[str] = []
    monkeypatch.setattr(
        handoff,
        "normalize_execution",
        lambda db_, **kw: seen.append(kw["execution_id"]),
    )
    handoff.process_pending_evidence_packages(db)

    assert seen == []

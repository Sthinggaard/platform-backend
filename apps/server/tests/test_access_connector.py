"""CA-07.2 — a Connector exists, and its credentials never reach the platform.

The structural tests at the top are the ones that matter. "No code path can
return or log a raw credential" is only a real control if something checks the
shapes themselves — a reviewer noticing a new field is not a control, and the
field that breaks this will be added a year from now by someone who never read
the contract.
"""

from __future__ import annotations

import ast
import inspect
import pytest
from sqlalchemy import create_engine
from sqlalchemy.dialects.postgresql import ARRAY as PgArray
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.dialects.sqlite import JSON as SqliteJSON
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool
from sqlalchemy.sql.sqltypes import ARRAY as SqlArray

from src.api.routes import access_connector_lifecycle as lifecycle_routes
from src.api.routes import access_connectors as routes
from src.api.routes import connector_access_test_agent as agent_routes
from src.api.schemas import connector_access_test_schemas as test_schemas
from src.core.constants.access_connector_enums import (
    CONNECTOR_AUDIT_CREATED,
    CONNECTOR_AUDIT_CREDENTIAL_REGISTERED,
    CONNECTOR_FORBIDDEN_FIELD_FRAGMENTS,
    AccessConnectorType,
    ConnectorCredentialModel,
)
from src.core.constants.contextual_access_enums import (
    AccessOperatingMode,
    ContextualAccessDecision,
    ContextualAccessPolicyStatus,
)
from src.core.database import Base
from src.core.model_defs.access_connector import AccessConnector
from src.core.model_defs.common import utcnow
from src.core.model_defs.contextual_access_policy import ContextualAccessPolicy
from src.core.model_defs.permission_subject import PermissionSubject
from src.core.model_defs.evidence_scanner import ScannerInstance
from src.core.model_defs.evidence_source import EvidenceSource
from src.core.models import AuditEvent, Organization, User
from src.core.services import access_connector_service as service
from src.core.services.access_connector_service import (
    AccessConnectorValidationError,
    create_connector,
    resolve_permitted_credential_model,
    rotate_connector_fingerprint,
)

ORG_ID = 1
OTHER_ORG_ID = 2
ADMIN_USER_ID = 1
INSTANCE_ID = "scanner-1"
FINGERPRINT = "SHA256:abcdef0123456789abcdef0123456789abcdef01"


# --- The structural guarantees --------------------------------------------


def test_no_connector_schema_can_carry_secret_material():
    """The story's central claim, asserted against the real request/response models.

    Hashing a secret on arrival would be too late — it has already been in a
    request body, in memory, and in whatever traced the request. So the check is
    that no such field exists to be sent in the first place.
    """
    schemas = [
        routes.AccessConnectorCreateRequest,
        routes.AccessConnectorRotateRequest,
        routes.AccessConnectorResponse,
        routes.AccessConnectorListResponse,
        routes.PermittedCredentialModelResponse,
        # CA-07.4's surfaces are swept by the same check. A structural guarantee
        # that only covered the first story's models would decay the moment a
        # second Connector surface arrived — which it now has.
        lifecycle_routes.ConnectorRevocationRequest,
        agent_routes.AccessTestResultRequest,
        test_schemas.ConnectorAccessTestResponse,
        test_schemas.ConnectorAccessTestListResponse,
    ]
    offenders = []
    for schema in schemas:
        for field_name in schema.model_fields:
            lowered = field_name.lower()
            for fragment in CONNECTOR_FORBIDDEN_FIELD_FRAGMENTS:
                # "credential_fingerprint" is public identifying material and is
                # the one permitted use of the word.
                if fragment in lowered and "fingerprint" not in lowered:
                    offenders.append(f"{schema.__name__}.{field_name}")
    assert offenders == [], f"Connector schemas must not carry secret material: {offenders}"


def test_no_connector_column_can_carry_secret_material():
    offenders = [
        column.name
        for column in AccessConnector.__table__.columns
        for fragment in CONNECTOR_FORBIDDEN_FIELD_FRAGMENTS
        if fragment in column.name.lower() and "fingerprint" not in column.name.lower()
    ]
    assert offenders == [], f"AccessConnector must not persist secret material: {offenders}"


def test_the_connector_service_never_imports_the_forbidden_encryption_machinery():
    """CredentialEncryption stores secrets the platform can decrypt.

    Reaching for it looks like good reuse and breaks the contract, which is
    exactly why this is asserted rather than left to a comment.

    Checks the module's real imports via AST rather than searching its text —
    the service's own docstring names the forbidden machinery in order to warn
    about it, and a text search cannot tell a warning from a use.
    """
    tree = ast.parse(inspect.getsource(service))
    imported: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported.update(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom):
            imported.add(node.module or "")
            imported.update(alias.name for alias in node.names)

    forbidden = {"CredentialEncryption", "CloudCredentials", "src.core.crypto"}
    assert not (imported & forbidden), f"Connector service must not import: {imported & forbidden}"
    assert not any(name.endswith("crypto") for name in imported)


def test_no_connector_function_accepts_a_credential_parameter():
    """A signature that cannot take a secret cannot leak one."""
    offenders = []
    for name, fn in inspect.getmembers(service, inspect.isfunction):
        if fn.__module__ != service.__name__:
            continue
        for param in inspect.signature(fn).parameters:
            lowered = param.lower()
            for fragment in CONNECTOR_FORBIDDEN_FIELD_FRAGMENTS:
                if fragment in lowered and "fingerprint" not in lowered:
                    offenders.append(f"{name}({param})")
    assert offenders == [], f"Connector functions must not accept secrets: {offenders}"


# --- Fixtures --------------------------------------------------------------


@pytest.fixture()
def db() -> Session:
    engine = create_engine(
        "sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool
    )
    for table in Base.metadata.tables.values():
        for column in table.columns:
            if isinstance(column.type, (SqlArray, PgArray, JSONB)):
                column.type = SqliteJSON()
    Base.metadata.create_all(
        engine,
        tables=[
            Organization.__table__,
            User.__table__,
            EvidenceSource.__table__,
            ScannerInstance.__table__,
            ContextualAccessPolicy.__table__,
            PermissionSubject.__table__,
            AccessConnector.__table__,
            AuditEvent.__table__,
        ],
    )
    session = sessionmaker(bind=engine)()
    session.add_all(
        [
            Organization(id=ORG_ID, name="Org", slug="org"),
            Organization(id=OTHER_ORG_ID, name="Other", slug="other"),
            User(id=ADMIN_USER_ID, organization_id=ORG_ID, email="a@example.com", role="org_admin"),
            EvidenceSource(
                id="source-1",
                organization_id=ORG_ID,
                name="Source",
                type="scanner",
                mode="agent",
            ),
            ScannerInstance(
                id=INSTANCE_ID,
                organization_id=ORG_ID,
                evidence_source_id="source-1",
                name="Auth & Access scanner",
                installation_method="docker",
                status="registered",
                activation_token_hash="hash-1",
            ),
        ]
    )
    session.commit()
    yield session
    session.close()


def _approve_mode(db: Session, mode: str, organization_id: int = ORG_ID) -> ContextualAccessPolicy:
    policy = ContextualAccessPolicy(
        organization_id=organization_id,
        decision=ContextualAccessDecision.ACCESS_OPERATING_MODE.value,
        choice=mode,
        status=ContextualAccessPolicyStatus.ACTIVE.value,
        version=1,
        consequence_statement="Stated before approval.",
        consequence_acknowledged=True,
        approved_by=str(ADMIN_USER_ID),
        approved_at=utcnow(),
        effective_from=utcnow(),
    )
    db.add(policy)
    db.commit()
    return policy


def _create(db: Session, **kwargs) -> AccessConnector:
    connector = create_connector(
        db,
        organization_id=kwargs.pop("organization_id", ORG_ID),
        scanner_instance_id=kwargs.pop("scanner_instance_id", INSTANCE_ID),
        connector_type=kwargs.pop("connector_type", AccessConnectorType.SSH_RESTRICTED.value),
        target_host=kwargs.pop("target_host", "db-01.internal"),
        created_by_user_id=ADMIN_USER_ID,
        **kwargs,
    )
    db.commit()
    return connector


# --- CA-07.0 gates this story ---------------------------------------------


def test_a_connector_cannot_be_configured_before_the_operating_mode_is_decided(db: Session):
    with pytest.raises(AccessConnectorValidationError, match="has not decided"):
        _create(db, credential_fingerprint=FINGERPRINT)


def test_mode_a_requires_a_collector_resident_credential(db: Session):
    _approve_mode(db, AccessOperatingMode.SCHEDULED_AUTONOMOUS.value)

    assert (
        resolve_permitted_credential_model(db, ORG_ID)
        == ConnectorCredentialModel.COLLECTOR_RESIDENT.value
    )
    with pytest.raises(AccessConnectorValidationError, match="nobody present"):
        _create(db, credential_model=ConnectorCredentialModel.OPERATOR_SUPPLIED.value)


def test_mode_b_defaults_to_operator_supplied_and_stores_nothing(db: Session):
    _approve_mode(db, AccessOperatingMode.PROCESS_TRIGGERED.value)

    connector = _create(db)

    assert connector.credential_model == ConnectorCredentialModel.OPERATOR_SUPPLIED.value
    assert connector.credential_fingerprint is None
    assert connector.credential_registered_at is None


def test_mode_b_may_still_choose_a_collector_resident_credential(db: Session):
    """A person being present does not forbid keeping a key on the Collector."""
    _approve_mode(db, AccessOperatingMode.PROCESS_TRIGGERED.value)

    connector = _create(
        db,
        credential_model=ConnectorCredentialModel.COLLECTOR_RESIDENT.value,
        credential_fingerprint=FINGERPRINT,
    )

    assert connector.credential_model == ConnectorCredentialModel.COLLECTOR_RESIDENT.value


def test_an_operator_supplied_connector_refuses_a_fingerprint(db: Session):
    """Nothing durable is held, so recording an identifier would contradict that."""
    _approve_mode(db, AccessOperatingMode.PROCESS_TRIGGERED.value)

    with pytest.raises(AccessConnectorValidationError, match="never stored"):
        _create(
            db,
            credential_model=ConnectorCredentialModel.OPERATOR_SUPPLIED.value,
            credential_fingerprint=FINGERPRINT,
        )


# --- The three Connector types --------------------------------------------


@pytest.mark.parametrize(
    "connector_type",
    [t.value for t in AccessConnectorType],
)
def test_every_connector_type_the_contract_names_is_supported(db: Session, connector_type: str):
    _approve_mode(db, AccessOperatingMode.SCHEDULED_AUTONOMOUS.value)

    connector = _create(db, connector_type=connector_type, credential_fingerprint=FINGERPRINT)

    assert connector.connector_type == connector_type


def test_a_docker_connector_declares_it_needs_socket_approval(db: Session):
    """Declared, never granted — the approval itself is CA-07.3's."""
    _approve_mode(db, AccessOperatingMode.SCHEDULED_AUTONOMOUS.value)

    connector = _create(
        db,
        connector_type=AccessConnectorType.DOCKER_READONLY.value,
        credential_fingerprint=FINGERPRINT,
    )

    assert connector.requires_docker_socket is True


def test_an_unknown_connector_type_is_refused(db: Session):
    _approve_mode(db, AccessOperatingMode.SCHEDULED_AUTONOMOUS.value)

    with pytest.raises(AccessConnectorValidationError, match="Unknown Connector type"):
        _create(db, connector_type="rdp_full_desktop", credential_fingerprint=FINGERPRINT)


# --- Fingerprints identify; they never carry ------------------------------


def test_a_collector_resident_credential_must_be_registered_by_fingerprint(db: Session):
    _approve_mode(db, AccessOperatingMode.SCHEDULED_AUTONOMOUS.value)

    with pytest.raises(AccessConnectorValidationError, match="by fingerprint"):
        _create(db)


def test_a_pasted_private_key_is_refused_rather_than_stored(db: Session):
    """The clearest sign somebody sent the credential itself instead of its id.

    Refused loudly, because a private key that reaches the database is not fixed
    by rejecting the next one.
    """
    _approve_mode(db, AccessOperatingMode.SCHEDULED_AUTONOMOUS.value)

    for pasted in (
        "-----BEGIN OPENSSH PRIVATE KEY-----abcdefghijklmnop",
        "-----BEGIN RSA PRIVATE KEY-----MIIEowIBAAKCAQEA",
    ):
        with pytest.raises(AccessConnectorValidationError, match="fingerprint"):
            _create(db, credential_fingerprint=pasted)

    assert db.query(AccessConnector).count() == 0


def test_a_fingerprint_that_is_too_long_or_malformed_is_refused(db: Session):
    _approve_mode(db, AccessOperatingMode.SCHEDULED_AUTONOMOUS.value)

    for bad in ("short", "x" * 200, "has spaces in it here"):
        with pytest.raises(AccessConnectorValidationError, match="fingerprint"):
            _create(db, credential_fingerprint=bad)


def test_rotation_records_the_new_fingerprint_without_performing_the_rotation(db: Session):
    _approve_mode(db, AccessOperatingMode.SCHEDULED_AUTONOMOUS.value)
    connector = _create(db, credential_fingerprint=FINGERPRINT)
    new_fingerprint = "SHA256:99887766554433221100ffeeddccbbaa99887766"

    rotate_connector_fingerprint(
        db, connector, credential_fingerprint=new_fingerprint, rotated_by_user_id=ADMIN_USER_ID
    )
    db.commit()

    assert connector.credential_fingerprint == new_fingerprint
    assert connector.credential_rotated_at is not None


def test_an_operator_supplied_connector_cannot_rotate_a_fingerprint_it_never_had(db: Session):
    _approve_mode(db, AccessOperatingMode.PROCESS_TRIGGERED.value)
    connector = _create(db)

    with pytest.raises(AccessConnectorValidationError):
        rotate_connector_fingerprint(db, connector, credential_fingerprint=FINGERPRINT)


# --- What leaves the platform ---------------------------------------------


def test_the_read_surface_never_returns_a_whole_fingerprint(db: Session):
    _approve_mode(db, AccessOperatingMode.SCHEDULED_AUTONOMOUS.value)
    connector = _create(db, credential_fingerprint=FINGERPRINT)

    response = routes.to_connector_response(connector)

    assert response.credential_fingerprint_preview is not None
    assert response.credential_fingerprint_preview != FINGERPRINT
    assert FINGERPRINT not in response.model_dump_json()


def test_the_audit_trail_carries_what_was_configured_but_not_which_key(db: Session):
    _approve_mode(db, AccessOperatingMode.SCHEDULED_AUTONOMOUS.value)
    _create(db, credential_fingerprint=FINGERPRINT, target_username="risklence-ro")

    events = db.query(AuditEvent).all()
    types = {e.event_type for e in events}
    assert CONNECTOR_AUDIT_CREATED in types
    assert CONNECTOR_AUDIT_CREDENTIAL_REGISTERED in types
    for event in events:
        serialised = str(event.metadata_json)
        assert FINGERPRINT not in serialised
    # It still answers the question an auditor actually asks.
    created = next(e for e in events if e.event_type == CONNECTOR_AUDIT_CREATED)
    assert created.metadata_json["target_host"] == "db-01.internal"
    assert created.metadata_json["target_username"] == "risklence-ro"


# --- Tenancy ---------------------------------------------------------------


def test_a_connector_belongs_to_one_organisation_and_is_unreachable_from_another(db: Session):
    _approve_mode(db, AccessOperatingMode.SCHEDULED_AUTONOMOUS.value)
    _create(db, credential_fingerprint=FINGERPRINT)

    assert len(service.list_connectors(db, organization_id=ORG_ID)) == 1
    assert service.list_connectors(db, organization_id=OTHER_ORG_ID) == []


def test_another_organisations_approved_mode_does_not_authorise_this_one(db: Session):
    _approve_mode(db, AccessOperatingMode.SCHEDULED_AUTONOMOUS.value, organization_id=OTHER_ORG_ID)

    with pytest.raises(AccessConnectorValidationError, match="has not decided"):
        _create(db, credential_fingerprint=FINGERPRINT)


def test_a_connector_must_say_what_it_reaches(db: Session):
    _approve_mode(db, AccessOperatingMode.SCHEDULED_AUTONOMOUS.value)

    with pytest.raises(AccessConnectorValidationError, match="what it reaches"):
        _create(db, target_host="   ", credential_fingerprint=FINGERPRINT)

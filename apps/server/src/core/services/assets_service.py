from __future__ import annotations

import secrets
from datetime import datetime

from sqlalchemy.orm import Session

from src.core.constants import (
    ALLOWED_LAYERS_BY_ARCHETYPE,
    ARCHETYPE_LABELS,
    AssetArchetype,
    LAYER_ARCHETYPES,
    Provider,
)
from src.core.models import (
    Asset,
    AssetConnection,
    AssetEvidenceSignal,
    AssetStatus,
    ConnectivityStatus,
    ConnectionState,
    SetupConfidence,
)
from src.core.models import AssetStatusHistory, ScanStartMode
from src.core.logging_config import get_logger
from src.core.services.provider_adapters import get_provider_adapter
from src.core.services.asset_schema import get_layer_label_and_description

logger = get_logger(__name__)


class PayloadValidationError(ValueError):
    def __init__(self, field_errors: list[dict[str, str]]):
        super().__init__("Validation failed")
        self.field_errors = field_errors


def _field_error(field: str, message: str, code: str = "INVALID_INPUT") -> dict[str, str]:
    return {"field": field, "message": message, "code": code}


def _generate_external_id() -> str:
    return secrets.token_urlsafe(24)


def _validate_create_payload(payload) -> None:
    errors: list[dict[str, str]] = []

    display_name = getattr(payload, "display_name", "")
    if not display_name or not display_name.strip():
        errors.append(_field_error("display_name", "Asset name is required."))

    provider = getattr(payload, "provider", None)
    provider_display_name = getattr(payload, "provider_display_name", None)
    if provider == Provider.OTHER.value and not provider_display_name:
        errors.append(_field_error("provider_display_name", "Provider name is required when provider is Other."))

    layer = getattr(payload, "layer", None)
    archetype = getattr(payload, "archetype", None)
    allowed_archetypes = LAYER_ARCHETYPES.get(layer, [])
    if layer and archetype and archetype not in allowed_archetypes:
        if not getattr(payload, "advanced_override", False):
            archetype_label = ARCHETYPE_LABELS.get(archetype, archetype.value)
            layer_label = get_layer_label_and_description(layer)
            layer_display = layer_label[0] if layer_label else layer
            allowed_layers = ALLOWED_LAYERS_BY_ARCHETYPE.get(archetype, [])
            valid_layers = ", ".join(allowed_layers) or "the compatible OSI layer"
            message = f"{archetype_label} cannot be placed in {layer_display}. Allowed: {valid_layers}."
            errors.append(_field_error("archetype", message, code="LAYER_NOT_ALLOWED"))

    if getattr(payload, "advanced_override", False) and not getattr(payload, "override_reason", None):
        errors.append(_field_error("override_reason", "Override reason required when using advanced override.", code="MISSING_OVERRIDE_REASON"))

    if archetype == AssetArchetype.CLOUD_ACCOUNT_GOVERNANCE:
        acct = getattr(payload, "provider_account_id", None)
        if not acct or not acct.strip():
            errors.append(_field_error("provider_account_id", "Cloud account identifier is required for governance assets."))
        elif provider == Provider.AWS.value and (not acct.strip().isdigit() or len(acct.strip()) != 12):
            errors.append(_field_error("provider_account_id", "AWS account id must be 12 digits.", code="INVALID_FORMAT"))

    if errors:
        raise PayloadValidationError(errors)


def create_asset_with_connection(
    db: Session,
    organization_id: int,
    created_by_ref: str | None,
    payload,
):
    """Create asset and connection in pending verification state."""
    _validate_create_payload(payload)
    setup_assignee = payload.setup_assignee_ref or payload.technical_owner_ref

    asset = Asset(
        organization_id=organization_id,
        type=payload.type,
        provider=payload.provider,
        provider_display_name=getattr(payload, "provider_display_name", None),
        display_name=payload.display_name,
        layer=str(payload.layer),
        environment=payload.environment,
        criticality=payload.criticality,
        status=AssetStatus.NOT_CONNECTED,
        connectivity_status=ConnectivityStatus.PENDING_VERIFICATION,
        setup_confidence=payload.setup_confidence,
        scan_start_mode=payload.scan_start_mode,
        secondary_layers=payload.secondary_layers or None,
        intent=payload.intent,
        business_owner_ref=payload.business_owner_ref,
        technical_owner_ref=payload.technical_owner_ref,
        setup_assignee_ref=setup_assignee,
        created_by_ref=created_by_ref,
    )
    db.add(asset)
    db.flush()

    connection = AssetConnection(
        asset_id=asset.id,
        provider=payload.provider,
        provider_account_id=(payload.provider_account_id or "").strip() or None,
        permission_preset=payload.permission_preset or "SECURITY_READONLY",
        auth_method=getattr(payload, "access_method", None),
        provider_resource_id=(getattr(payload, "provider_resource_id", None) or "").strip() or None,
        external_id=_generate_external_id(),
        connection_state=ConnectionState.INSTRUCTIONS_ISSUED,
        state="DISCONNECTED",
    )
    if payload.advanced_override and payload.override_reason:
        detail = payload.override_reason.strip()
        connection.last_error_code = "ADVANCED_OVERRIDE"
        connection.last_error_detail = detail
        logger.info("Advanced override engaged for asset %s: %s", asset.id, detail)
    db.add(connection)
    db.commit()
    db.refresh(asset)
    db.refresh(connection)

    setup_url = f"/orgs/{organization_id}/assets/{asset.id}/complete-setup"
    return asset, connection, setup_url


def complete_access_setup(db: Session, asset: Asset, role_arn: str, actor_ref: str | None = None) -> AssetConnection:
    connection = asset.connections[0] if asset.connections else None
    if not connection:
        raise ValueError("Asset connection not found")
    connection.role_arn = role_arn
    connection.connection_state = ConnectionState.PENDING
    connection.updated_at = datetime.utcnow()
    db.add(connection)
    db.commit()
    db.refresh(connection)
    return connection


def verify_connection(
    db: Session, asset: Asset, diagnostic_on_failure: bool = False
) -> tuple[bool, AssetConnection, AssetEvidenceSignal | None]:
    connection = asset.connections[0] if asset.connections else None
    if not connection:
        raise ValueError("Asset connection not found")

    adapter = get_provider_adapter(asset.provider or "")
    success, diagnostic = adapter.verify(
        role_arn=connection.role_arn,
        external_id=connection.external_id,
        provider_account_id=connection.provider_account_id,
    )

    signal = None
    if success:
        asset.connectivity_status = ConnectivityStatus.CONNECTED
        connection.connection_state = ConnectionState.VERIFIED
        connection.validated_at = datetime.utcnow()
        signal = AssetEvidenceSignal(
            organization_id=asset.organization_id,
            asset_id=asset.id,
            kind="HANDSHAKE",
            payload_json={
                "provider_account_id": connection.provider_account_id,
                "role_arn": connection.role_arn,
            },
            observed_at=datetime.utcnow(),
            confidence=1.0,
        )
        db.add(signal)
        history = AssetStatusHistory(
            asset_id=asset.id,
            status=asset.status,
            connectivity_status=asset.connectivity_status,
            connection_state=connection.connection_state,
            observed_at=datetime.utcnow(),
        )
        db.add(history)
        diagnostic_msg = None
    else:
        connection.connection_state = ConnectionState.FAILED
        asset.connectivity_status = ConnectivityStatus.PENDING_VERIFICATION
        diagnostic_msg = diagnostic if diagnostic_on_failure else None
        connection.last_error_code = diagnostic

    db.add(asset)
    db.add(connection)
    db.commit()
    db.refresh(connection)
    db.refresh(asset)
    return success, connection, signal, diagnostic_msg


def start_monitoring(db: Session, asset: Asset):
    if asset.scan_start_mode == ScanStartMode.AFTER_SME_CONFIRM:
        logger.info("Asset %s requires SME confirm before monitoring", asset.id)
        return False
    # Stub: set status history marker
    history = AssetStatusHistory(
        asset_id=asset.id,
        status=asset.status,
        connectivity_status=asset.connectivity_status,
        connection_state=asset.connections[0].connection_state if asset.connections else None,
        observed_at=datetime.utcnow(),
    )
    db.add(history)
    db.commit()
    return True


def notify_setup_assignee(asset: Asset, assignee_ref: str | None):
    logger.info("Notify setup assignee %s for asset %s", assignee_ref, asset.id)

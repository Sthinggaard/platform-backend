"""Backfill process–service linkage for pre-UC-TDM-01 ValueStream rows.

Before UC-TDM-01, POST /api/v1/value-streams only created the ValueStream row
and did NOT auto-create BusinessService rows for each core_service_key.

This migration finds every template-backed ValueStream that has no linked
BusinessService rows and repairs the linkage:

  Case A — BusinessService with matching library_item_id already exists in the
            same org: add the ValueStream ID to value_stream_ids.

  Case B — No matching BusinessService exists: create one from the template
            definition (name, archetype, template_key) so the process detail
            view has something to display.

Revision ID: 20250411_backfill_process_service_linkage
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Union, Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy import text

revision: str = "20250411_backfill_process_service_linkage"
down_revision: Union[str, None] = "20250411_template_candidates"
branch_labels: Union[Sequence[str], None] = None
depends_on: Union[Sequence[str], None] = None


# ---------------------------------------------------------------------------
# Inline service-key lookup — avoids importing src.core at migration time.
# Built from service_key_archetypes.py constants; update when new keys land.
# ---------------------------------------------------------------------------

_SERVICE_KEY_NAMES: dict[str, str] = {
    "payment_processing": "Payment Processing",
    "billing_service": "Billing Service",
    "order_management": "Order Management",
    "inventory_management": "Inventory Management",
    "customer_portal": "Customer Portal",
    "crm_system": "CRM System",
    "sales_operations": "Sales Operations",
    "marketing_automation": "Marketing Automation",
    "lead_generation": "Lead Generation",
    "campaign_management": "Campaign Management",
    "hr_information_system": "HR Information System",
    "payroll_processing": "Payroll Processing",
    "recruitment_platform": "Recruitment Platform",
    "talent_management": "Talent Management",
    "learning_management": "Learning Management",
    "financial_reporting": "Financial Reporting",
    "accounts_payable": "Accounts Payable",
    "accounts_receivable": "Accounts Receivable",
    "budgeting_tool": "Budgeting Tool",
    "expense_management": "Expense Management",
    "it_service_desk": "IT Service Desk",
    "identity_provider": "Identity Provider",
    "endpoint_management": "Endpoint Management",
    "network_monitoring": "Network Monitoring",
    "backup_recovery": "Backup & Recovery",
    "data_warehouse": "Data Warehouse",
    "analytics_platform": "Analytics Platform",
    "etl_pipeline": "ETL Pipeline",
    "reporting_tool": "Reporting Tool",
    "data_governance": "Data Governance",
    "ecommerce_platform": "E-commerce Platform",
    "product_catalog": "Product Catalog",
    "shipping_fulfillment": "Shipping & Fulfillment",
    "returns_management": "Returns Management",
    "customer_support": "Customer Support",
    "document_management": "Document Management",
    "legal_contract_management": "Legal & Contract Management",
    "compliance_management": "Compliance Management",
    "risk_management": "Risk Management",
    "audit_management": "Audit Management",
    "procurement_platform": "Procurement Platform",
    "vendor_management": "Vendor Management",
    "contract_management": "Contract Management",
    "asset_management": "Asset Management",
    "facilities_management": "Facilities Management",
    "project_management": "Project Management",
    "collaboration_platform": "Collaboration Platform",
    "communication_platform": "Communication Platform",
    "code_repository": "Code Repository",
    "ci_cd_pipeline": "CI/CD Pipeline",
    "cloud_infrastructure": "Cloud Infrastructure",
    "monitoring_alerting": "Monitoring & Alerting",
    "api_gateway": "API Gateway",
    "load_balancer": "Load Balancer",
    "cdn": "CDN",
    "secret_management": "Secret Management",
    "logging_platform": "Logging Platform",
    "feature_flag_platform": "Feature Flag Platform",
    "release_management": "Release Management",
}

_SERVICE_KEY_ARCHETYPES: dict[str, str] = {
    "payment_processing": "fintech",
    "billing_service": "saas_platform",
    "order_management": "ecommerce",
    "inventory_management": "ecommerce",
    "customer_portal": "saas_platform",
    "crm_system": "saas_platform",
    "sales_operations": "saas_platform",
    "marketing_automation": "saas_platform",
    "lead_generation": "saas_platform",
    "campaign_management": "saas_platform",
    "hr_information_system": "enterprise_hr",
    "payroll_processing": "enterprise_hr",
    "recruitment_platform": "enterprise_hr",
    "talent_management": "enterprise_hr",
    "learning_management": "enterprise_hr",
    "financial_reporting": "enterprise_finance",
    "accounts_payable": "enterprise_finance",
    "accounts_receivable": "enterprise_finance",
    "budgeting_tool": "enterprise_finance",
    "expense_management": "enterprise_finance",
    "it_service_desk": "it_operations",
    "identity_provider": "it_operations",
    "endpoint_management": "it_operations",
    "network_monitoring": "it_operations",
    "backup_recovery": "it_operations",
    "data_warehouse": "data_platform",
    "analytics_platform": "data_platform",
    "etl_pipeline": "data_platform",
    "reporting_tool": "data_platform",
    "data_governance": "data_platform",
    "ecommerce_platform": "ecommerce",
    "product_catalog": "ecommerce",
    "shipping_fulfillment": "ecommerce",
    "returns_management": "ecommerce",
    "customer_support": "saas_platform",
    "document_management": "enterprise_ops",
    "legal_contract_management": "enterprise_ops",
    "compliance_management": "enterprise_ops",
    "risk_management": "enterprise_ops",
    "audit_management": "enterprise_ops",
    "procurement_platform": "enterprise_ops",
    "vendor_management": "enterprise_ops",
    "contract_management": "enterprise_ops",
    "asset_management": "it_operations",
    "facilities_management": "enterprise_ops",
    "project_management": "saas_platform",
    "collaboration_platform": "saas_platform",
    "communication_platform": "saas_platform",
    "code_repository": "devops",
    "ci_cd_pipeline": "devops",
    "cloud_infrastructure": "devops",
    "monitoring_alerting": "devops",
    "api_gateway": "devops",
    "load_balancer": "devops",
    "cdn": "devops",
    "secret_management": "devops",
    "logging_platform": "devops",
    "feature_flag_platform": "devops",
    "release_management": "devops",
}

# Inline VALUE_STREAM_BY_KEY core_service_keys for the same reason.
# Mirrors src/core/constants/value_stream_library.py.
_PROCESS_CORE_SERVICE_KEYS: dict[str, list[str]] = {
    "order_to_cash": [
        "order_management",
        "payment_processing",
        "billing_service",
        "customer_portal",
        "inventory_management",
    ],
    "procure_to_pay": [
        "procurement_platform",
        "vendor_management",
        "contract_management",
        "accounts_payable",
        "expense_management",
    ],
    "hire_to_retire": [
        "hr_information_system",
        "payroll_processing",
        "recruitment_platform",
        "talent_management",
        "learning_management",
    ],
    "record_to_report": [
        "financial_reporting",
        "accounts_receivable",
        "accounts_payable",
        "budgeting_tool",
        "audit_management",
    ],
    "lead_to_close": [
        "crm_system",
        "sales_operations",
        "marketing_automation",
        "lead_generation",
        "campaign_management",
    ],
    "issue_to_resolution": [
        "it_service_desk",
        "identity_provider",
        "endpoint_management",
        "network_monitoring",
        "backup_recovery",
    ],
    "data_to_insight": [
        "data_warehouse",
        "analytics_platform",
        "etl_pipeline",
        "reporting_tool",
        "data_governance",
    ],
    "ship_to_deliver": [
        "ecommerce_platform",
        "inventory_management",
        "shipping_fulfillment",
        "returns_management",
        "customer_support",
    ],
    "plan_to_produce": [
        "project_management",
        "asset_management",
        "facilities_management",
        "risk_management",
        "compliance_management",
    ],
    "govern_to_comply": [
        "compliance_management",
        "risk_management",
        "audit_management",
        "legal_contract_management",
        "document_management",
    ],
    "build_to_operate": [
        "code_repository",
        "ci_cd_pipeline",
        "cloud_infrastructure",
        "monitoring_alerting",
        "api_gateway",
    ],
    "design_to_deploy": [
        "project_management",
        "collaboration_platform",
        "code_repository",
        "ci_cd_pipeline",
        "release_management",
    ],
}


def upgrade() -> None:
    conn = op.get_bind()
    now = datetime.utcnow()

    # ── 1. Fetch all template-backed value streams ────────────────────────────
    vs_rows = conn.execute(
        text(
            "SELECT id, organization_id, library_item_id "
            "FROM value_streams "
            "WHERE library_item_id IS NOT NULL"
        )
    ).fetchall()

    if not vs_rows:
        return

    for vs_id, org_id, lib_key in vs_rows:
        core_keys = _PROCESS_CORE_SERVICE_KEYS.get(lib_key)
        if not core_keys:
            # Unknown process template — nothing to backfill.
            continue

        # ── 2. Check if this VS already has linked services ───────────────────
        linked_count = conn.execute(
            text(
                "SELECT COUNT(*) FROM business_services "
                "WHERE organization_id = :org_id "
                "AND :vs_id = ANY(value_stream_ids)"
            ),
            {"org_id": org_id, "vs_id": vs_id},
        ).scalar()

        if linked_count and linked_count > 0:
            # Already linked — nothing to do.
            continue

        # ── 3. Get org-level excluded service keys ────────────────────────────
        exc_row = conn.execute(
            text(
                "SELECT excluded_service_keys FROM org_process_configs "
                "WHERE organization_id = :org_id AND template_key = :lib_key"
            ),
            {"org_id": org_id, "lib_key": lib_key},
        ).fetchone()
        excluded: set[str] = set(exc_row[0] or []) if exc_row and exc_row[0] else set()

        # ── 4. Get latest active service template versions ────────────────────
        template_versions: dict[str, int | None] = {}
        for svc_key in core_keys:
            if svc_key in excluded:
                continue
            tmpl = conn.execute(
                text(
                    "SELECT version FROM service_templates "
                    "WHERE service_key = :key AND is_active = TRUE "
                    "ORDER BY version DESC LIMIT 1"
                ),
                {"key": svc_key},
            ).fetchone()
            template_versions[svc_key] = tmpl[0] if tmpl else None

        # ── 5. Case A or B per service key ───────────────────────────────────
        for svc_key in core_keys:
            if svc_key in excluded:
                continue

            existing = conn.execute(
                text(
                    "SELECT id, value_stream_ids FROM business_services "
                    "WHERE organization_id = :org_id AND library_item_id = :key "
                    "ORDER BY id LIMIT 1"
                ),
                {"org_id": org_id, "key": svc_key},
            ).fetchone()

            if existing:
                # Case A — service exists but not linked; add vs_id.
                svc_id, current_ids = existing
                if not current_ids:
                    current_ids = []
                if vs_id not in current_ids:
                    conn.execute(
                        text(
                            "UPDATE business_services "
                            "SET value_stream_ids = array_append(value_stream_ids, :vs_id) "
                            "WHERE id = :svc_id"
                        ),
                        {"vs_id": vs_id, "svc_id": svc_id},
                    )
            else:
                # Case B — service does not exist; create it.
                svc_id = str(uuid.uuid4())
                name = _SERVICE_KEY_NAMES.get(svc_key, svc_key.replace("_", " ").title())
                archetype = _SERVICE_KEY_ARCHETYPES.get(svc_key)
                tmpl_ver = template_versions.get(svc_key)

                conn.execute(
                    text(
                        "INSERT INTO business_services "
                        "(id, organization_id, name, tier, trading_impact, "
                        " library_item_id, archetype, template_key, template_version, "
                        " value_stream_ids, created_at, updated_at) "
                        "VALUES "
                        "(:id, :org_id, :name, 'Business Critical', '', "
                        " :lib_id, :archetype, :tmpl_key, :tmpl_ver, "
                        " ARRAY[:vs_id]::text[], :now, :now)"
                    ),
                    {
                        "id": svc_id,
                        "org_id": org_id,
                        "name": name,
                        "lib_id": svc_key,
                        "archetype": archetype,
                        "tmpl_key": svc_key,
                        "tmpl_ver": tmpl_ver,
                        "vs_id": vs_id,
                        "now": now,
                    },
                )


def downgrade() -> None:
    # No safe downgrade — we can't distinguish rows we created from rows the
    # application created legitimately after UC-TDM-01.
    pass

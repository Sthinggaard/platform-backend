"""Add recommendations and decision_records tables

Revision ID: 20250416_recommendations_and_decision_records
Revises: 20250411_backfill_process_service_linkage
Create Date: 2026-04-16 00:00:00.000000
"""

from __future__ import annotations

import json
import uuid
from datetime import datetime, timezone

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects.postgresql import JSONB

revision = "20250416_recommendations_and_decision_records"
down_revision = "20250411_backfill_process_service_linkage"
branch_labels = None
depends_on = None

ACTION_ACCEPTED = "accepted"
DECISION_TYPE_RECOMMENDED = "recommended"
DECISION_TYPE_ALTERNATIVE = "alternative"
RECOMMENDATION_STATUS_OPEN = "open"
RECOMMENDATION_STATUS_DECIDED = "decided"


def _table_exists(conn, table: str) -> bool:
    return conn.execute(
        sa.text(
            "SELECT 1 FROM information_schema.tables "
            "WHERE table_name=:t"
        ),
        {"t": table},
    ).fetchone() is not None


def _index_exists(conn, index_name: str) -> bool:
    return conn.execute(
        sa.text("SELECT 1 FROM pg_indexes WHERE indexname = :i"),
        {"i": index_name},
    ).fetchone() is not None


def _parse_timestamp(value: str | None, fallback: datetime) -> datetime:
    if not value:
        return fallback
    try:
        parsed = datetime.strptime(value, "%Y-%m-%d %H:%M")
        return parsed.replace(tzinfo=timezone.utc)
    except ValueError:
        return fallback


def upgrade() -> None:
    conn = op.get_bind()

    if not _table_exists(conn, "recommendations"):
        op.create_table(
            "recommendations",
            sa.Column("id", sa.String(36), primary_key=True),
            sa.Column(
                "organization_id",
                sa.Integer(),
                sa.ForeignKey("organizations.id", ondelete="CASCADE"),
                nullable=False,
            ),
            sa.Column(
                "threat_id",
                sa.String(36),
                sa.ForeignKey("threats.id", ondelete="SET NULL"),
                nullable=True,
            ),
            sa.Column("status", sa.String(20), nullable=False, server_default=RECOMMENDATION_STATUS_OPEN),
            sa.Column("linked_context_type", sa.String(20), nullable=False, server_default="asset"),
            sa.Column("linked_context_id", sa.String(200), nullable=False),
            sa.Column("linked_context_label", sa.String(255), nullable=True),
            sa.Column("problem", sa.Text(), nullable=False),
            sa.Column("why_it_matters", sa.Text(), nullable=False),
            sa.Column("suggested_action", sa.String(20), nullable=False),
            sa.Column("confidence_score", sa.Integer(), nullable=False, server_default="0"),
            sa.Column("is_stale", sa.Boolean(), nullable=False, server_default=sa.false()),
            sa.Column("intelligence_snapshot", JSONB(), nullable=False, server_default=sa.text("'{}'::jsonb")),
            sa.Column("generated_at", sa.DateTime(), nullable=False),
            sa.Column("created_at", sa.DateTime(), nullable=False),
            sa.Column("updated_at", sa.DateTime(), nullable=False),
        )

    if not _index_exists(conn, "ix_recommendations_org"):
        op.create_index("ix_recommendations_org", "recommendations", ["organization_id"])
    if not _index_exists(conn, "ix_recommendations_threat"):
        op.create_index("ix_recommendations_threat", "recommendations", ["threat_id"])
    if not _index_exists(conn, "ix_recommendations_org_status"):
        op.create_index("ix_recommendations_org_status", "recommendations", ["organization_id", "status"])

    if not _table_exists(conn, "decision_records"):
        op.create_table(
            "decision_records",
            sa.Column("id", sa.String(36), primary_key=True),
            sa.Column(
                "organization_id",
                sa.Integer(),
                sa.ForeignKey("organizations.id", ondelete="CASCADE"),
                nullable=False,
            ),
            sa.Column(
                "recommendation_id",
                sa.String(36),
                sa.ForeignKey("recommendations.id", ondelete="CASCADE"),
                nullable=False,
            ),
            sa.Column(
                "threat_id",
                sa.String(36),
                sa.ForeignKey("threats.id", ondelete="SET NULL"),
                nullable=True,
            ),
            sa.Column("selected_action", sa.String(20), nullable=False),
            sa.Column("decision_type", sa.String(20), nullable=False),
            sa.Column("rationale", sa.Text(), nullable=False, server_default=""),
            sa.Column("decided_by", sa.String(255), nullable=False),
            sa.Column("decided_role", sa.String(100), nullable=False),
            sa.Column("review_date", sa.String(30), nullable=True),
            sa.Column("stale", sa.Boolean(), nullable=False, server_default=sa.false()),
            sa.Column("recommendation_snapshot", JSONB(), nullable=False, server_default=sa.text("'{}'::jsonb")),
            sa.Column("reasoning_snapshot", JSONB(), nullable=False, server_default=sa.text("'{}'::jsonb")),
            sa.Column("integration_ref", sa.String(200), nullable=True),
            sa.Column("integration_provider", sa.String(50), nullable=True),
            sa.Column("external_url", sa.String(500), nullable=True),
            sa.Column(
                "recovery_action_id",
                sa.Integer(),
                sa.ForeignKey("recovery_actions.id", ondelete="SET NULL"),
                nullable=True,
            ),
            sa.Column("created_at", sa.DateTime(), nullable=False),
        )

    if not _index_exists(conn, "ix_decision_records_org"):
        op.create_index("ix_decision_records_org", "decision_records", ["organization_id"])
    if not _index_exists(conn, "ix_decision_records_recommendation"):
        op.create_index("ix_decision_records_recommendation", "decision_records", ["recommendation_id"])
    if not _index_exists(conn, "ix_decision_records_threat"):
        op.create_index("ix_decision_records_threat", "decision_records", ["threat_id"])
    if not _index_exists(conn, "ix_decision_records_org_created"):
        op.create_index("ix_decision_records_org_created", "decision_records", ["organization_id", "created_at"])

    threats = conn.execute(
        sa.text(
            "SELECT id, organization_id, asset, signal, what_it_means, recommendation, "
            "intelligence, requires_escalation, decision, created_at, updated_at "
            "FROM threats"
        )
    ).mappings().all()
    existing_recommendations = {
        row["threat_id"]: row["id"]
        for row in conn.execute(sa.text("SELECT id, threat_id FROM recommendations WHERE threat_id IS NOT NULL")).mappings()
    }
    recovery_actions = {
        row["threat_id"]: row["id"]
        for row in conn.execute(
            sa.text("SELECT id, threat_id FROM recovery_actions WHERE threat_id IS NOT NULL")
        ).mappings()
    }

    recommendation_ids_by_threat: dict[str, str] = {}
    for threat in threats:
        threat_id = threat["id"]
        if threat_id in existing_recommendations:
            recommendation_ids_by_threat[threat_id] = existing_recommendations[threat_id]
            continue

        intelligence = threat["intelligence"] or {}
        generated_at = threat["created_at"] or threat["updated_at"] or datetime.now(timezone.utc)
        recommendation_id = str(uuid.uuid4())
        recommendation_ids_by_threat[threat_id] = recommendation_id
        conn.execute(
            sa.text(
                "INSERT INTO recommendations ("
                "id, organization_id, threat_id, status, linked_context_type, linked_context_id, linked_context_label, "
                "problem, why_it_matters, suggested_action, confidence_score, is_stale, intelligence_snapshot, "
                "generated_at, created_at, updated_at"
                ") VALUES ("
                ":id, :organization_id, :threat_id, :status, :linked_context_type, :linked_context_id, :linked_context_label, "
                ":problem, :why_it_matters, :suggested_action, :confidence_score, :is_stale, CAST(:intelligence_snapshot AS jsonb), "
                ":generated_at, :created_at, :updated_at"
                ")"
            ),
            {
                "id": recommendation_id,
                "organization_id": threat["organization_id"],
                "threat_id": threat_id,
                "status": RECOMMENDATION_STATUS_DECIDED if threat["decision"] else RECOMMENDATION_STATUS_OPEN,
                "linked_context_type": "asset",
                "linked_context_id": threat["asset"],
                "linked_context_label": threat["asset"],
                "problem": threat["signal"],
                "why_it_matters": threat["what_it_means"],
                "suggested_action": intelligence.get("recommendedAction")
                or (ACTION_ACCEPTED if not threat["requires_escalation"] else "escalated"),
                "confidence_score": int(intelligence.get("confidence") or 0),
                "is_stale": False,
                "intelligence_snapshot": json.dumps(intelligence),
                "generated_at": generated_at,
                "created_at": generated_at,
                "updated_at": threat["updated_at"] or generated_at,
            },
        )

    existing_decisions = {
        row["recommendation_id"]
        for row in conn.execute(sa.text("SELECT recommendation_id FROM decision_records")).mappings()
    }
    for threat in threats:
        legacy_decision = threat["decision"] or {}
        if not legacy_decision:
            continue
        recommendation_id = recommendation_ids_by_threat.get(threat["id"]) or existing_recommendations.get(threat["id"])
        if not recommendation_id or recommendation_id in existing_decisions:
            continue

        selected_action = legacy_decision.get("action") or ACTION_ACCEPTED
        recommended_action = (threat["intelligence"] or {}).get("recommendedAction") or selected_action
        created_at = _parse_timestamp(legacy_decision.get("timestamp"), threat["updated_at"] or datetime.now(timezone.utc))
        snapshot = {
            "recommendationId": recommendation_id,
            "problem": threat["signal"],
            "whyItMatters": threat["what_it_means"],
            "suggestedAction": recommended_action,
            "linkedContext": {
                "type": "asset",
                "id": threat["asset"],
                "label": threat["asset"],
            },
            "generatedAt": (threat["created_at"] or created_at).isoformat(),
            "isStale": False,
            "confidenceScore": int(((threat["intelligence"] or {}).get("confidence")) or 0),
        }
        reasoning_snapshot = {
            "decisionType": (
                DECISION_TYPE_RECOMMENDED
                if selected_action == recommended_action
                else DECISION_TYPE_ALTERNATIVE
            ),
            "recommendedAction": recommended_action,
            "intelligence": threat["intelligence"] or {},
        }

        conn.execute(
            sa.text(
                "INSERT INTO decision_records ("
                "id, organization_id, recommendation_id, threat_id, selected_action, decision_type, rationale, "
                "decided_by, decided_role, review_date, stale, recommendation_snapshot, reasoning_snapshot, "
                "integration_ref, integration_provider, external_url, recovery_action_id, created_at"
                ") VALUES ("
                ":id, :organization_id, :recommendation_id, :threat_id, :selected_action, :decision_type, :rationale, "
                ":decided_by, :decided_role, :review_date, :stale, CAST(:recommendation_snapshot AS jsonb), "
                "CAST(:reasoning_snapshot AS jsonb), :integration_ref, :integration_provider, :external_url, "
                ":recovery_action_id, :created_at"
                ")"
            ),
            {
                "id": str(uuid.uuid4()),
                "organization_id": threat["organization_id"],
                "recommendation_id": recommendation_id,
                "threat_id": threat["id"],
                "selected_action": selected_action,
                "decision_type": (
                    DECISION_TYPE_RECOMMENDED
                    if selected_action == recommended_action
                    else DECISION_TYPE_ALTERNATIVE
                ),
                "rationale": legacy_decision.get("rationale") or "",
                "decided_by": legacy_decision.get("by") or "unknown",
                "decided_role": legacy_decision.get("role") or "user",
                "review_date": legacy_decision.get("reviewDate"),
                "stale": False,
                "recommendation_snapshot": json.dumps(snapshot),
                "reasoning_snapshot": json.dumps(reasoning_snapshot),
                "integration_ref": legacy_decision.get("ref"),
                "integration_provider": legacy_decision.get("integrationProvider"),
                "external_url": legacy_decision.get("externalUrl"),
                "recovery_action_id": recovery_actions.get(threat["id"]),
                "created_at": created_at,
            },
        )


def downgrade() -> None:
    conn = op.get_bind()
    if _table_exists(conn, "decision_records"):
        op.drop_table("decision_records")
    if _table_exists(conn, "recommendations"):
        op.drop_table("recommendations")

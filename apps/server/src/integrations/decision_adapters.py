"""Decision-layer integration adapters.

This module owns the external handoff for actionable threat decisions.
Routes call the adapter factory and never talk to Jira or ServiceNow directly.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Literal, Protocol
from uuid import uuid4

import httpx
from jira import JIRA

from src.core.config import settings
from src.core.logging_config import get_logger
from src.core.models import Threat

logger = get_logger(__name__)

ActionableDecisionAction = Literal["jira", "servicenow", "escalated"]


@dataclass(frozen=True)
class DecisionIntegrationRequest:
    organization_id: int
    submitted_by: str
    submitted_role: str
    action: ActionableDecisionAction
    rationale: str
    provided_ref: str | None
    review_date: str | None
    timestamp: str


@dataclass(frozen=True)
class IntegrationDispatchResult:
    ref: str
    provider: str
    external_url: str | None = None


class IntegrationDispatchError(RuntimeError):
    """Raised when an external decision handoff fails."""


class IntegrationAdapter(Protocol):
    def send(
        self,
        threat: Threat,
        request: DecisionIntegrationRequest,
    ) -> IntegrationDispatchResult:
        """Send the decision to the target integration and return its reference."""


def get_decision_integration_adapter(action: ActionableDecisionAction) -> IntegrationAdapter:
    """Return the correct adapter for a decision action."""
    if action == "jira":
        if settings.jira.jira_url and settings.jira.jira_username and settings.jira.jira_api_token:
            return JiraDecisionAdapter()
        return ManualReferenceAdapter(provider="jira", prefix="JIRA")

    if action == "servicenow":
        if (
            settings.servicenow.servicenow_url
            and settings.servicenow.servicenow_username
            and settings.servicenow.servicenow_password
        ):
            return ServiceNowDecisionAdapter()
        return ManualReferenceAdapter(provider="servicenow", prefix="CHG")

    return EscalationDecisionAdapter()


class ManualReferenceAdapter:
    """Fallback adapter used when a real integration is not configured."""

    def __init__(self, *, provider: str, prefix: str) -> None:
        self.provider = provider
        self.prefix = prefix

    def send(
        self,
        threat: Threat,
        request: DecisionIntegrationRequest,
    ) -> IntegrationDispatchResult:
        if request.provided_ref:
            return IntegrationDispatchResult(
                ref=request.provided_ref,
                provider=self.provider,
            )

        generated = f"{self.prefix}-{uuid4().hex[:8].upper()}"
        logger.info(
            "decision_integration_fallback_ref_created",
            provider=self.provider,
            threat_id=threat.id,
            ref=generated,
        )
        return IntegrationDispatchResult(ref=generated, provider=self.provider)


class EscalationDecisionAdapter:
    """Internal escalation handoff — records a governance reference."""

    provider = "escalation"

    def send(
        self,
        threat: Threat,
        request: DecisionIntegrationRequest,
    ) -> IntegrationDispatchResult:
        ref = request.provided_ref or f"ESC-{threat.id[:8].upper()}"
        return IntegrationDispatchResult(ref=ref, provider=self.provider)


class JiraDecisionAdapter:
    """Real Jira issue creation for threat decisions."""

    provider = "jira"

    def __init__(self) -> None:
        self.url = settings.jira.jira_url or ""
        self.project_key = settings.jira.jira_project_key
        self.client = JIRA(
            server=self.url,
            basic_auth=(
                settings.jira.jira_username,
                settings.jira.jira_api_token.get_secret_value()
                if settings.jira.jira_api_token
                else None,
            ),
        )

    def send(
        self,
        threat: Threat,
        request: DecisionIntegrationRequest,
    ) -> IntegrationDispatchResult:
        if request.provided_ref:
            return IntegrationDispatchResult(
                ref=request.provided_ref,
                provider=self.provider,
                external_url=f"{self.url.rstrip('/')}/browse/{request.provided_ref}",
            )

        try:
            issue = self.client.create_issue(
                fields={
                    "project": {"key": self.project_key},
                    "summary": f"Threat response: {threat.asset}",
                    "description": _format_jira_description(threat, request),
                    "issuetype": {"name": "Task"},
                    "labels": ["risklence", "decision-layer", threat.severity],
                }
            )
        except Exception as exc:  # pragma: no cover - exact third-party failures vary
            raise IntegrationDispatchError(f"Jira ticket creation failed: {exc}") from exc

        issue_key = str(issue.key)
        return IntegrationDispatchResult(
            ref=issue_key,
            provider=self.provider,
            external_url=f"{self.url.rstrip('/')}/browse/{issue_key}",
        )


class ServiceNowDecisionAdapter:
    """Real ServiceNow change-request creation for threat decisions."""

    provider = "servicenow"

    def __init__(self) -> None:
        self.url = (settings.servicenow.servicenow_url or "").rstrip("/")
        self.username = settings.servicenow.servicenow_username or ""
        self.password = (
            settings.servicenow.servicenow_password.get_secret_value()
            if settings.servicenow.servicenow_password
            else ""
        )
        self.table = settings.servicenow.servicenow_table

    def send(
        self,
        threat: Threat,
        request: DecisionIntegrationRequest,
    ) -> IntegrationDispatchResult:
        if request.provided_ref:
            return IntegrationDispatchResult(
                ref=request.provided_ref,
                provider=self.provider,
            )

        payload = {
            "short_description": f"Threat decision: {threat.asset}",
            "description": _format_servicenow_description(threat, request),
            "category": "risk",
            "priority": _servicenow_priority(threat.severity),
        }

        endpoint = f"{self.url}/api/now/table/{self.table}"
        try:
            response = httpx.post(
                endpoint,
                json=payload,
                auth=(self.username, self.password),
                timeout=15.0,
                headers={"Accept": "application/json", "Content-Type": "application/json"},
            )
            response.raise_for_status()
        except httpx.HTTPError as exc:  # pragma: no cover - network failures are env-specific
            raise IntegrationDispatchError(f"ServiceNow change creation failed: {exc}") from exc

        result = response.json().get("result") or {}
        change_number = result.get("number")
        if not change_number:
            raise IntegrationDispatchError("ServiceNow response did not include a change number")

        sys_id = result.get("sys_id")
        external_url = f"{self.url}/nav_to.do?uri={self.table}.do?sys_id={sys_id}" if sys_id else None
        return IntegrationDispatchResult(
            ref=str(change_number),
            provider=self.provider,
            external_url=external_url,
        )


def _format_jira_description(threat: Threat, request: DecisionIntegrationRequest) -> str:
    return (
        f"h2. Risklence threat decision\n\n"
        f"*Threat ID:* {threat.id}\n"
        f"*Asset:* {threat.asset}\n"
        f"*Severity:* {threat.severity}\n"
        f"*Signal:* {threat.signal}\n\n"
        f"h3. Why this matters\n\n{threat.what_it_means}\n\n"
        f"h3. Recommended action\n\n{threat.recommendation}\n\n"
        f"h3. Decision rationale\n\n"
        f"Submitted by {request.submitted_by} ({request.submitted_role}) at {request.timestamp}\n\n"
        f"{request.rationale}"
    )


def _format_servicenow_description(threat: Threat, request: DecisionIntegrationRequest) -> str:
    return (
        f"Risklence threat decision\n\n"
        f"Threat ID: {threat.id}\n"
        f"Asset: {threat.asset}\n"
        f"Severity: {threat.severity}\n"
        f"Signal: {threat.signal}\n\n"
        f"Why this matters:\n{threat.what_it_means}\n\n"
        f"Recommended action:\n{threat.recommendation}\n\n"
        f"Decision rationale:\n"
        f"Submitted by {request.submitted_by} ({request.submitted_role}) at {request.timestamp}\n"
        f"{request.rationale}"
    )


def _servicenow_priority(severity: str) -> str:
    if severity == "critical":
        return "1"
    if severity == "high":
        return "2"
    if severity == "medium":
        return "3"
    return "4"

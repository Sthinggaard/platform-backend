"""
Enhanced Jira service for creating compliance and remediation tickets.
"""

from typing import Dict, List, Optional

from jira import JIRA

from src.core.config import settings
from src.core.logging_config import get_logger
from src.core.models import Finding, JiraTicket, JiraTicketStatus
from src.remediation.finding_processor import DocumentationType, RemediationAction, RemediationType

logger = get_logger(__name__)


class JiraService:
    """Enhanced Jira service for compliance ticket creation.

    Creates different ticket types:
    - Documentation tickets (DPIA, architecture, registers)
    - Development tickets (code changes)
    - Auto-remediation tickets (AI-generated fixes)
    - Manual review tickets
    """

    def __init__(self):
        """Initialize Jira client."""
        if not settings.jira.jira_url or not settings.jira.jira_api_token:
            logger.warning("jira_not_configured")
            self.client = None
            return

        self.client = JIRA(
            server=settings.jira.jira_url,
            basic_auth=(
                settings.jira.jira_username,
                settings.jira.jira_api_token.get_secret_value()
                if settings.jira.jira_api_token
                else None,
            ),
        )

        self.project_key = settings.jira.jira_project_key

        logger.info("jira_service_initialized", project_key=self.project_key)

    def create_remediation_ticket(
        self, finding: Finding, action: RemediationAction, db_session
    ) -> Optional[JiraTicket]:
        """Create Jira ticket for a remediation action.

        Args:
            finding: The compliance finding
            action: The remediation action
            db_session: Database session for storing ticket

        Returns:
            JiraTicket model instance if created successfully
        """
        if not self.client:
            logger.warning("jira_client_not_available", finding_id=finding.id)
            return None

        try:
            # Determine issue type based on remediation type
            issue_type = self._get_issue_type(action.remediation_type)

            # Build issue fields
            issue_fields = {
                "project": {"key": self.project_key},
                "summary": action.title,
                "description": self._format_description(finding, action),
                "issuetype": {"name": issue_type},
                "priority": {"name": self._get_jira_priority(action.priority)},
                "labels": action.jira_labels or [],
            }

            # Add components if configured
            if action.jira_components:
                issue_fields["components"] = [{"name": c} for c in action.jira_components]

            # Add custom fields for remediation metadata
            issue_fields.update(self._get_custom_fields(finding, action))

            # Create Jira issue
            jira_issue = self.client.create_issue(fields=issue_fields)

            logger.info(
                "jira_ticket_created",
                finding_id=finding.id,
                jira_key=jira_issue.key,
                issue_type=issue_type,
            )

            # Create JiraTicket record in database
            ticket = JiraTicket(
                organization_id=finding.organization_id,
                finding_id=finding.id,
                ticket_key=jira_issue.key,
                ticket_url=f"{settings.jira.jira_url}/browse/{jira_issue.key}",
                status=JiraTicketStatus.CREATED,
            )

            db_session.add(ticket)
            db_session.commit()

            # Add comment with additional context
            self._add_ticket_comment(jira_issue.key, finding, action)

            return ticket

        except Exception as e:
            logger.error(
                "jira_ticket_creation_failed",
                finding_id=finding.id,
                error=str(e),
            )
            return None

    def _get_issue_type(self, remediation_type: RemediationType) -> str:
        """Map remediation type to Jira issue type."""
        issue_type_mapping = {
            RemediationType.DOCUMENTATION: "Task",
            RemediationType.DEVELOPMENT: "Story",
            RemediationType.CONFIGURATION: "Task",
            RemediationType.AUTO_FIX: "Sub-task",
            RemediationType.MANUAL_REVIEW: "Task",
            RemediationType.POLICY_UPDATE: "Task",
        }

        return issue_type_mapping.get(remediation_type, "Task")

    def _get_jira_priority(self, priority: int) -> str:
        """Map priority number to Jira priority name."""
        priority_mapping = {
            1: "Highest",
            2: "High",
            3: "Medium",
            4: "Low",
            5: "Lowest",
        }

        return priority_mapping.get(priority, "Medium")

    def _format_description(self, finding: Finding, action: RemediationAction) -> str:
        """Format detailed ticket description."""
        description = f"""
h2. Compliance Finding

*Finding ID:* {finding.id}
*Severity:* {finding.severity.value.upper()}
*Asset:* {finding.asset.name if finding.asset else 'N/A'}
*Cloud Provider:* {finding.asset.cloud_provider if finding.asset else 'N/A'}

h2. Description

{finding.description or 'No description provided'}

h2. Remediation Action

*Type:* {action.remediation_type.value.replace('_', ' ').title()}
*Priority:* P{action.priority}
*Estimated Effort:* {action.estimated_effort_hours} hours
*Can Auto-Remediate:* {'Yes' if action.can_auto_remediate else 'No'}

{self._format_remediation_details(action)}

h2. Compliance Context

*Rule:* {finding.rule.name if finding.rule else 'N/A'}
*Control:* {finding.rule.control.title if finding.rule and finding.rule.control else 'N/A'}
*Framework:* {finding.rule.control.framework.name if finding.rule and finding.rule.control and finding.rule.control.framework else 'N/A'}

h2. Evidence

{self._format_evidence(finding.evidence)}

---
_Generated by Risklence Tower Auto-Remediation System_
"""

        return description.strip()

    def _format_remediation_details(self, action: RemediationAction) -> str:
        """Format remediation-specific details."""
        details = []

        if action.remediation_type == RemediationType.DOCUMENTATION:
            details.append(f"*Documentation Type:* {action.documentation_type.value if action.documentation_type else 'N/A'}")
            details.append(f"*Template:* {action.documentation_template or 'N/A'}")

        elif action.remediation_type in [RemediationType.DEVELOPMENT, RemediationType.CONFIGURATION]:
            if action.affected_resources:
                details.append("*Affected Resources:*")
                for resource in action.affected_resources[:5]:  # Limit to 5
                    details.append(f"- {resource}")

            if action.code_changes_required:
                details.append("\n*Suggested Changes:*")
                for change in action.code_changes_required:
                    details.append(f"- {change}")

        elif action.remediation_type == RemediationType.AUTO_FIX:
            details.append(f"*Auto-Fix Strategy:* {action.auto_fix_strategy or 'N/A'}")
            details.append(f"*Risk Level:* {action.auto_fix_risk_level or 'N/A'}")

        return "\n".join(details) if details else ""

    def _format_evidence(self, evidence: Optional[Dict]) -> str:
        """Format evidence for Jira description."""
        if not evidence:
            return "No additional evidence available"

        import json

        evidence_json = json.dumps(evidence, indent=2)
        return f"{{code:json}}\n{evidence_json}\n{{code}}"

    def _get_custom_fields(self, finding: Finding, action: RemediationAction) -> Dict:
        """Get custom field values for Jira ticket.

        Note: Custom field IDs vary by Jira instance. Configure these in settings.
        """
        custom_fields = {}

        # Example custom fields (adjust based on your Jira setup)
        # custom_fields["customfield_10001"] = action.estimated_effort_hours
        # custom_fields["customfield_10002"] = finding.severity.value
        # custom_fields["customfield_10003"] = action.assigned_team

        return custom_fields

    def _add_ticket_comment(
        self, ticket_key: str, finding: Finding, action: RemediationAction
    ) -> None:
        """Add comment with additional context to ticket."""
        try:
            comment_text = self._build_comment_text(finding, action)

            if comment_text:
                self.client.add_comment(ticket_key, comment_text)

                logger.debug("jira_comment_added", ticket_key=ticket_key)

        except Exception as e:
            logger.warning(
                "jira_comment_failed",
                ticket_key=ticket_key,
                error=str(e),
            )

    def _build_comment_text(self, finding: Finding, action: RemediationAction) -> str:
        """Build comment text with recommendations."""
        if action.remediation_type == RemediationType.DOCUMENTATION:
            return self._build_documentation_comment(action)
        elif action.remediation_type == RemediationType.AUTO_FIX:
            return self._build_auto_fix_comment(action)
        else:
            return ""

    def _build_documentation_comment(self, action: RemediationAction) -> str:
        """Build comment for documentation tickets."""
        if action.documentation_type == DocumentationType.DPIA:
            return """
h3. DPIA (Data Protection Impact Assessment) Guidance

To complete this DPIA:
1. Identify the personal data being processed
2. Assess necessity and proportionality
3. Identify and assess risks to individuals
4. Identify measures to reduce risks
5. Get stakeholder input
6. Sign off and record DPIA

Use the template: {}/templates/dpia_gdpr.docx
""".format(settings.app_name).strip()

        elif action.documentation_type == DocumentationType.ARCHITECTURE:
            return """
h3. Architecture Documentation Guidance

Document the following:
1. Context and problem statement
2. Decision drivers
3. Considered options
4. Decision outcome
5. Consequences (positive and negative)

Use ADR (Architecture Decision Record) format.
""".strip()

        elif action.documentation_type == DocumentationType.REGISTER:
            return """
h3. Compliance Register Entry Guidance

Record in compliance register:
1. Control ID and description
2. Implementation status
3. Evidence location
4. Review date
5. Owner/responsible party
""".strip()

        return ""

    def _build_auto_fix_comment(self, action: RemediationAction) -> str:
        """Build comment for auto-fix tickets."""
        return f"""
h3. Auto-Remediation Available

This finding can be automatically remediated using AI.

*Strategy:* {action.auto_fix_strategy}
*Risk Level:* {action.auto_fix_risk_level}

To trigger auto-remediation:
1. Review the finding details
2. Approve the auto-fix in Risklence Tower
3. AI will generate code/config changes
4. Review the generated pull request
5. Merge to apply the fix

⚠️ *Note:* Always review AI-generated changes before applying to production.
""".strip()

    def update_ticket_status(
        self, ticket: JiraTicket, new_status: JiraTicketStatus, db_session
    ) -> bool:
        """Update Jira ticket status.

        Args:
            ticket: JiraTicket model instance
            new_status: New status to set
            db_session: Database session

        Returns:
            True if updated successfully
        """
        if not self.client:
            return False

        try:
            # Get Jira issue
            jira_issue = self.client.issue(ticket.ticket_key)

            # Find transition ID for new status
            transitions = self.client.transitions(jira_issue)

            status_mapping = {
                JiraTicketStatus.IN_PROGRESS: "In Progress",
                JiraTicketStatus.RESOLVED: "Resolved",
                JiraTicketStatus.CLOSED: "Closed",
            }

            target_status = status_mapping.get(new_status)

            if not target_status:
                return False

            # Find matching transition
            transition_id = None
            for t in transitions:
                if t["name"] == target_status:
                    transition_id = t["id"]
                    break

            if not transition_id:
                logger.warning(
                    "jira_transition_not_found",
                    ticket_key=ticket.ticket_key,
                    target_status=target_status,
                )
                return False

            # Perform transition
            self.client.transition_issue(jira_issue, transition_id)

            # Update database
            ticket.status = new_status
            db_session.commit()

            logger.info(
                "jira_ticket_updated",
                ticket_key=ticket.ticket_key,
                new_status=new_status.value,
            )

            return True

        except Exception as e:
            logger.error(
                "jira_update_failed",
                ticket_key=ticket.ticket_key,
                error=str(e),
            )
            return False

    def add_pull_request_link(
        self, ticket: JiraTicket, pr_url: str, pr_title: str
    ) -> bool:
        """Add pull request link to Jira ticket.

        Args:
            ticket: JiraTicket model instance
            pr_url: Pull request URL
            pr_title: Pull request title

        Returns:
            True if added successfully
        """
        if not self.client:
            return False

        try:
            comment = f"""
h3. Auto-Remediation Pull Request Created

*PR:* [{pr_title}|{pr_url}]

The AI has generated code changes to remediate this finding.
Please review the pull request and merge if approved.
"""

            self.client.add_comment(ticket.ticket_key, comment)

            logger.info(
                "pr_link_added_to_jira",
                ticket_key=ticket.ticket_key,
                pr_url=pr_url,
            )

            return True

        except Exception as e:
            logger.error(
                "pr_link_add_failed",
                ticket_key=ticket.ticket_key,
                error=str(e),
            )
            return False

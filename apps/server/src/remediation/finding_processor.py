"""
Finding processor - Analyzes compliance findings and determines remediation actions.
"""

import enum
from dataclasses import dataclass
from typing import Dict, List, Optional

from src.core.logging_config import get_logger
from src.core.models import Finding, SeverityLevel

logger = get_logger(__name__)


class RemediationType(enum.Enum):
    """Type of remediation action required."""

    DOCUMENTATION = "documentation"  # Create/update docs (DPIA, architecture, register)
    DEVELOPMENT = "development"  # Code changes by developers
    CONFIGURATION = "configuration"  # Config file changes
    AUTO_FIX = "auto_fix"  # AI can automatically fix
    MANUAL_REVIEW = "manual_review"  # Requires manual assessment
    POLICY_UPDATE = "policy_update"  # Update compliance policy/rules


class DocumentationType(enum.Enum):
    """Types of documentation that may need to be created."""

    DPIA = "dpia"  # Data Protection Impact Assessment
    ARCHITECTURE = "architecture"  # Architecture documentation
    REGISTER = "register"  # Compliance register entry
    PROCEDURE = "procedure"  # Standard operating procedure
    RISK_ASSESSMENT = "risk_assessment"  # Risk assessment document


@dataclass
class RemediationAction:
    """Represents a recommended action to remediate a finding."""

    finding_id: int
    organization_id: int
    remediation_type: RemediationType
    priority: int  # 1 (highest) to 5 (lowest)
    title: str
    description: str
    estimated_effort_hours: float
    can_auto_remediate: bool

    # For documentation tasks
    documentation_type: Optional[DocumentationType] = None
    documentation_template: Optional[str] = None

    # For development/config tasks
    affected_resources: Optional[List[str]] = None
    code_changes_required: Optional[List[str]] = None

    # For auto-fix tasks
    auto_fix_strategy: Optional[str] = None
    auto_fix_risk_level: Optional[str] = None  # low, medium, high

    # Jira metadata
    jira_labels: Optional[List[str]] = None
    jira_components: Optional[List[str]] = None
    assigned_team: Optional[str] = None


class FindingProcessor:
    """Processes compliance findings and generates remediation actions.

    Analyzes findings and determines:
    - What type of action is needed (docs, dev, auto-fix)
    - Priority level
    - Estimated effort
    - Whether AI can auto-remediate
    """

    # Keywords that indicate documentation is needed
    DOCUMENTATION_KEYWORDS = [
        "data processing",
        "personal data",
        "privacy",
        "gdpr",
        "data protection",
        "consent",
        "data retention",
        "cross-border transfer",
    ]

    # Keywords that indicate auto-fix is possible
    AUTO_FIX_KEYWORDS = [
        "encryption disabled",
        "public access",
        "https not enforced",
        "logging disabled",
        "backup not configured",
        "versioning disabled",
        "mfa not enabled",
        "password policy weak",
    ]

    # Keywords that require code changes
    DEVELOPMENT_KEYWORDS = [
        "authentication",
        "authorization",
        "input validation",
        "sql injection",
        "xss vulnerability",
        "insecure deserialization",
        "broken access control",
    ]

    def __init__(self):
        logger.info("finding_processor_initialized")

    def process_finding(self, finding: Finding) -> RemediationAction:
        """Process a finding and determine remediation action.

        Args:
            finding: Compliance finding to process

        Returns:
            RemediationAction with recommended steps
        """
        logger.debug("processing_finding", finding_id=finding.id, severity=finding.severity.value)

        # Determine remediation type
        remediation_type = self._determine_remediation_type(finding)

        # Calculate priority (1=highest, 5=lowest)
        priority = self._calculate_priority(finding)

        # Check if can auto-remediate
        can_auto_remediate = self._can_auto_remediate(finding, remediation_type)

        # Estimate effort
        estimated_effort = self._estimate_effort(finding, remediation_type)

        # Generate action
        action = RemediationAction(
            finding_id=finding.id,
            organization_id=finding.organization_id,
            remediation_type=remediation_type,
            priority=priority,
            title=self._generate_action_title(finding, remediation_type),
            description=self._generate_action_description(finding, remediation_type),
            estimated_effort_hours=estimated_effort,
            can_auto_remediate=can_auto_remediate,
            jira_labels=self._generate_jira_labels(finding, remediation_type),
            jira_components=self._generate_jira_components(finding),
            assigned_team=self._assign_team(remediation_type),
        )

        # Add type-specific details
        if remediation_type == RemediationType.DOCUMENTATION:
            action.documentation_type = self._determine_documentation_type(finding)
            action.documentation_template = self._get_documentation_template(
                action.documentation_type
            )

        elif remediation_type in [RemediationType.DEVELOPMENT, RemediationType.CONFIGURATION]:
            action.affected_resources = self._extract_affected_resources(finding)
            action.code_changes_required = self._suggest_code_changes(finding)

        elif remediation_type == RemediationType.AUTO_FIX:
            action.auto_fix_strategy = self._determine_auto_fix_strategy(finding)
            action.auto_fix_risk_level = self._assess_auto_fix_risk(finding)

        logger.info(
            "remediation_action_generated",
            finding_id=finding.id,
            remediation_type=remediation_type.value,
            priority=priority,
            can_auto_remediate=can_auto_remediate,
        )

        return action

    def _determine_remediation_type(self, finding: Finding) -> RemediationType:
        """Determine what type of remediation is needed."""
        title_lower = finding.title.lower()
        description_lower = (finding.description or "").lower()
        combined_text = f"{title_lower} {description_lower}"

        # Check for documentation needs
        if any(keyword in combined_text for keyword in self.DOCUMENTATION_KEYWORDS):
            return RemediationType.DOCUMENTATION

        # Check for auto-fix possibility
        if any(keyword in combined_text for keyword in self.AUTO_FIX_KEYWORDS):
            return RemediationType.AUTO_FIX

        # Check for development work
        if any(keyword in combined_text for keyword in self.DEVELOPMENT_KEYWORDS):
            return RemediationType.DEVELOPMENT

        # Check for configuration changes
        if "config" in combined_text or "setting" in combined_text:
            return RemediationType.CONFIGURATION

        # Default to manual review
        return RemediationType.MANUAL_REVIEW

    def _calculate_priority(self, finding: Finding) -> int:
        """Calculate priority (1=highest, 5=lowest) based on severity and risk."""
        severity_priority = {
            SeverityLevel.CRITICAL: 1,
            SeverityLevel.HIGH: 2,
            SeverityLevel.MEDIUM: 3,
            SeverityLevel.LOW: 4,
            SeverityLevel.INFO: 5,
        }

        base_priority = severity_priority.get(finding.severity, 3)

        # Adjust based on risk score
        if finding.risk_score:
            if finding.risk_score >= 9.0:
                base_priority = min(base_priority, 1)
            elif finding.risk_score >= 7.0:
                base_priority = min(base_priority, 2)

        # Adjust based on business impact
        if finding.business_impact_score and finding.business_impact_score >= 8.0:
            base_priority = max(1, base_priority - 1)

        return base_priority

    def _can_auto_remediate(self, finding: Finding, remediation_type: RemediationType) -> bool:
        """Determine if finding can be auto-remediated by AI."""
        if remediation_type != RemediationType.AUTO_FIX:
            return False

        # Critical findings should require manual review before auto-fix
        if finding.severity == SeverityLevel.CRITICAL:
            return False

        # High-risk findings should be reviewed
        if finding.risk_score and finding.risk_score >= 8.0:
            return False

        return True

    def _estimate_effort(self, finding: Finding, remediation_type: RemediationType) -> float:
        """Estimate effort in hours."""
        effort_by_type = {
            RemediationType.AUTO_FIX: 0.5,
            RemediationType.CONFIGURATION: 1.0,
            RemediationType.DOCUMENTATION: 4.0,
            RemediationType.DEVELOPMENT: 8.0,
            RemediationType.MANUAL_REVIEW: 2.0,
            RemediationType.POLICY_UPDATE: 3.0,
        }

        base_effort = effort_by_type.get(remediation_type, 4.0)

        # Adjust based on severity
        if finding.severity in [SeverityLevel.CRITICAL, SeverityLevel.HIGH]:
            base_effort *= 1.5

        return base_effort

    def _determine_documentation_type(self, finding: Finding) -> DocumentationType:
        """Determine what type of documentation is needed."""
        text = f"{finding.title} {finding.description}".lower()

        if "personal data" in text or "gdpr" in text or "privacy" in text:
            return DocumentationType.DPIA
        elif "architecture" in text or "design" in text:
            return DocumentationType.ARCHITECTURE
        elif "register" in text or "inventory" in text:
            return DocumentationType.REGISTER
        elif "procedure" in text or "process" in text:
            return DocumentationType.PROCEDURE
        else:
            return DocumentationType.RISK_ASSESSMENT

    def _get_documentation_template(self, doc_type: Optional[DocumentationType]) -> str:
        """Get documentation template name for the type."""
        if not doc_type:
            return "generic_compliance_doc"

        templates = {
            DocumentationType.DPIA: "dpia_template_gdpr",
            DocumentationType.ARCHITECTURE: "architecture_decision_record",
            DocumentationType.REGISTER: "compliance_register_entry",
            DocumentationType.PROCEDURE: "standard_operating_procedure",
            DocumentationType.RISK_ASSESSMENT: "risk_assessment_template",
        }

        return templates.get(doc_type, "generic_compliance_doc")

    def _extract_affected_resources(self, finding: Finding) -> List[str]:
        """Extract list of affected resources from finding."""
        resources = []

        if finding.asset:
            resources.append(finding.asset.asset_id)

        # Extract from evidence
        if finding.evidence and isinstance(finding.evidence, dict):
            if "resources" in finding.evidence:
                resources.extend(finding.evidence["resources"])

        return resources

    def _suggest_code_changes(self, finding: Finding) -> List[str]:
        """Suggest code changes needed."""
        # This would typically use AI to analyze and suggest changes
        # For now, return generic suggestions based on finding type
        suggestions = []

        title_lower = finding.title.lower()

        if "authentication" in title_lower:
            suggestions.append("Implement multi-factor authentication")
            suggestions.append("Add session timeout configuration")

        if "encryption" in title_lower:
            suggestions.append("Enable encryption at rest")
            suggestions.append("Enforce TLS 1.2+ for data in transit")

        if "logging" in title_lower:
            suggestions.append("Enable audit logging")
            suggestions.append("Configure log retention policy")

        return suggestions

    def _determine_auto_fix_strategy(self, finding: Finding) -> str:
        """Determine strategy for auto-remediation."""
        title_lower = finding.title.lower()

        strategies = {
            "encryption disabled": "enable_encryption_terraform",
            "public access": "restrict_public_access",
            "https not enforced": "enforce_https_redirect",
            "logging disabled": "enable_logging",
            "backup not configured": "configure_backup_policy",
            "versioning disabled": "enable_versioning",
        }

        for keyword, strategy in strategies.items():
            if keyword in title_lower:
                return strategy

        return "generic_config_update"

    def _assess_auto_fix_risk(self, finding: Finding) -> str:
        """Assess risk level of auto-fixing this finding."""
        # Critical and high severity findings are high risk to auto-fix
        if finding.severity in [SeverityLevel.CRITICAL, SeverityLevel.HIGH]:
            return "high"

        # Medium severity with high business impact is medium risk
        if finding.severity == SeverityLevel.MEDIUM and finding.business_impact_score and finding.business_impact_score >= 7.0:
            return "medium"

        return "low"

    def _generate_action_title(self, finding: Finding, remediation_type: RemediationType) -> str:
        """Generate action title for Jira ticket."""
        type_prefixes = {
            RemediationType.DOCUMENTATION: "[DOC]",
            RemediationType.DEVELOPMENT: "[DEV]",
            RemediationType.CONFIGURATION: "[CONFIG]",
            RemediationType.AUTO_FIX: "[AUTO-FIX]",
            RemediationType.MANUAL_REVIEW: "[REVIEW]",
            RemediationType.POLICY_UPDATE: "[POLICY]",
        }

        prefix = type_prefixes.get(remediation_type, "")
        return f"{prefix} {finding.title}"

    def _generate_action_description(self, finding: Finding, remediation_type: RemediationType) -> str:
        """Generate detailed action description."""
        description = f"""
**Finding:** {finding.title}
**Severity:** {finding.severity.value.upper()}
**Asset:** {finding.asset.name if finding.asset else 'N/A'}

**Description:**
{finding.description or 'No description provided'}

**Remediation Type:** {remediation_type.value.replace('_', ' ').title()}

**Recommended Actions:**
{finding.rule.remediation if finding.rule and finding.rule.remediation else 'Review finding and implement appropriate controls'}
        """.strip()

        return description

    def _generate_jira_labels(self, finding: Finding, remediation_type: RemediationType) -> List[str]:
        """Generate Jira labels for the ticket."""
        labels = [
            f"severity-{finding.severity.value}",
            f"type-{remediation_type.value}",
            "compliance",
        ]

        if finding.asset:
            labels.append(f"provider-{finding.asset.cloud_provider}")

        if finding.rule:
            labels.append(f"rule-{finding.rule.cloud_provider}")

        return labels

    def _generate_jira_components(self, finding: Finding) -> List[str]:
        """Generate Jira components."""
        components = ["Security", "Compliance"]

        if finding.asset:
            components.append(finding.asset.cloud_provider.upper())

        return components

    def _assign_team(self, remediation_type: RemediationType) -> str:
        """Assign appropriate team based on remediation type."""
        team_assignments = {
            RemediationType.DOCUMENTATION: "compliance-team",
            RemediationType.DEVELOPMENT: "engineering-team",
            RemediationType.CONFIGURATION: "devops-team",
            RemediationType.AUTO_FIX: "automation-team",
            RemediationType.MANUAL_REVIEW: "security-team",
            RemediationType.POLICY_UPDATE: "compliance-team",
        }

        return team_assignments.get(remediation_type, "security-team")

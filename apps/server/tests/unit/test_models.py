"""
Unit tests for database models.
"""

from datetime import datetime

import pytest
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from src.core.models import (
    CloudAsset,
    ComplianceControl,
    ComplianceFramework,
    Finding,
    FindingStatus,
    JiraTicket,
    JiraTicketStatus,
    KeyRiskIndicator,
    Organization,
    PolicyRule,
    RiskAppetite,
    ScanRun,
    ScanStatus,
    SeverityLevel,
)


class TestComplianceFramework:
    """Test ComplianceFramework model."""

    def test_create_framework(self, db_session: Session, sample_organization: Organization) -> None:
        """Test creating a compliance framework."""
        framework = ComplianceFramework(
            organization_id=sample_organization.id,
            name="CIS AWS Foundations",
            version="1.4.0",
            description="CIS AWS security benchmark",
        )
        db_session.add(framework)
        db_session.commit()

        assert framework.id is not None
        assert framework.name == "CIS AWS Foundations"
        assert framework.version == "1.4.0"
        assert isinstance(framework.created_at, datetime)
        assert isinstance(framework.updated_at, datetime)

    def test_unique_name_constraint(self, db_session: Session, sample_framework: ComplianceFramework) -> None:
        """Test unique constraint on framework name."""
        duplicate = ComplianceFramework(
            name=sample_framework.name,  # Same name
            version="2.0.0",
            description="Duplicate framework",
            organization_id=sample_framework.organization_id,
        )
        db_session.add(duplicate)

        with pytest.raises(IntegrityError):
            db_session.commit()

    def test_framework_controls_relationship(
        self, db_session: Session, sample_framework: ComplianceFramework, sample_control: ComplianceControl
    ) -> None:
        """Test relationship between framework and controls."""
        assert len(sample_framework.controls) == 1
        assert sample_framework.controls[0].id == sample_control.id


class TestComplianceControl:
    """Test ComplianceControl model."""

    def test_create_control(self, db_session: Session, sample_framework: ComplianceFramework) -> None:
        """Test creating a compliance control."""
        control = ComplianceControl(
            organization_id=sample_framework.organization_id,
            framework_id=sample_framework.id,
            control_id="2.1",
            title="Ensure logging is enabled",
            description="Enable logging for all resources",
            severity=SeverityLevel.MEDIUM,
            remediation="Enable logging in Azure Monitor",
            references={"doc_url": "https://example.com"},
        )
        db_session.add(control)
        db_session.commit()

        assert control.id is not None
        assert control.framework_id == sample_framework.id
        assert control.severity == SeverityLevel.MEDIUM


class TestPolicyRule:
    """Test PolicyRule model."""

    def test_create_rule(self, db_session: Session, sample_control: ComplianceControl) -> None:
        """Test creating a policy rule."""
        rule = PolicyRule(
            organization_id=sample_control.organization_id,
            control_id=sample_control.id,
            name="Check encryption enabled",
            description="Verify storage encryption is enabled",
            rule_definition={
                "property": "encryption.enabled",
                "operator": "equals",
                "value": True,
            },
            cloud_provider="azure",
            resource_type="storage_account",
            enabled=True,
        )
        db_session.add(rule)
        db_session.commit()

        assert rule.id is not None
        assert rule.cloud_provider == "azure"
        assert rule.enabled is True
        assert "property" in rule.rule_definition


class TestCloudAsset:
    """Test CloudAsset model."""

    def test_create_asset(self, db_session: Session, sample_organization: Organization) -> None:
        """Test creating a cloud asset."""
        asset = CloudAsset(
            organization_id=sample_organization.id,
            asset_id="/subscriptions/test/resourceGroups/test",
            asset_type="virtual_machine",
            cloud_provider="azure",
            region="westus",
            name="test-vm",
            asset_metadata={"size": "Standard_D2s_v3"},
        )
        db_session.add(asset)
        db_session.commit()

        assert asset.id is not None
        assert asset.cloud_provider == "azure"
        assert isinstance(asset.discovered_at, datetime)

    def test_unique_asset_id(self, db_session: Session, sample_asset: CloudAsset) -> None:
        """Test unique constraint on asset_id."""
        duplicate = CloudAsset(
            organization_id=sample_asset.organization_id,
            asset_id=sample_asset.asset_id,  # Same asset ID
            asset_type="storage_account",
            cloud_provider="azure",
            region="eastus",
            name="duplicate-asset",
        )
        db_session.add(duplicate)

        with pytest.raises(IntegrityError):
            db_session.commit()


class TestScanRun:
    """Test ScanRun model."""

    def test_create_scan_run(self, db_session: Session, sample_organization: Organization) -> None:
        """Test creating a scan run."""
        scan = ScanRun(
            organization_id=sample_organization.id,
            scan_type="vulnerability",
            status=ScanStatus.RUNNING,
            cloud_provider="aws",
            scope={"account_id": "123456789012"},
            total_assets=100,
            total_findings=25,
        )
        db_session.add(scan)
        db_session.commit()

        assert scan.id is not None
        assert scan.status == ScanStatus.RUNNING
        assert isinstance(scan.started_at, datetime)

    @pytest.mark.unreconciled
    def test_scan_status_enum(self, db_session: Session, sample_organization: Organization) -> None:
        """Test scan status enumeration."""
        # The `db_session.rollback()` that used to end each iteration is gone
        # (#210). It came after a `commit()`, so there was nothing of this
        # test's own left to undo — what it actually did was expire the session
        # and discard the transaction the `sample_organization` fixture was
        # created in. The next iteration then read `sample_organization.id`,
        # SQLAlchemy went back for a row that no longer existed, and the test
        # died on `ObjectDeletedError` — reported as schema drift, and never
        # anything of the sort.
        for status in ScanStatus:
            scan = ScanRun(
                organization_id=sample_organization.id,
                scan_type="compliance",
                status=status,
            )
            db_session.add(scan)
            db_session.commit()
            assert scan.status == status


class TestFinding:
    """Test Finding model."""

    def test_create_finding(
        self, db_session: Session, sample_scan_run: ScanRun, sample_asset: CloudAsset, sample_rule: PolicyRule
    ) -> None:
        """Test creating a finding."""
        finding = Finding(
            organization_id=sample_scan_run.organization_id,
            scan_run_id=sample_scan_run.id,
            asset_id=sample_asset.id,
            rule_id=sample_rule.id,
            severity=SeverityLevel.CRITICAL,
            title="Critical security issue",
            description="A critical security issue was detected",
            evidence={"details": "Evidence data"},
            risk_score=9.5,
            status=FindingStatus.OPEN,
        )
        db_session.add(finding)
        db_session.commit()

        assert finding.id is not None
        assert finding.severity == SeverityLevel.CRITICAL
        assert finding.status == FindingStatus.OPEN
        assert isinstance(finding.detected_at, datetime)

    def test_finding_relationships(self, db_session: Session, sample_finding: Finding) -> None:
        """Test finding relationships."""
        assert sample_finding.scan_run is not None
        assert sample_finding.asset is not None
        assert sample_finding.rule is not None


class TestJiraTicket:
    """Test JiraTicket model."""

    def test_create_jira_ticket(self, db_session: Session, sample_finding: Finding) -> None:
        """Test creating a Jira ticket."""
        ticket = JiraTicket(
            organization_id=sample_finding.organization_id,
            finding_id=sample_finding.id,
            ticket_key="SEC-123",
            ticket_url="https://jira.example.com/browse/SEC-123",
            status=JiraTicketStatus.CREATED,
        )
        db_session.add(ticket)
        db_session.commit()

        assert ticket.id is not None
        assert ticket.ticket_key == "SEC-123"
        assert isinstance(ticket.created_at, datetime)

    def test_unique_finding_id(self, db_session: Session, sample_finding: Finding) -> None:
        """Test one-to-one relationship with finding."""
        ticket1 = JiraTicket(
            organization_id=sample_finding.organization_id,
            finding_id=sample_finding.id,
            ticket_key="SEC-100",
            ticket_url="https://jira.example.com/browse/SEC-100",
        )
        db_session.add(ticket1)
        db_session.commit()

        # Try to create another ticket for the same finding
        ticket2 = JiraTicket(
            organization_id=sample_finding.organization_id,
            finding_id=sample_finding.id,
            ticket_key="SEC-101",
            ticket_url="https://jira.example.com/browse/SEC-101",
        )
        db_session.add(ticket2)

        with pytest.raises(IntegrityError):
            db_session.commit()


class TestRiskAppetite:
    """Test RiskAppetite model."""

    def test_create_risk_appetite(self, db_session: Session, sample_organization: Organization) -> None:
        """Test creating risk appetite."""
        risk_appetite = RiskAppetite(
            organization_id=sample_organization.id,
            domain="data_security",
            max_acceptable_score=7.5,
            threshold_critical=0,
            threshold_high=5,
            threshold_medium=20,
            threshold_low=50,
        )
        db_session.add(risk_appetite)
        db_session.commit()

        assert risk_appetite.id is not None
        assert risk_appetite.domain == "data_security"
        assert risk_appetite.max_acceptable_score == 7.5


class TestKeyRiskIndicator:
    """Test KeyRiskIndicator model."""

    @pytest.mark.unreconciled
    def test_create_kri(self, db_session: Session, sample_organization: Organization) -> None:
        """Test creating a KRI."""
        kri = KeyRiskIndicator(
            organization_id=sample_organization.id,
            name="Critical Findings Count",
            description="Number of open critical findings",
            calculation_method={"type": "count", "severity": "critical"},
            threshold_value=10.0,
            current_value=5.0,
            status="normal",
        )
        db_session.add(kri)
        db_session.commit()

        assert kri.id is not None
        assert kri.name == "Critical Findings Count"
        assert kri.status == "normal"
        assert isinstance(kri.measured_at, datetime)

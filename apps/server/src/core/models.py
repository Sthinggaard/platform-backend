"""
Compatibility export surface for SQLAlchemy ORM models.

Model definitions live in ``src.core.model_defs`` and are re-exported here to
preserve existing import contracts across the backend.
"""

import enum
from uuid import uuid4

from sqlalchemy import JSON, Column, DateTime, Float, ForeignKey, Index, Integer, String, Text, func

from src.core.database import Base
from src.core.model_defs import (
    SEVERITY_ENUM,
    USER_STATUS_ENUM,
    AccessConnector,
    ActivationAuditOutbox,
    ArtefactAccessLifecycle,
    ArtefactIdentityConflict,
    ArtefactMergeRecord,
    ArtefactRelationship,
    Asset,
    AssetAppetiteConfig,
    AssetConnection,
    AssetEvidenceSignal,
    AssetFinding,
    AssetFindingStatus,
    AssetIdentifier,
    AssetLifecycleState,
    AssetObservedPort,
    AssetStatus,
    AssetStatusHistory,
    AuditEvent,
    AuthMsGroupRole,
    AuthMsTenantAllowlist,
    AuthTenantSettings,
    BaselineRiskHypothesis,
    BusinessProcessActivation,
    BusinessService,
    BusinessServiceAppetiteConfig,
    CloudAsset,
    CloudCredentials,
    ComplianceControl,
    ComplianceFramework,
    ConnectionState,
    ConnectivityStatus,
    ConnectorAccessTest,
    ContextualAccessPolicy,
    Control,
    ControlCoverageStatus,
    ControlEvidence,
    ControlMapping,
    ControlShareLink,
    Criticality,
    DecisionRecord,
    DependencyBundle,
    DependencyBundleVersion,
    Environment,
    EvidenceImportBatch,
    EvidenceManualEntry,
    EvidenceReceipt,
    EvidenceSource,
    EvidenceSourceException,
    EvidenceSourceScope,
    Finding,
    FindingStatus,
    ForecastImpact,
    InviteToken,
    JiraTicket,
    JiraTicketStatus,
    KeyRiskIndicator,
    LeadershipAuthorization,
    LearningImprovementCandidate,
    LearningLoopRun,
    MappingDecision,
    MfaChallenge,
    OnboardingStatus,
    Organization,
    OrganizationBiaBaseline,
    OrganizationDomain,
    OrganizationIdentityConfirmation,
    OrganizationIdentityEvidence,
    OrganizationLegalEntity,
    OrganizationLocation,
    OrganizationOperatingContextSuggestion,
    OrganizationScope,
    OrganizationUnit,
    OrganizationUnitMatchSuggestion,
    OrganizationUnitMembership,
    OrganizationUnitRelationship,
    OrgMandateRoleAssignment,
    OrgMandateScopeBinding,
    OrgProcessConfig,
    OrgReportingLineException,
    OrgServiceConfig,
    OrgVisibilityPolicy,
    PasswordResetToken,
    PermissionPreset,
    PermissionProfile,
    PermissionSubject,
    PolicyRule,
    ProcessBiaAssessment,
    ProcessOwnerAcceptance,
    ProcessScannerLink,
    ProcessScanScope,
    ProcessTailoringSignal,
    Recommendation,
    RecoveryAction,
    RecurrenceOccurrence,
    RecurrenceSchedule,
    ResolutionRecord,
    ReviewReopening,
    RiskAppetite,
    RiskAppetitePolicy,
    RiskEvaluation,
    RiskIngestionBatch,
    RiskIngestionBatchStatus,
    ScanRun,
    ScanStartMode,
    ScanStatus,
    ServiceAppetiteReassessment,
    ServiceArtefactDependencyLink,
    ServiceBiaException,
    ServiceChangeNotice,
    ServiceChangeNoticeKind,
    ServiceJourneySignal,
    SetupConfidence,
    SeverityLevel,
    SlotInstance,
    TemplateCandidate,
    TemplateLearningRun,
    Threat,
    TrainingSignal,
    User,
    UserIdentity,
    UserSession,
    UserStatus,
    ValueStream,
    ValueStreamSignal,
    VerificationRecord,
    VerificationRun,
    utcnow,
)
from src.core.template_models import ProcessTemplate, ServiceTemplate, SlotTemplate


class BusinessProcessRecommendationStatus(str, enum.Enum):
    SUGGESTED = "suggested"
    ACCEPTED = "accepted"
    REMOVED = "removed"
    ADDED = "added"


class BusinessProcessDecisionAction(str, enum.Enum):
    ACCEPT = "accept"
    REMOVE = "remove"
    ADD = "add"
    CONFIRM = "confirm"
    CROWN_CONFIRM = "crown_confirm"
    CROWN_REJECT = "crown_reject"
    CROWN_DEFER = "crown_defer"
    SERVICE_ARCHIVE = "service_archive"
    APPETITE_SET = "appetite_set"
    SLOT_CONFIRMED = "slot_confirmed"


class BusinessProcessRecommendation(Base):
    __tablename__ = "business_process_recommendations"
    __table_args__ = (
        Index("ix_business_process_recommendations_org_status", "organization_id", "status"),
        Index(
            "ix_business_process_recommendations_org_template",
            "organization_id",
            "process_template_id",
        ),
    )

    id = Column(String(36), primary_key=True, default=lambda: str(uuid4()))
    organization_id = Column(Integer, nullable=False, index=True)
    user_id = Column(Integer, nullable=True, index=True)
    process_template_id = Column(String(100), nullable=False)
    name = Column(String(200), nullable=False)
    category = Column(String(100), nullable=False)
    confidence = Column(Float, nullable=False)
    recommendation_reason = Column(Text, nullable=False)
    source_rule = Column(String(120), nullable=False)
    status = Column(
        String(20),
        nullable=False,
        default=BusinessProcessRecommendationStatus.SUGGESTED.value,
    )
    model_version = Column(String(80), nullable=False)
    created_at = Column(DateTime(), nullable=False, default=func.now())
    updated_at = Column(DateTime(), nullable=False, default=func.now(), onupdate=func.now())


class BusinessProcessDecisionLog(Base):
    __tablename__ = "business_process_decision_logs"
    __table_args__ = (
        Index("ix_business_process_decision_logs_org_created", "organization_id", "created_at"),
        Index("ix_business_process_decision_logs_recommendation", "recommendation_id"),
    )

    id = Column(String(36), primary_key=True, default=lambda: str(uuid4()))
    organization_id = Column(Integer, nullable=False, index=True)
    recommendation_id = Column(
        String(36),
        ForeignKey("business_process_recommendations.id", ondelete="SET NULL"),
        nullable=True,
        index=True,
    )
    user_id = Column(Integer, nullable=True, index=True)
    action = Column(String(20), nullable=False)
    reason = Column(JSON, nullable=True)
    model_version = Column(String(80), nullable=False)
    created_at = Column(DateTime(), nullable=False, default=func.now())


__all__ = [
    "ActivationAuditOutbox",
    "Asset",
    "ServiceArtefactDependencyLink",
    "ArtefactIdentityConflict",
    "ArtefactMergeRecord",
    "ArtefactRelationship",
    "AssetAppetiteConfig",
    "BusinessServiceAppetiteConfig",
    "AssetConnection",
    "AssetEvidenceSignal",
    "AssetFinding",
    "AssetFindingStatus",
    "AssetIdentifier",
    "AssetLifecycleState",
    "AssetObservedPort",
    "AssetStatus",
    "AssetStatusHistory",
    "AuditEvent",
    "AuthMsGroupRole",
    "AuthMsTenantAllowlist",
    "AuthTenantSettings",
    "Base",
    "BaselineRiskHypothesis",
    "BusinessProcessActivation",
    "RecurrenceOccurrence",
    "RecurrenceSchedule",
    "RiskAppetitePolicy",
    "RiskEvaluation",
    "ReviewReopening",
    "ForecastImpact",
    "BusinessService",
    "BusinessProcessRecommendationStatus",
    "BusinessProcessDecisionAction",
    "BusinessProcessRecommendation",
    "BusinessProcessDecisionLog",
    "DecisionRecord",
    "CloudAsset",
    "CloudCredentials",
    "AccessConnector",
    "ArtefactAccessLifecycle",
    "ConnectorAccessTest",
    "ComplianceControl",
    "ContextualAccessPolicy",
    "ComplianceFramework",
    "ConnectionState",
    "ConnectivityStatus",
    "Control",
    "ControlCoverageStatus",
    "ControlEvidence",
    "ControlMapping",
    "ControlShareLink",
    "Criticality",
    "DependencyBundle",
    "DependencyBundleVersion",
    "EvidenceImportBatch",
    "EvidenceManualEntry",
    "EvidenceReceipt",
    "EvidenceSource",
    "EvidenceSourceException",
    "EvidenceSourceScope",
    "LearningImprovementCandidate",
    "LearningLoopRun",
    "Environment",
    "Finding",
    "FindingStatus",
    "InviteToken",
    "JiraTicket",
    "JiraTicketStatus",
    "KeyRiskIndicator",
    "LeadershipAuthorization",
    "MappingDecision",
    "MfaChallenge",
    "OnboardingStatus",
    "Organization",
    "OrganizationBiaBaseline",
    "OrganizationDomain",
    "OrganizationIdentityConfirmation",
    "OrganizationIdentityEvidence",
    "OrganizationLegalEntity",
    "OrganizationOperatingContextSuggestion",
    "OrganizationLocation",
    "OrganizationScope",
    "OrganizationUnit",
    "OrganizationUnitMatchSuggestion",
    "OrganizationUnitMembership",
    "OrganizationUnitRelationship",
    "OrgMandateRoleAssignment",
    "OrgMandateScopeBinding",
    "OrgReportingLineException",
    "OrgProcessConfig",
    "OrgServiceConfig",
    "OrgVisibilityPolicy",
    "ProcessBiaAssessment",
    "ProcessOwnerAcceptance",
    "ProcessScanScope",
    "ProcessScannerLink",
    "ProcessTailoringSignal",
    "ServiceBiaException",
    "PasswordResetToken",
    "PermissionPreset",
    "PermissionProfile",
    "PermissionSubject",
    "VerificationRun",
    "PolicyRule",
    "ProcessTemplate",
    "RecoveryAction",
    "Recommendation",
    "ResolutionRecord",
    "RiskIngestionBatch",
    "RiskIngestionBatchStatus",
    "VerificationRecord",
    "RiskAppetite",
    "SEVERITY_ENUM",
    "ScanRun",
    "ScanStartMode",
    "ScanStatus",
    "ServiceAppetiteReassessment",
    "ServiceChangeNotice",
    "ServiceChangeNoticeKind",
    "ServiceJourneySignal",
    "ServiceTemplate",
    "SetupConfidence",
    "SeverityLevel",
    "SlotInstance",
    "SlotTemplate",
    "TemplateCandidate",
    "TemplateLearningRun",
    "Threat",
    "TrainingSignal",
    "USER_STATUS_ENUM",
    "User",
    "UserIdentity",
    "UserSession",
    "UserStatus",
    "ValueStream",
    "ValueStreamSignal",
    "utcnow",
]

"""
Recommendation engine - Prioritizes and routes remediation actions.
"""

import enum
from dataclasses import dataclass
from typing import Dict, List

from src.core.logging_config import get_logger
from src.remediation.finding_processor import RemediationAction, RemediationType

logger = get_logger(__name__)


class TaskType(enum.Enum):
    """High-level task categorization for routing."""

    DOCUMENTATION = "documentation"
    DEVELOPMENT = "development"
    AUTO_REMEDIATION = "auto_remediation"
    MANUAL_REVIEW = "manual_review"


@dataclass
class RecommendationBatch:
    """Batch of related recommendations."""

    batch_id: str
    task_type: TaskType
    priority: int
    actions: List[RemediationAction]
    estimated_total_effort_hours: float
    can_parallelize: bool
    dependencies: List[str]  # Other batch IDs that must complete first


class RecommendationEngine:
    """Prioritizes and groups remediation actions into actionable batches.

    Groups similar actions together, identifies dependencies, and creates
    an execution plan for remediation.
    """

    def __init__(self):
        logger.info("recommendation_engine_initialized")

    def prioritize_actions(
        self, actions: List[RemediationAction]
    ) -> Dict[TaskType, List[RecommendationBatch]]:
        """Prioritize and group actions by task type.

        Args:
            actions: List of remediation actions

        Returns:
            Dict mapping task types to prioritized batches
        """
        logger.info("prioritizing_actions", total_actions=len(actions))

        # Group by task type
        grouped_actions: Dict[TaskType, List[RemediationAction]] = {
            TaskType.DOCUMENTATION: [],
            TaskType.DEVELOPMENT: [],
            TaskType.AUTO_REMEDIATION: [],
            TaskType.MANUAL_REVIEW: [],
        }

        for action in actions:
            task_type = self._map_remediation_to_task_type(action.remediation_type)
            grouped_actions[task_type].append(action)

        # Create batches for each task type
        result: Dict[TaskType, List[RecommendationBatch]] = {}

        for task_type, task_actions in grouped_actions.items():
            if not task_actions:
                continue

            # Sort by priority
            task_actions.sort(key=lambda a: a.priority)

            # Create batches
            batches = self._create_batches(task_type, task_actions)
            result[task_type] = batches

            logger.info(
                "task_type_processed",
                task_type=task_type.value,
                actions_count=len(task_actions),
                batches_count=len(batches),
            )

        return result

    def _map_remediation_to_task_type(self, remediation_type: RemediationType) -> TaskType:
        """Map remediation type to high-level task type."""
        mapping = {
            RemediationType.DOCUMENTATION: TaskType.DOCUMENTATION,
            RemediationType.DEVELOPMENT: TaskType.DEVELOPMENT,
            RemediationType.CONFIGURATION: TaskType.DEVELOPMENT,
            RemediationType.AUTO_FIX: TaskType.AUTO_REMEDIATION,
            RemediationType.MANUAL_REVIEW: TaskType.MANUAL_REVIEW,
            RemediationType.POLICY_UPDATE: TaskType.DOCUMENTATION,
        }

        return mapping.get(remediation_type, TaskType.MANUAL_REVIEW)

    def _create_batches(
        self, task_type: TaskType, actions: List[RemediationAction]
    ) -> List[RecommendationBatch]:
        """Create batches of related actions."""
        batches: List[RecommendationBatch] = []

        if task_type == TaskType.AUTO_REMEDIATION:
            # Group auto-remediation by risk level
            batches.extend(self._batch_by_risk_level(actions))

        elif task_type == TaskType.DOCUMENTATION:
            # Group documentation by type
            batches.extend(self._batch_by_documentation_type(actions))

        elif task_type == TaskType.DEVELOPMENT:
            # Group development by affected resources
            batches.extend(self._batch_by_affected_resources(actions))

        else:
            # Manual review - create individual batches
            for action in actions:
                batch = RecommendationBatch(
                    batch_id=f"manual_{action.finding_id}",
                    task_type=task_type,
                    priority=action.priority,
                    actions=[action],
                    estimated_total_effort_hours=action.estimated_effort_hours,
                    can_parallelize=False,
                    dependencies=[],
                )
                batches.append(batch)

        # Sort batches by priority
        batches.sort(key=lambda b: b.priority)

        return batches

    def _batch_by_risk_level(self, actions: List[RemediationAction]) -> List[RecommendationBatch]:
        """Batch auto-remediation actions by risk level."""
        low_risk = [a for a in actions if a.auto_fix_risk_level == "low"]
        medium_risk = [a for a in actions if a.auto_fix_risk_level == "medium"]
        high_risk = [a for a in actions if a.auto_fix_risk_level == "high"]

        batches = []

        if low_risk:
            batch = RecommendationBatch(
                batch_id="auto_fix_low_risk",
                task_type=TaskType.AUTO_REMEDIATION,
                priority=min(a.priority for a in low_risk),
                actions=low_risk,
                estimated_total_effort_hours=sum(a.estimated_effort_hours for a in low_risk),
                can_parallelize=True,
                dependencies=[],
            )
            batches.append(batch)

        if medium_risk:
            batch = RecommendationBatch(
                batch_id="auto_fix_medium_risk",
                task_type=TaskType.AUTO_REMEDIATION,
                priority=min(a.priority for a in medium_risk),
                actions=medium_risk,
                estimated_total_effort_hours=sum(a.estimated_effort_hours for a in medium_risk),
                can_parallelize=False,
                dependencies=[],
            )
            batches.append(batch)

        if high_risk:
            batch = RecommendationBatch(
                batch_id="auto_fix_high_risk",
                task_type=TaskType.AUTO_REMEDIATION,
                priority=min(a.priority for a in high_risk),
                actions=high_risk,
                estimated_total_effort_hours=sum(a.estimated_effort_hours for a in high_risk),
                can_parallelize=False,
                dependencies=[],
            )
            batches.append(batch)

        return batches

    def _batch_by_documentation_type(
        self, actions: List[RemediationAction]
    ) -> List[RecommendationBatch]:
        """Batch documentation actions by documentation type."""
        from collections import defaultdict

        doc_groups: Dict[str, List[RemediationAction]] = defaultdict(list)

        for action in actions:
            doc_type = action.documentation_type.value if action.documentation_type else "other"
            doc_groups[doc_type].append(action)

        batches = []

        for doc_type, doc_actions in doc_groups.items():
            batch = RecommendationBatch(
                batch_id=f"doc_{doc_type}",
                task_type=TaskType.DOCUMENTATION,
                priority=min(a.priority for a in doc_actions),
                actions=doc_actions,
                estimated_total_effort_hours=sum(a.estimated_effort_hours for a in doc_actions),
                can_parallelize=True,
                dependencies=[],
            )
            batches.append(batch)

        return batches

    def _batch_by_affected_resources(
        self, actions: List[RemediationAction]
    ) -> List[RecommendationBatch]:
        """Batch development actions by affected resources."""
        from collections import defaultdict

        resource_groups: Dict[str, List[RemediationAction]] = defaultdict(list)

        for action in actions:
            # Group by first affected resource or "general"
            resource = (
                action.affected_resources[0] if action.affected_resources else "general"
            )
            resource_groups[resource].append(action)

        batches = []

        for resource, resource_actions in resource_groups.items():
            batch = RecommendationBatch(
                batch_id=f"dev_{resource[:20]}",
                task_type=TaskType.DEVELOPMENT,
                priority=min(a.priority for a in resource_actions),
                actions=resource_actions,
                estimated_total_effort_hours=sum(a.estimated_effort_hours for a in resource_actions),
                can_parallelize=False,  # Dev tasks on same resource can't be parallelized
                dependencies=[],
            )
            batches.append(batch)

        return batches

    def generate_execution_plan(
        self, batches: Dict[TaskType, List[RecommendationBatch]]
    ) -> List[RecommendationBatch]:
        """Generate ordered execution plan across all task types.

        Args:
            batches: Batches grouped by task type

        Returns:
            Ordered list of batches with dependencies resolved
        """
        all_batches = []
        for task_batches in batches.values():
            all_batches.extend(task_batches)

        # Sort by priority, then by whether they can be parallelized
        all_batches.sort(key=lambda b: (b.priority, not b.can_parallelize))

        # Identify dependencies (simple heuristic: auto-fix should come after manual review)
        auto_fix_batches = [b for b in all_batches if b.task_type == TaskType.AUTO_REMEDIATION]
        high_priority_reviews = [
            b
            for b in all_batches
            if b.task_type == TaskType.MANUAL_REVIEW and b.priority <= 2
        ]

        # Auto-fix batches depend on high-priority reviews being done
        if high_priority_reviews and auto_fix_batches:
            for auto_batch in auto_fix_batches:
                auto_batch.dependencies = [b.batch_id for b in high_priority_reviews]

        logger.info(
            "execution_plan_generated",
            total_batches=len(all_batches),
            parallelizable=sum(1 for b in all_batches if b.can_parallelize),
        )

        return all_batches

import enum


class ValueStreamEvent(str, enum.Enum):
    VALUE_STREAM_ADDED = "value_stream_added"
    CUSTOM_PROCESS_CREATED = "custom_process_created"
    VALUE_STREAM_PRIORITY_SET = "value_stream_priority_set"
    VALUE_STREAM_JOURNEY_STARTED = "value_stream_journey_started"
    DIAGRAM_TOGGLED = "diagram_toggled"
    GRAPH_NODE_CLICKED = "graph_node_clicked"
    GRAPH_LEVEL_VIEWED = "graph_level_viewed"
    DIAGRAM_UNAVAILABLE_SEEN = "diagram_unavailable_seen"
    # UC-TDM-01 slot mapping signals
    SLOT_MAPPED = "slot_mapped"
    SLOT_NOT_APPLICABLE = "slot_not_applicable"
    SLOT_UNKNOWN = "slot_unknown"
    # BSP-05 intelligence-engine suggestion signals
    SLOT_MAPPING_SUGGESTED = "slot_mapping_suggested"
    # BSP-13 — accountable validation of the Baseline Risk Hypothesis
    HYPOTHESIS_VALIDATED = "hypothesis_validated"
    # Dashboard slice 4 — a lapsed review reopened the process evaluation
    REVIEW_REOPENED = "review_reopened"
    SERVICE_PUBLISHED = "service_published"
    COVERAGE_SCORE_RECORDED = "coverage_score_recorded"
    # UC-TDM-02 template learning signals
    TEMPLATE_CANDIDATE_GENERATED = "template_candidate_generated"
    TEMPLATE_VERSION_PUBLISHED = "template_version_published"
    TEMPLATE_UPGRADE_ACCEPTED = "template_upgrade_accepted"
    TEMPLATE_UPGRADE_DECLINED = "template_upgrade_declined"
    TEMPLATE_VARIANT_APPLIED = "template_variant_applied"
    LEARNING_RUN_COMPLETED = "learning_run_completed"
    CANDIDATE_IMPROVEMENT_GENERATED = "candidate_improvement_generated"
    IMPROVEMENT_AUTO_APPLIED = "improvement_auto_applied"
    IMPROVEMENT_QUEUED_FOR_REVIEW = "improvement_queued_for_review"

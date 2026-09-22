TEMPLATE_GOVERNANCE_SCHEDULED_RUN_PATH = "/api/v1/internal/template-governance/runs/scheduled"
LEARNING_LOOP_SCHEDULED_RUN_PATH = "/api/v1/internal/learning/runs/scheduled"

# Risklence Scanner agent endpoints (Step 3.5 setup + Step 4.1 discovery
# command delivery/acknowledgement) — called by the standalone scanner
# process itself, never a logged-in browser user. Every route under this
# prefix is authenticated by its own per-instance activation-token
# credential (scanner_agent.py's require_scanner_instance), not by the
# platform's user JWT — so the whole prefix is exempt from
# TenantContextMiddleware's JWT requirement, same pattern as the
# /public/onboarding/ prefix exemption. A prefix (not individual literal
# paths) because Step 4.1 added routes with path parameters
# (/commands/{id}/acknowledge, /discovery-runs/{id}/status) that a literal
# PUBLIC_PATHS set membership check can't match.
SCANNER_AGENT_PATH_PREFIX = "/api/v1/scanner-agent/"

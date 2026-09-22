"""Typed paths and errors for explicit onboarding page submission."""

ONBOARDING_PAGE_SUBMISSION_PREFIX = "/api/v1/onboarding/page-submissions"
OPERATING_CONTEXT_SUBMISSION_PATH = "/operating-context"
ORGANIZATION_UNITS_SUBMISSION_PATH = "/organization-units"
ORGANIZATION_UNIT_SCOPE_SUBMISSION_PATH = "/organization-unit-scope"

ONBOARDING_PAGE_SUBMISSION_ADMIN_REQUIRED = (
    "Organisation administrator access is required to submit onboarding decisions"
)
ONBOARDING_PAGE_SUBMISSION_DUPLICATE_DECISION = (
    "Each onboarding record may be submitted only once per page"
)
ONBOARDING_PAGE_SUBMISSION_OPERATING_CONTEXT_NOT_FOUND = (
    "Organisation operating-context suggestion not found"
)
ONBOARDING_PAGE_SUBMISSION_OPERATING_CONTEXT_STALE = (
    "An operating-context suggestion changed before this page was submitted"
)
ONBOARDING_PAGE_SUBMISSION_UNIT_NOT_FOUND = "Organisation unit not found"
ONBOARDING_PAGE_SUBMISSION_UNIT_NAME_REQUIRED = "A unit name is required."

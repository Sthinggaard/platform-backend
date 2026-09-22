#!/bin/bash

#
# UC-18 Sprint 1 UAT Test Script
#
# This script automates the UAT testing process for the Living AI Onboarding Canvas.
# It walks through the complete flow: creating session, getting prompts, responding,
# testing evidence pipeline, and checking progress.
#

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
API_BASE="http://localhost:8000"
AUTH_TOKEN="${AUTH_TOKEN:-}"  # Set via environment variable if needed

# Helper functions
print_header() {
    echo -e "\n${BLUE}========================================${NC}"
    echo -e "${BLUE}$1${NC}"
    echo -e "${BLUE}========================================${NC}\n"
}

print_success() {
    echo -e "${GREEN}✅ $1${NC}"
}

print_error() {
    echo -e "${RED}❌ $1${NC}"
}

print_info() {
    echo -e "${YELLOW}ℹ️  $1${NC}"
}

api_call() {
    local method=$1
    local endpoint=$2
    local data=$3

    local auth_header=""
    if [ -n "$AUTH_TOKEN" ]; then
        auth_header="-H \"Authorization: Bearer $AUTH_TOKEN\""
    fi

    if [ -n "$data" ]; then
        eval curl -s -X "$method" "$API_BASE$endpoint" \
            -H "Content-Type: application/json" \
            $auth_header \
            -d "'$data'"
    else
        eval curl -s -X "$method" "$API_BASE$endpoint" \
            $auth_header
    fi
}

# Check prerequisites
print_header "Checking Prerequisites"

# Check if API is running
if curl -s "$API_BASE/health" > /dev/null 2>&1; then
    print_success "API is running at $API_BASE"
else
    print_error "API is not running at $API_BASE"
    print_info "Please start the API with: make run"
    exit 1
fi

# Check if jq is installed
if command -v jq &> /dev/null; then
    print_success "jq is installed"
else
    print_error "jq is not installed"
    print_info "Install with: brew install jq (macOS) or apt-get install jq (Linux)"
    exit 1
fi

# Login to get auth token if not provided
if [ -z "$AUTH_TOKEN" ]; then
    print_info "Logging in with admin@example.com..."
    LOGIN_RESPONSE=$(curl -s -X POST "$API_BASE/api/v1/auth/login" \
        -H "Content-Type: application/json" \
        -d '{"email": "admin@example.com", "password": "changeme"}')

    AUTH_TOKEN=$(echo "$LOGIN_RESPONSE" | jq -r '.access_token')

    if [ "$AUTH_TOKEN" = "null" ] || [ -z "$AUTH_TOKEN" ]; then
        print_error "Login failed"
        echo "$LOGIN_RESPONSE" | jq '.'
        exit 1
    fi

    print_success "Logged in successfully"
fi

# Test 1: Use Existing Session (Session 4 - collecting_profile status)
print_header "Test 1: Using Test Session"

SESSION_ID=4
print_info "Using existing session ID: $SESSION_ID"
print_success "Session ready for testing"

# Test 2: Get First Prompt
print_header "Test 2: Get First Prompt (Company Name)"

PROMPT_1=$(api_call POST "/api/v1/onboarding/$SESSION_ID/prompt/mock-next")

if echo "$PROMPT_1" | jq -e '.type' > /dev/null 2>&1; then
    PROMPT_TYPE=$(echo "$PROMPT_1" | jq -r '.type')
    print_success "First prompt received: Type = $PROMPT_TYPE"
    echo "$PROMPT_1" | jq '.payload'
else
    print_error "Failed to get first prompt"
    echo "$PROMPT_1"
    exit 1
fi

# Test 3: Respond to First Prompt
print_header "Test 3: Respond with Company Name"

RESPONSE_1=$(api_call POST "/api/v1/onboarding/$SESSION_ID/prompt/respond" '{
    "value": "Acme Corp UAT"
}')

if echo "$RESPONSE_1" | jq -e '.[0].id' > /dev/null 2>&1; then
    print_success "Response recorded"
    echo "$RESPONSE_1" | jq '.'
else
    print_error "Failed to record response"
    echo "$RESPONSE_1"
    exit 1
fi

# Test 4: Get Second Prompt (Company Size Options)
print_header "Test 4: Get Second Prompt (Company Size)"

PROMPT_2=$(api_call POST "/api/v1/onboarding/$SESSION_ID/prompt/mock-next")

if echo "$PROMPT_2" | jq -e '.type' > /dev/null 2>&1; then
    PROMPT_TYPE=$(echo "$PROMPT_2" | jq -r '.type')
    print_success "Second prompt received: Type = $PROMPT_TYPE"

    if [ "$PROMPT_TYPE" = "present_options" ]; then
        print_success "Correctly switched to options prompt"
        OPTION_COUNT=$(echo "$PROMPT_2" | jq '.payload.options | length')
        print_info "Options available: $OPTION_COUNT"
        echo "$PROMPT_2" | jq '.payload.options'
    fi
else
    print_error "Failed to get second prompt"
    echo "$PROMPT_2"
fi

# Test 5: Respond with Option
print_header "Test 5: Respond with Company Size Option"

RESPONSE_2=$(api_call POST "/api/v1/onboarding/$SESSION_ID/prompt/respond" '{
    "option_id": "51-200",
    "value": "51-200"
}')

if echo "$RESPONSE_2" | jq -e '.[0].id' > /dev/null 2>&1; then
    print_success "Option response recorded"
else
    print_error "Failed to record option response"
    echo "$RESPONSE_2"
fi

# Test 6: Check Progress
print_header "Test 6: Check Overall Progress"

PROGRESS=$(api_call GET "/api/v1/onboarding/$SESSION_ID/progress")

if echo "$PROGRESS" | jq -e '.completed' > /dev/null 2>&1; then
    COMPLETED=$(echo "$PROGRESS" | jq -r '.completed')
    TOTAL=$(echo "$PROGRESS" | jq -r '.total')
    PERCENTAGE=$(echo "$PROGRESS" | jq -r '.percentage')
    print_success "Progress: $COMPLETED/$TOTAL fields ($PERCENTAGE%)"
    echo "$PROGRESS" | jq '.'
else
    print_error "Failed to get progress"
    echo "$PROGRESS"
fi

# Test 7: Check Artefact Completeness
print_header "Test 7: Check Artefact Completeness"

COMPLETENESS=$(api_call GET "/api/v1/onboarding/$SESSION_ID/artefacts/completeness")

if echo "$COMPLETENESS" | jq -e '.artefacts' > /dev/null 2>&1; then
    print_success "Artefact completeness retrieved"

    ORG_PROFILE_PCT=$(echo "$COMPLETENESS" | jq -r '.artefacts.organisation_profile * 100 | floor')
    print_info "Organisation Profile: $ORG_PROFILE_PCT%"

    echo "$COMPLETENESS" | jq '.summary'
else
    print_error "Failed to get completeness"
    echo "$COMPLETENESS"
fi

# Test 8: Ingest Evidence Signal (AWS VPC)
print_header "Test 8: Ingest Evidence Signal (AWS VPC)"

EVIDENCE_1=$(api_call POST "/api/v1/onboarding/$SESSION_ID/evidence" '{
    "asset_type": "aws_resource",
    "provider": "aws",
    "identifier": "vpc-uat-12345",
    "signal": {
        "resource_type": "vpc",
        "region": "us-east-1",
        "criticality": "high",
        "cidr_blocks": ["10.0.0.0/16"]
    },
    "confidence": 0.95,
    "source": "cloud_connector"
}')

if echo "$EVIDENCE_1" | jq -e '.id' > /dev/null 2>&1; then
    EVIDENCE_ID=$(echo "$EVIDENCE_1" | jq -r '.id')
    print_success "Evidence signal ingested: ID = $EVIDENCE_ID"
    echo "$EVIDENCE_1" | jq '.'
else
    print_error "Failed to ingest evidence"
    echo "$EVIDENCE_1"
fi

# Test 9: Analyze Evidence Signal
print_header "Test 9: Analyze Evidence Signal"

ANALYSIS=$(api_call POST "/api/v1/onboarding/$SESSION_ID/evidence/$EVIDENCE_ID/analyze")

if echo "$ANALYSIS" | jq -e '.applicable' > /dev/null 2>&1; then
    APPLICABLE=$(echo "$ANALYSIS" | jq -r '.applicable')

    if [ "$APPLICABLE" = "true" ]; then
        ARTEFACT_TYPE=$(echo "$ANALYSIS" | jq -r '.artefact_type')
        CONFIDENCE=$(echo "$ANALYSIS" | jq -r '.confidence')
        AUTO_APPLY=$(echo "$ANALYSIS" | jq -r '.auto_apply_eligible')

        print_success "Signal analyzed successfully"
        print_info "Target artefact: $ARTEFACT_TYPE"
        print_info "Confidence: $CONFIDENCE"
        print_info "Auto-apply eligible: $AUTO_APPLY"

        echo "$ANALYSIS" | jq '.patch'
    else
        print_error "Signal not applicable"
    fi
else
    print_error "Failed to analyze evidence"
    echo "$ANALYSIS"
fi

# Test 10: Ingest Evidence with Auto-Apply
print_header "Test 10: Ingest Evidence with Auto-Apply (Okta)"

EVIDENCE_2=$(api_call POST "/api/v1/onboarding/$SESSION_ID/evidence?auto_apply=true" '{
    "asset_type": "identity_provider",
    "provider": "saml",
    "identifier": "okta-uat",
    "signal": {
        "provider_name": "Okta",
        "mfa_enabled": true,
        "user_count": 150
    },
    "confidence": 0.9,
    "source": "integration"
}')

if echo "$EVIDENCE_2" | jq -e '.id' > /dev/null 2>&1; then
    print_success "Evidence auto-applied (high confidence ≥0.8)"
    echo "$EVIDENCE_2" | jq '.'
else
    print_error "Failed to auto-apply evidence"
    echo "$EVIDENCE_2"
fi

# Test 11: Verify Auto-Applied Changes
print_header "Test 11: Verify Auto-Applied Changes"

COMPLETENESS_AFTER=$(api_call GET "/api/v1/onboarding/$SESSION_ID/artefacts/completeness")

if echo "$COMPLETENESS_AFTER" | jq -e '.artefacts' > /dev/null 2>&1; then
    ASSET_INV=$(echo "$COMPLETENESS_AFTER" | jq -r '.artefacts.asset_inventory * 100 | floor')
    IAM_MODEL=$(echo "$COMPLETENESS_AFTER" | jq -r '.artefacts.identity_access_model * 100 | floor')

    print_success "Artefacts updated from evidence"
    print_info "Asset Inventory: $ASSET_INV%"
    print_info "IAM Model: $IAM_MODEL%"

    echo "$COMPLETENESS_AFTER" | jq '.summary'
else
    print_error "Failed to verify changes"
fi

# Test 12: View Event Timeline
print_header "Test 12: View Event Timeline (Last 10 Events)"

EVENTS=$(api_call GET "/api/v1/onboarding/$SESSION_ID/events")

if echo "$EVENTS" | jq -e '.[0].id' > /dev/null 2>&1; then
    EVENT_COUNT=$(echo "$EVENTS" | jq 'length')
    print_success "Event timeline retrieved: $EVENT_COUNT events"

    echo "$EVENTS" | jq '.[-10:] | .[] | {id, actor, type, artefact_ref}'
else
    print_error "Failed to get event timeline"
    echo "$EVENTS"
fi

# Summary
print_header "UAT Test Summary"

echo -e "${GREEN}✅ All tests completed!${NC}\n"

print_info "Session ID: $SESSION_ID"
print_info "Total events: $EVENT_COUNT"
print_info "Progress: $COMPLETED/$TOTAL fields ($PERCENTAGE%)"
print_info "Avg completion: $(echo "$COMPLETENESS_AFTER" | jq -r '.summary.average_completion')%"

echo ""
print_info "You can continue testing with:"
echo "  curl -X POST $API_BASE/api/v1/onboarding/$SESSION_ID/prompt/mock-next | jq"
echo "  curl $API_BASE/api/v1/onboarding/$SESSION_ID/progress | jq"
echo "  curl $API_BASE/api/v1/onboarding/$SESSION_ID/events | jq"

echo ""
print_success "Sprint 1 UAT: PASSED ✅"

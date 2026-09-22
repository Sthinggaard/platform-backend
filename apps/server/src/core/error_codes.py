# ─── ERROR CODES ──────────────────────────────────────────────────────────────
# Canonical error_type constants used in all HTTPException detail payloads.
# Single source of truth — never use raw strings in raise HTTPException().
# Mirrors apps/tenant/features/api/errorCodes.ts on the frontend.
#
# Usage:
#   from src.core.error_codes import E
#   raise HTTPException(status_code=401, detail={"error_type": E.INVALID_CREDENTIALS})

class E:
    # ─── Auth ─────────────────────────────────────────────────────────────────
    INVALID_CREDENTIALS         = "invalid_credentials"
    LOCKED                      = "locked"
    MFA_REQUIRED                = "mfa_required"
    SUSPENDED                   = "suspended"

    # ─── Token / session ──────────────────────────────────────────────────────
    INVALID_TOKEN               = "invalid_token"
    TOKEN_EXPIRED               = "token_expired"
    TOKEN_REDEEMED              = "token_redeemed"
    INVALID_SESSION_ID          = "invalid_session_id"
    SESSION_NOT_FOUND           = "session_not_found"
    SESSION_EXPIRED             = "session_expired"
    SESSION_UNAVAILABLE         = "session_unavailable"

    # ─── Verification ─────────────────────────────────────────────────────────
    INVALID_VERIFICATION_CODE   = "invalid_verification_code"
    INVALID_VERIFICATION_CHALLENGE = "invalid_verification_challenge"
    VERIFICATION_CODE_EXPIRED   = "verification_code_expired"
    VERIFICATION_CODE_LOCKED    = "verification_code_locked"
    VERIFICATION_CODE_USED      = "verification_code_used"
    INVALID_CONFIRMATION        = "invalid_confirmation"

    # ─── User / organisation ──────────────────────────────────────────────────
    INVALID_USER_CONTEXT        = "invalid_user_context"
    ORGANIZATION_NOT_FOUND      = "organization_not_found"
    EMAIL_ALREADY_IN_USE        = "email_already_in_use"

    # ─── Activation ───────────────────────────────────────────────────────────
    ACTIVATION_FAILED           = "activation_failed"
    SIGNUP_ACTIVATION_FAILED    = "signup_activation_failed"

    # ─── Draft / onboarding ───────────────────────────────────────────────────
    DRAFT_INCOMPLETE            = "draft_incomplete"
    DRAFT_LOCKED                = "draft_locked"
    DRAFT_NOT_LOCKED            = "draft_not_locked"
    DRAFT_UNAVAILABLE           = "draft_unavailable"
    INCOMPLETE_DRAFT            = "incomplete_draft"
    BASELINE_NOT_FOUND          = "baseline_not_found"
    CVR_NOT_FOUND               = "cvr_not_found"

    # ─── Validation ───────────────────────────────────────────────────────────
    VALIDATION_ERROR            = "validation_error"
    VALIDATION_FAILED           = "validation_failed"
    INVALID_FIELDS              = "invalid_fields"
    INVALID_SCHEMA              = "invalid_schema"
    PARSE_ERROR                 = "parse_error"

    # ─── General HTTP ─────────────────────────────────────────────────────────
    UNAUTHORIZED                = "unauthorized"
    AUTHENTICATION_ERROR        = "authentication_error"
    AUTHORIZATION_ERROR         = "authorization_error"
    RESOURCE_NOT_FOUND          = "resource_not_found"
    RATE_LIMIT                  = "rate_limit"
    INTERNAL_ERROR              = "internal_error"

    # ─── External / integration ───────────────────────────────────────────────
    PROVIDER_ERROR              = "provider_error"
    CONFIGURATION_ERROR         = "configuration_error"
    ENRICHMENT_TIMEOUT          = "enrichment_timeout"
    INSUFFICIENT_DATA           = "insufficient_data"
    MODELING_UNAVAILABLE        = "modeling_unavailable"
    UNSUPPORTED_MODEL_VERSION   = "unsupported_model_version"

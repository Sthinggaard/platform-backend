"""Auth request/response schemas."""

from datetime import datetime
from typing import Optional

from pydantic import BaseModel, EmailStr
from src.api.schemas.timestamps import UtcTimestamp


class LoginRequest(BaseModel):
    email: EmailStr
    password: str
    tenant_id: Optional[int] = None


class RefreshRequest(BaseModel):
    refresh_token: Optional[str] = None


class PasswordResetRequest(BaseModel):
    email: EmailStr


class PasswordResetConfirmRequest(BaseModel):
    token: str
    new_password: str


class InviteCreateRequest(BaseModel):
    email: EmailStr
    role: Optional[str] = None
    permissions: Optional[list[str]] = None
    # DISC-44 — required when role="consultant", forbidden otherwise. See
    # create_invite's own validation for the max-duration cap.
    access_expires_at: Optional[UtcTimestamp] = None


class InviteAcceptRequest(BaseModel):
    token: str
    password: Optional[str] = None


class SignupStartRequest(BaseModel):
    activation_token: str
    email: EmailStr
    password: str


class SignupVerifyRequest(BaseModel):
    activation_token: str
    challenge_id: str
    code: str


class SignupResendRequest(BaseModel):
    activation_token: str
    challenge_id: str


class MfaEnrollStartRequest(BaseModel):
    phone_e164: str


class MfaVerifyRequest(BaseModel):
    challenge_id: int
    code: str


class MfaDisableRequest(BaseModel):
    password: str


class MfaResendRequest(BaseModel):
    challenge_id: int


class AuthUserOut(BaseModel):
    id: int
    organization_id: int
    email: EmailStr
    first_name: Optional[str] = None
    last_name: Optional[str] = None
    title: Optional[str] = None
    email_verified: bool
    status: str
    role: str
    permissions: list[str]
    last_login_at: Optional[UtcTimestamp] = None
    mfa_enabled: bool = False
    mfa_phone_e164: Optional[str] = None
    mfa_phone_verified_at: Optional[UtcTimestamp] = None
    mfa_method: Optional[str] = None
    mfa_enforced_by_policy: bool = False
    # DISC-53 — null for every role except an active consultant (DISC-44's
    # own invariant: only a consultant invite ever sets this).
    access_expires_at: Optional[UtcTimestamp] = None


class TenantOut(BaseModel):
    id: int
    name: str
    sso_required: bool
    local_login_enabled: bool


class LoginResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    user: AuthUserOut
    tenant: TenantOut


class InviteAcceptResponse(BaseModel):
    access_token: Optional[str] = None
    token_type: Optional[str] = "bearer"
    user: Optional[AuthUserOut] = None
    tenant: Optional[TenantOut] = None
    sso_required: bool = False
    sso_google_enabled: bool = False
    sso_ms_enabled: bool = False
    message: Optional[str] = None


class SignupStartResponse(BaseModel):
    challenge_id: str
    masked_destination: str
    expires_at: UtcTimestamp
    verification_method: str = "email_code"
    message: str


class SignupVerifyResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    user: AuthUserOut
    tenant: TenantOut
    workspace_url: str
    activated_at: UtcTimestamp
    model_version: Optional[str] = None


class MfaChallengeResponse(BaseModel):
    mfa_required: bool = True
    challenge_id: int
    masked_destination: str


class RefreshResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"


class LogoutResponse(BaseModel):
    success: bool


class MessageResponse(BaseModel):
    message: str

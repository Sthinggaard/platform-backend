"""Tenant security policy schemas."""

from typing import Optional

from pydantic import BaseModel


class MfaPolicyOut(BaseModel):
    mfa_sms_enabled: bool
    mfa_required_for_all: bool
    mfa_required_for_admins: bool


class MfaPolicyUpdate(BaseModel):
    mfa_sms_enabled: Optional[bool] = None
    mfa_required_for_all: Optional[bool] = None
    mfa_required_for_admins: Optional[bool] = None

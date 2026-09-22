"""MFA challenge helpers."""

from __future__ import annotations

import hashlib
import hmac
import secrets
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

from sqlalchemy import select
from sqlalchemy.orm import Session

from src.core.config import settings
from src.core.exceptions import AuthenticationError, ValidationError
from src.core.models import MfaChallenge, User

MFA_PURPOSE_ENROLL = "enroll"
MFA_PURPOSE_LOGIN = "login"


@dataclass
class MfaChallengePayload:
    challenge: MfaChallenge
    code: str
    masked_destination: str


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _coerce_utc(value: datetime) -> datetime:
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value


def _hash_otp(code: str, salt: str) -> str:
    digest = hashlib.pbkdf2_hmac(
        "sha256",
        code.encode("utf-8"),
        salt.encode("utf-8"),
        150_000,
    )
    return digest.hex()


def _hash_destination(phone_e164: str) -> str:
    return hashlib.sha256(phone_e164.encode("utf-8")).hexdigest()


def mask_phone(phone_e164: str) -> str:
    digits = "".join(ch for ch in phone_e164 if ch.isdigit())
    if len(digits) <= 4:
        return phone_e164
    return f"+{'•' * len(digits[:-4])}{digits[-4:]}"


def generate_otp() -> str:
    return f"{secrets.randbelow(1_000_000):06d}"


def create_mfa_challenge(
    db: Session,
    user: User,
    organization_id: int,
    phone_e164: str,
    purpose: str,
    ip: str | None,
) -> MfaChallengePayload:
    if purpose not in {MFA_PURPOSE_ENROLL, MFA_PURPOSE_LOGIN}:
        raise ValidationError("Invalid MFA purpose")

    code = generate_otp()
    salt = secrets.token_hex(16)
    code_hash = _hash_otp(code, salt)
    expires_at = _now() + timedelta(minutes=settings.auth.mfa_otp_ttl_minutes)
    challenge = MfaChallenge(
        organization_id=organization_id,
        user_id=user.id,
        purpose=purpose,
        channel="sms",
        destination_hash=_hash_destination(phone_e164),
        code_hash=code_hash,
        salt=salt,
        expires_at=expires_at,
        used_at=None,
        attempt_count=0,
        max_attempts=settings.auth.mfa_otp_max_attempts,
        resend_count=0,
        last_sent_at=_now(),
        created_ip=ip,
    )
    db.add(challenge)
    db.commit()
    db.refresh(challenge)
    return MfaChallengePayload(
        challenge=challenge,
        code=code,
        masked_destination=mask_phone(phone_e164),
    )


def verify_mfa_challenge(
    db: Session,
    challenge_id: int,
    code: str,
    purpose: str,
) -> MfaChallenge:
    challenge = db.execute(
        select(MfaChallenge).where(MfaChallenge.id == challenge_id)
    ).scalar_one_or_none()
    if not challenge or challenge.purpose != purpose:
        raise AuthenticationError("Invalid MFA challenge")

    now = _now()
    if challenge.used_at:
        raise AuthenticationError("MFA challenge already used")
    if _coerce_utc(challenge.expires_at) <= now:
        raise AuthenticationError("MFA challenge expired")
    if challenge.attempt_count >= challenge.max_attempts:
        raise AuthenticationError("MFA challenge locked")

    expected = _hash_otp(code, challenge.salt)
    if not hmac.compare_digest(expected, challenge.code_hash):
        challenge.attempt_count += 1
        if challenge.attempt_count >= challenge.max_attempts:
            challenge.used_at = now
        db.add(challenge)
        db.commit()
        raise AuthenticationError("Invalid MFA code")

    challenge.used_at = now
    db.add(challenge)
    db.commit()
    return challenge


def resend_mfa_challenge(
    db: Session,
    challenge_id: int,
    phone_e164: str | None = None,
) -> MfaChallengePayload:
    challenge = db.execute(
        select(MfaChallenge).where(MfaChallenge.id == challenge_id)
    ).scalar_one_or_none()
    if not challenge:
        raise AuthenticationError("Invalid MFA challenge")
    if challenge.used_at:
        raise AuthenticationError("MFA challenge already used")

    now = _now()
    if challenge.last_sent_at and (
        now - _coerce_utc(challenge.last_sent_at)
    ).total_seconds() < settings.auth.mfa_resend_cooldown_seconds:
        raise ValidationError("MFA resend cooldown active")

    code = generate_otp()
    salt = secrets.token_hex(16)
    challenge.code_hash = _hash_otp(code, salt)
    challenge.salt = salt
    challenge.expires_at = now + timedelta(minutes=settings.auth.mfa_otp_ttl_minutes)
    challenge.last_sent_at = now
    challenge.attempt_count = 0
    challenge.resend_count += 1
    db.add(challenge)
    db.commit()
    db.refresh(challenge)

    masked = mask_phone(phone_e164) if phone_e164 else ""
    return MfaChallengePayload(
        challenge=challenge,
        code=code,
        masked_destination=masked,
    )

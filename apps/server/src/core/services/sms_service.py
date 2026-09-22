"""SMS delivery abstraction."""

from __future__ import annotations

from typing import Optional

import requests

from src.core.config import Environment, settings
from src.core.exceptions import ConfigurationError
from src.core.logging_config import get_logger

logger = get_logger(__name__)


def send_sms(phone_e164: str, message: str, purpose: Optional[str] = None) -> None:
    provider = (settings.sms.provider or "dev").lower()
    if provider == "twilio":
        _send_twilio_sms(phone_e164, message, purpose)
        return

    if settings.environment == Environment.PRODUCTION and provider != "dev":
        raise ConfigurationError("Unsupported SMS provider")

    logger.info(
        "sms_dev_logger",
        to=phone_e164,
        purpose=purpose,
        message=message,
    )


def _send_twilio_sms(phone_e164: str, message: str, purpose: Optional[str]) -> None:
    account_sid = settings.sms.twilio_account_sid
    auth_token = settings.sms.twilio_auth_token.get_secret_value() if settings.sms.twilio_auth_token else None
    from_phone = settings.sms.twilio_from
    if not account_sid or not auth_token or not from_phone:
        raise ConfigurationError("Twilio SMS configuration missing")

    url = f"https://api.twilio.com/2010-04-01/Accounts/{account_sid}/Messages.json"
    response = requests.post(
        url,
        data={
            "From": from_phone,
            "To": phone_e164,
            "Body": message,
        },
        auth=(account_sid, auth_token),
        timeout=10,
    )
    if response.status_code >= 400:
        logger.warning(
            "sms_twilio_send_failed",
            status_code=response.status_code,
            purpose=purpose,
        )
        raise ConfigurationError("SMS provider error")

    logger.info(
        "sms_twilio_sent",
        to=phone_e164,
        purpose=purpose,
    )

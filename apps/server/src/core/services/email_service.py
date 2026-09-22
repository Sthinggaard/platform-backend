"""Email delivery abstraction."""

from email.message import EmailMessage
import smtplib

from src.core.config import settings
from src.core.logging_config import get_logger

logger = get_logger(__name__)


def send_password_reset_email(email: str, reset_url: str) -> None:
    sender = settings.auth.email_from or "no-reply@risklence.local"
    host = settings.email.smtp_host
    if not host:
        logger.info(
            "password_reset_email_stubbed",
            recipient=email,
            sender=sender,
        )
        return

    msg = EmailMessage()
    msg["From"] = sender
    msg["To"] = email
    msg["Subject"] = "Reset your Risklence password"
    msg.set_content(
        "We received a request to reset your password.\n\n"
        f"Reset link: {reset_url}\n\n"
        "If you did not request this, you can ignore this email."
    )

    with smtplib.SMTP(host, settings.email.smtp_port, timeout=10) as smtp:
        if settings.email.smtp_use_tls:
            smtp.starttls()
        if settings.email.smtp_user and settings.email.smtp_password:
            smtp.login(settings.email.smtp_user, settings.email.smtp_password.get_secret_value())
        smtp.send_message(msg)

    logger.info(
        "password_reset_email_sent",
        recipient=email,
        sender=sender,
    )


def send_password_reset_sso_email(email: str) -> None:
    sender = settings.auth.email_from or "no-reply@risklence.local"
    host = settings.email.smtp_host
    if not host:
        logger.info(
            "password_reset_sso_email_stubbed",
            recipient=email,
            sender=sender,
        )
        return

    msg = EmailMessage()
    msg["From"] = sender
    msg["To"] = email
    msg["Subject"] = "Use SSO to access Risklence"
    msg.set_content(
        "We received a request to reset your Risklence password, "
        "but your organization uses single sign-on.\n\n"
        "Please sign in with your SSO provider instead."
    )

    with smtplib.SMTP(host, settings.email.smtp_port, timeout=10) as smtp:
        if settings.email.smtp_use_tls:
            smtp.starttls()
        if settings.email.smtp_user and settings.email.smtp_password:
            smtp.login(settings.email.smtp_user, settings.email.smtp_password.get_secret_value())
        smtp.send_message(msg)

    logger.info(
        "password_reset_sso_email_sent",
        recipient=email,
        sender=sender,
    )


def send_invite_email(email: str, invite_url: str, inviter_email: str | None = None) -> None:
    sender = settings.auth.email_from or "no-reply@risklence.local"
    host = settings.email.smtp_host
    if not host:
        logger.info(
            "invite_email_stubbed",
            recipient=email,
            sender=sender,
        )
        return

    msg = EmailMessage()
    msg["From"] = sender
    msg["To"] = email
    msg["Subject"] = "You're invited to Risklence"
    inviter_line = f"Invited by: {inviter_email}\n\n" if inviter_email else ""
    msg.set_content(
        "You have been invited to join Risklence.\n\n"
        f"{inviter_line}"
        f"Accept invite: {invite_url}\n\n"
        "If you were not expecting this, you can ignore this email."
    )

    with smtplib.SMTP(host, settings.email.smtp_port, timeout=10) as smtp:
        if settings.email.smtp_use_tls:
            smtp.starttls()
        if settings.email.smtp_user and settings.email.smtp_password:
            smtp.login(settings.email.smtp_user, settings.email.smtp_password.get_secret_value())
        smtp.send_message(msg)

    logger.info(
        "invite_email_sent",
        recipient=email,
        sender=sender,
    )


def send_signup_verification_email(email: str, verification_code: str) -> None:
    sender = settings.auth.email_from or "no-reply@risklence.local"
    host = settings.email.smtp_host
    if not host:
        logger.info(
            "signup_verification_email_stubbed",
            recipient=email,
            sender=sender,
        )
        return

    msg = EmailMessage()
    msg["From"] = sender
    msg["To"] = email
    msg["Subject"] = "Verify your Risklence account"
    msg.set_content(
        "Complete your Risklence account setup by entering this verification code:\n\n"
        f"{verification_code}\n\n"
        "If you did not request this, you can ignore this email."
    )

    with smtplib.SMTP(host, settings.email.smtp_port, timeout=10) as smtp:
        if settings.email.smtp_use_tls:
            smtp.starttls()
        if settings.email.smtp_user and settings.email.smtp_password:
            smtp.login(settings.email.smtp_user, settings.email.smtp_password.get_secret_value())
        smtp.send_message(msg)

    logger.info(
        "signup_verification_email_sent",
        recipient=email,
        sender=sender,
    )

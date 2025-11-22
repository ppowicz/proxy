import os
import smtplib
from dataclasses import dataclass
from email.message import EmailMessage
from functools import lru_cache
from pathlib import Path
from string import Template
from typing import Any, Dict, Iterable, List, Optional, Sequence, Union

from dotenv import load_dotenv

from core.logging import get_logger

load_dotenv()

LOGGER = get_logger("proxy.email")
EMAIL_TEMPLATES_DIR = Path(os.getenv("EMAIL_TEMPLATES_DIR") or (Path(__file__).resolve().parent.parent / "emails"))


@dataclass(frozen=True)
class SMTPSettings:
    host: str
    port: int
    username: Optional[str]
    password: Optional[str]
    sender: str
    use_tls: bool
    use_ssl: bool
    timeout: float


def _env_bool(key: str, default: bool = False) -> bool:
    value = os.getenv(key)
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


def get_smtp_settings() -> SMTPSettings:
    host = os.getenv("SMTP_HOST", "localhost")
    port = int(os.getenv("SMTP_PORT", "25"))
    username = os.getenv("SMTP_USERNAME")
    password = os.getenv("SMTP_PASSWORD")
    sender = os.getenv("SMTP_SENDER") or username or "no-reply@localhost"
    use_ssl = _env_bool("SMTP_USE_SSL", True)
    use_tls = _env_bool("SMTP_USE_TLS", not use_ssl)
    timeout = float(os.getenv("SMTP_TIMEOUT", "10"))
    return SMTPSettings(
        host=host,
        port=port,
        username=username,
        password=password,
        sender=sender,
        use_tls=use_tls,
        use_ssl=use_ssl,
        timeout=timeout,
    )


RecipientInput = Union[str, Sequence[str], Iterable[str]]


def _template_path(name: str) -> Path:
    return EMAIL_TEMPLATES_DIR / f"{name}.html"


@lru_cache(maxsize=32)
def _load_email_template(name: str) -> Optional[str]:
    path = _template_path(name)
    if not path.is_file():
        LOGGER.warning("[EMAIL] Missing template %s", path)
        return None
    try:
        return path.read_text(encoding="utf-8")
    except Exception as exc:  # pragma: no cover - defensive logging
        LOGGER.error("[EMAIL] Failed reading template %s: %s", path, exc)
        return None


def render_email_template(name: str, context: Optional[Dict[str, Any]] = None) -> str:
    raw = _load_email_template(name)
    if not raw:
        return ""
    try:
        template = Template(raw)
        return template.safe_substitute(context or {})
    except Exception:  # pragma: no cover - fallback to raw
        LOGGER.exception("[EMAIL] Failed rendering template %s", name)
        return raw


def clear_email_template_cache() -> None:
    _load_email_template.cache_clear()


def _normalize_recipients(recipients: RecipientInput) -> List[str]:
    if isinstance(recipients, str):
        return [recipients]
    normalized = []
    for recipient in recipients:
        if recipient:
            normalized.append(str(recipient))
    return normalized


def build_email_message(
    *,
    subject: str,
    body_text: str,
    recipients: RecipientInput,
    sender: Optional[str] = None,
    body_html: Optional[str] = None,
    settings: Optional[SMTPSettings] = None,
) -> EmailMessage:
    smtp_settings = settings or get_smtp_settings()
    to_addresses = _normalize_recipients(recipients)
    if not to_addresses:
        raise ValueError("At least one recipient is required")

    msg = EmailMessage()
    msg["Subject"] = subject.strip()
    msg["From"] = sender or smtp_settings.sender
    msg["To"] = ", ".join(to_addresses)
    msg.set_content(body_text or "")
    if body_html:
        msg.add_alternative(body_html, subtype="html")
    return msg


def send_email(
    *,
    subject: str,
    body_text: str,
    recipients: RecipientInput,
    sender: Optional[str] = None,
    body_html: Optional[str] = None,
    settings: Optional[SMTPSettings] = None,
) -> bool:
    smtp_settings = settings or get_smtp_settings()
    to_addresses = _normalize_recipients(recipients)
    if not to_addresses:
        LOGGER.warning("[EMAIL] No recipients provided for %s", subject)
        return False

    message = build_email_message(
        subject=subject,
        body_text=body_text,
        recipients=to_addresses,
        sender=sender or smtp_settings.sender,
        body_html=body_html,
        settings=smtp_settings,
    )

    smtp_client = None
    try:
        if smtp_settings.use_ssl:
            smtp_client = smtplib.SMTP_SSL(smtp_settings.host, smtp_settings.port, timeout=smtp_settings.timeout)
        else:
            smtp_client = smtplib.SMTP(smtp_settings.host, smtp_settings.port, timeout=smtp_settings.timeout)
            if smtp_settings.use_tls:
                smtp_client.starttls()

        if smtp_settings.username and smtp_settings.password:
            smtp_client.login(smtp_settings.username, smtp_settings.password)

        smtp_client.send_message(message)
        LOGGER.info("[EMAIL] Sent message to %s", message["To"])
        return True
    except Exception:
        LOGGER.exception("[EMAIL] Failed to send message to %s", to_addresses)
        return False
    finally:
        if smtp_client:
            try:
                smtp_client.quit()
            except Exception:
                LOGGER.debug("[EMAIL] Failed to close SMTP client cleanly", exc_info=True)

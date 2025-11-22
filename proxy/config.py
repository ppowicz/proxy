import os
import shutil
import time
from pathlib import Path
from typing import Dict, Optional, Tuple

from dotenv import load_dotenv
from core.logging import get_logger

load_dotenv()

ROOT_DOMAIN = os.getenv("ROOT_DOMAIN", "ppowicz.pl")
PROJECTS_ROOT = Path(os.getenv("PROJECTS_ROOT", "/home/ppowicz/projects"))
ERROR_TEMPLATE_PATH = Path(os.getenv("ERROR_TEMPLATE_PATH", "/home/ppowicz/proxy/sites/error.html"))
LOG_FILE_PATH = Path(
    os.getenv("LOG_FILE_PATH")
    or os.getenv("LOGGING_PATH", "")
    or "/home/ppowicz/proxy/proxy.log"
)
LOG_RETENTION_DAYS = int(os.getenv("LOG_RETENTION_DAYS", "90"))
LOG_CLEANUP_INTERVAL_SECONDS = int(os.getenv("LOG_CLEANUP_INTERVAL_SECONDS", str(6 * 60 * 60)))
SESSION_COOKIE_DOMAIN = os.getenv("SESSION_COOKIE_DOMAIN", ".ppowicz.pl")
PENDING_SESSION_MAX_AGE = int(os.getenv("PENDING_SESSION_MAX_AGE", "600"))

ALLOWED_HOST_SUFFIXES = [suffix.strip().lower() for suffix in os.getenv("ALLOWED_HOST_SUFFIXES", ROOT_DOMAIN).split(",") if suffix.strip()]
PROXY_AUTH_TOKEN_KEY = (os.getenv("PROXY_AUTH_TOKEN_KEY", "").strip()).encode()
PROXY_AUTH_COOKIE_TTL = int(os.getenv("PROXY_AUTH_COOKIE_TTL", str(24 * 60 * 60)))
CSRF_SECRET_KEY = (os.getenv("CSRF_SECRET_KEY") or os.getenv("PROXY_AUTH_TOKEN_KEY", "")).encode()

LOGIN_RATE_LIMIT_PER_IP = int(os.getenv("LOGIN_RATE_LIMIT_PER_IP", "10"))
LOGIN_RATE_LIMIT_PER_USER = int(os.getenv("LOGIN_RATE_LIMIT_PER_USER", "5"))
LOGIN_RATE_LIMIT_WINDOW_SECONDS = int(os.getenv("LOGIN_RATE_LIMIT_WINDOW_SECONDS", "900"))
TWO_FA_RATE_LIMIT_PER_SESSION = int(os.getenv("TWO_FA_RATE_LIMIT_PER_SESSION", "5"))
TWO_FA_RATE_LIMIT_WINDOW_SECONDS = int(os.getenv("TWO_FA_RATE_LIMIT_WINDOW_SECONDS", "900"))
REGISTER_RATE_LIMIT_PER_IP = int(os.getenv("REGISTER_RATE_LIMIT_PER_IP", "5"))
REGISTER_RATE_LIMIT_WINDOW_SECONDS = int(os.getenv("REGISTER_RATE_LIMIT_WINDOW_SECONDS", "3600"))
HTTP_BODY_LOG_BYTES = int(os.getenv("HTTP_LOG_BODY_LIMIT_BYTES", str(4 * 1024)))

BIND_HOST = "0.0.0.0"
BIND_PORT = 443
CERT_FILE = "/etc/letsencrypt/live/ppowicz.pl/fullchain.pem"
KEY_FILE = "/etc/letsencrypt/live/ppowicz.pl/privkey.pem"
SCAN_INTERVAL_SECONDS = 5.0
PROCESS_START_TIME = time.time()

ERROR_MESSAGES: Dict[str, Dict[str, str]] = {
    "404": {
        "TAB_TITLE": "404 Not Found",
        "TITLE": "Ta strona nie istnieje",
        "CODE": "404",
        "SUBTITLE": "Albo zniknęła, albo ktoś ją sobie wymyślił."
    },
    "401": {
        "TAB_TITLE": "401 Unauthorized",
        "TITLE": "Nie masz dostępu",
        "CODE": "401",
        "SUBTITLE": "Drzwi są, ale klucz nie pasuje."
    },
    "500": {
        "TAB_TITLE": "500 Internal Server Error",
        "TITLE": "Coś poszło nie tak",
        "CODE": "500",
        "SUBTITLE": "Serwer się pogubił."
    },
    "502": {
        "TAB_TITLE": "502 Bad Gateway",
        "TITLE": "Podserwer nie odpowiada",
        "CODE": "502",
        "SUBTITLE": "Po drugiej stronie coś powinno działać. Powinno..."
    },
    "bad_config": {
        "TAB_TITLE": "500 Configuration Error",
        "TITLE": "Błąd konfiguracji projektu",
        "CODE": "500",
        "SUBTITLE": "Ten projekt ma popsuty config. Popraw plik proxy-config.json i spróbuj ponownie."
    },
}

SENSITIVE_REQUEST_HEADERS = {"authorization", "proxy-authorization", "cookie"}
SENSITIVE_BODY_KEYWORDS = ("password", "passwd", "token", "secret", "key")

PASSWORD_TEMPLATE_PATH = Path("/home/ppowicz/proxy/sites/password.html")
LOGIN_TEMPLATE_PATH = Path("/home/ppowicz/proxy/sites/login.html")
REGISTER_TEMPLATE_PATH = Path("/home/ppowicz/proxy/sites/register.html")
REGISTER_PENDING_TEMPLATE_PATH = Path("/home/ppowicz/proxy/sites/register_pending.html")
USER_PANEL_TEMPLATE_PATH = Path("/home/ppowicz/proxy/sites/user_panel.html")
TWO_FA_SETUP_TEMPLATE_PATH = Path("/home/ppowicz/proxy/sites/2fa_setup.html")
TWO_FA_CHALLENGE_TEMPLATE_PATH = Path("/home/ppowicz/proxy/sites/2fa_challenge.html")

ADMIN_PAGE_FILES = {
    'home': Path("/home/ppowicz/proxy/sites/admin_home.html"),
    'db': Path("/home/ppowicz/proxy/sites/admin_db.html"),
    'logs': Path("/home/ppowicz/proxy/sites/admin_logs.html"),
    'users': Path("/home/ppowicz/proxy/sites/admin_users.html"),
    'roles': Path("/home/ppowicz/proxy/sites/admin_roles.html"),
}

ADMIN_ROUTE_TO_TEMPLATE = {
    '/': 'home',
    '': 'home',
    '/db': 'db',
    '/logs': 'logs',
    '/users': 'users',
    '/roles': 'roles',
}
LOGGER = get_logger("proxy.config")


def log_event(message: str, level: str = "info", console: bool = False, exc_info=False):
    log_func = getattr(LOGGER, level.lower(), LOGGER.info)
    log_func(message, exc_info=exc_info if exc_info else None)
    if console:
        print(message)


def log_operational(message: str):
    log_event(message, level="info", console=True)


def log_error(message: str, exc_info=False):
    log_event(message, level="error", console=True, exc_info=exc_info)


def _parse_log_timestamp(line: str) -> Optional[float]:
    timestamp_str = line[:23]
    try:
        return time.mktime(time.strptime(timestamp_str, "%Y-%m-%d %H:%M:%S,%f"))
    except (ValueError, OverflowError):
        return None


def cleanup_log_file(retention_days: int) -> int:
    if retention_days <= 0 or not LOG_FILE_PATH.is_file():
        return 0

    cutoff = time.time() - retention_days * 86400
    temp_path = LOG_FILE_PATH.with_suffix(".tmp")
    removed = 0
    try:
        with LOG_FILE_PATH.open("r", encoding="utf-8") as src, temp_path.open("w", encoding="utf-8") as dst:
            for line in src:
                ts = _parse_log_timestamp(line)
                if ts and ts < cutoff:
                    removed += 1
                    continue
                dst.write(line)
        temp_path.replace(LOG_FILE_PATH)
    except Exception as exc:
        log_error(f"[LOG ROTATE] Failed to cleanup proxy.log: {exc}")
        try:
            if temp_path.exists():
                temp_path.unlink()
        except Exception:
            pass
        return 0

    if removed:
        log_event(f"[LOG ROTATE] Removed {removed} log lines older than {retention_days} days", console=False)
    return removed


def _load_template(path: Path) -> str:
    if path.is_file():
        try:
            return path.read_text(encoding="utf-8")
        except Exception as exc:
            log_error(f"[FILE] Failed to read template {path}: {exc}")
    return ""


PASSWORD_TEMPLATE = _load_template(PASSWORD_TEMPLATE_PATH)
LOGIN_TEMPLATE = _load_template(LOGIN_TEMPLATE_PATH)
REGISTER_TEMPLATE = _load_template(REGISTER_TEMPLATE_PATH)
REGISTER_PENDING_TEMPLATE = _load_template(REGISTER_PENDING_TEMPLATE_PATH)
USER_PANEL_TEMPLATE = _load_template(USER_PANEL_TEMPLATE_PATH)
TWO_FA_SETUP_TEMPLATE = _load_template(TWO_FA_SETUP_TEMPLATE_PATH)
TWO_FA_CHALLENGE_TEMPLATE = _load_template(TWO_FA_CHALLENGE_TEMPLATE_PATH)


ERROR_TEMPLATE = _load_template(ERROR_TEMPLATE_PATH)
ADMIN_PAGE_TEMPLATES: Dict[str, str] = {key: _load_template(path) for key, path in ADMIN_PAGE_FILES.items()}


def render_error_page(key: str) -> Tuple[int, str]:
    msg = ERROR_MESSAGES.get(key) or ERROR_MESSAGES["500"]
    status_code = int(key) if key.isdigit() else 500

    if ERROR_TEMPLATE:
        html = (
            ERROR_TEMPLATE
            .replace("{TAB_TITLE}", msg.get("TAB_TITLE", "Error"))
            .replace("{TITLE}", msg.get("TITLE", "Error"))
            .replace("{CODE}", msg.get("CODE", "XXX"))
            .replace("{SUBTITLE}", msg.get("SUBTITLE", "Wystąpił błąd."))
        )
    else:
        html = f"<html><head><title>{msg.get('TAB_TITLE', 'Error')}</title></head><body><h1>{msg.get('CODE', 'XXX')}</h1><p>{msg.get('TITLE', 'Error')}</p><p>{msg.get('SUBTITLE', '')}</p></body></html>"
    return status_code, html

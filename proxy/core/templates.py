import os
from pathlib import Path
from typing import Dict, Optional

from dotenv import load_dotenv
from core.logging import get_logger

load_dotenv()

LOGGER = get_logger("proxy.templates")

ERROR_TEMPLATE_PATH = Path(os.getenv("ERROR_TEMPLATE_PATH", "/home/ppowicz/proxy/sites/error.html"))
PASSWORD_TEMPLATE_PATH = Path(os.getenv("PASSWORD_TEMPLATE_PATH", "/home/ppowicz/proxy/sites/password.html"))
LOGIN_TEMPLATE_PATH = Path(os.getenv("LOGIN_TEMPLATE_PATH", "/home/ppowicz/proxy/sites/login.html"))
REGISTER_TEMPLATE_PATH = Path(os.getenv("REGISTER_TEMPLATE_PATH", "/home/ppowicz/proxy/sites/register.html"))
REGISTER_PENDING_TEMPLATE_PATH = Path(os.getenv("REGISTER_PENDING_TEMPLATE_PATH", "/home/ppowicz/proxy/sites/register_pending.html"))
USER_PANEL_TEMPLATE_PATH = Path(os.getenv("USER_PANEL_TEMPLATE_PATH", "/home/ppowicz/proxy/sites/user_panel.html"))
TWO_FA_SETUP_TEMPLATE_PATH = Path(os.getenv("TWO_FA_SETUP_TEMPLATE_PATH", "/home/ppowicz/proxy/sites/2fa_setup.html"))
TWO_FA_CHALLENGE_TEMPLATE_PATH = Path(os.getenv("TWO_FA_CHALLENGE_TEMPLATE_PATH", "/home/ppowicz/proxy/sites/2fa_challenge.html"))

ADMIN_PAGE_FILES = {
    "home": Path(os.getenv("ADMIN_TEMPLATE_HOME", "/home/ppowicz/proxy/sites/admin_home.html")),
    "db": Path(os.getenv("ADMIN_TEMPLATE_DB", "/home/ppowicz/proxy/sites/admin_db.html")),
    "logs": Path(os.getenv("ADMIN_TEMPLATE_LOGS", "/home/ppowicz/proxy/sites/admin_logs.html")),
    "users": Path(os.getenv("ADMIN_TEMPLATE_USERS", "/home/ppowicz/proxy/sites/admin_users.html")),
    "roles": Path(os.getenv("ADMIN_TEMPLATE_ROLES", "/home/ppowicz/proxy/sites/admin_roles.html")),
}

ADMIN_ROUTE_TO_TEMPLATE = {
    "/": "home",
    "": "home",
    "/db": "db",
    "/logs": "logs",
    "/users": "users",
    "/roles": "roles",
}


def _read_template(path: Path, *, default: Optional[str] = "") -> Optional[str]:
    if path.is_file():
        try:
            return path.read_text(encoding="utf-8")
        except Exception as exc:
            LOGGER.error("[TEMPLATES] Failed to read template %s: %s", path, exc)
    return default


def load_error_template() -> Optional[str]:
    return _read_template(ERROR_TEMPLATE_PATH, default=None)


def load_password_template() -> Optional[str]:
    return _read_template(PASSWORD_TEMPLATE_PATH, default=None)


def load_login_template() -> str:
    return _read_template(LOGIN_TEMPLATE_PATH, default="") or ""


def load_register_template() -> str:
    return _read_template(REGISTER_TEMPLATE_PATH, default="") or ""


def load_register_pending_template() -> str:
    return _read_template(REGISTER_PENDING_TEMPLATE_PATH, default="") or ""


def load_user_panel_template() -> str:
    return _read_template(USER_PANEL_TEMPLATE_PATH, default="") or ""


def load_admin_page_templates() -> Dict[str, str]:
    templates: Dict[str, str] = {}
    for key, path in ADMIN_PAGE_FILES.items():
        templates[key] = _read_template(path, default="") or ""
    return templates


def load_2fa_setup_template() -> str:
    return _read_template(TWO_FA_SETUP_TEMPLATE_PATH, default="") or ""


def load_2fa_challenge_template() -> str:
    return _read_template(TWO_FA_CHALLENGE_TEMPLATE_PATH, default="") or ""


ERROR_TEMPLATE = load_error_template()
PASSWORD_TEMPLATE = load_password_template()
LOGIN_TEMPLATE = load_login_template()
REGISTER_TEMPLATE = load_register_template()
REGISTER_PENDING_TEMPLATE = load_register_pending_template()
USER_PANEL_TEMPLATE = load_user_panel_template()
ADMIN_PAGE_TEMPLATES = load_admin_page_templates()
TWO_FA_SETUP_TEMPLATE = load_2fa_setup_template()
TWO_FA_CHALLENGE_TEMPLATE = load_2fa_challenge_template()

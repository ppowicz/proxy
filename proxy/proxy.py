#!/usr/bin/env python3
import base64
import hashlib
import hmac
import http.client
import json
import os
import secrets
import shutil
import ssl
import threading
import time
from collections import defaultdict, deque
from dataclasses import dataclass
from datetime import datetime, timedelta
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from socketserver import ThreadingMixIn
from typing import Any, Dict, Optional, Tuple
from urllib.parse import parse_qs

from dotenv import load_dotenv

from core.admin import (
    handle_admin_api as core_handle_admin_api,
    handle_admin_panel as core_handle_admin_panel,
)
from core.auth import (
    handle_login as core_handle_login,
    handle_logout as core_handle_logout,
    handle_register as core_handle_register,
    handle_user_panel as core_handle_user_panel,
)
from core.logging import get_logger
from core.templates import (
    ADMIN_PAGE_FILES,
    ADMIN_PAGE_TEMPLATES,
    ADMIN_ROUTE_TO_TEMPLATE,
    ERROR_TEMPLATE,
    ERROR_TEMPLATE_PATH,
    LOGIN_TEMPLATE,
    PASSWORD_TEMPLATE,
    PASSWORD_TEMPLATE_PATH,
    REGISTER_PENDING_TEMPLATE,
    REGISTER_TEMPLATE,
    TWO_FA_CHALLENGE_TEMPLATE,
    TWO_FA_CHALLENGE_TEMPLATE_PATH,
    TWO_FA_SETUP_TEMPLATE,
    TWO_FA_SETUP_TEMPLATE_PATH,
    USER_PANEL_TEMPLATE,
)
from core.twofa import (
    handle_2fa_challenge as core_handle_2fa_challenge,
    handle_2fa_setup as core_handle_2fa_setup,
    handle_skip_2fa_setup as core_handle_skip_2fa_setup,
)

from db import (
    get_user_by_id, get_user_by_username, get_session, update_session_activity,
    verify_password, create_session, user_has_permission,
    get_all_users, get_all_sessions, get_all_roles, get_all_permissions,
    get_user_roles, expire_session, DBConnection, user_is_admin,
    assign_role_to_user, deassign_role_from_user,
    insert_http_log, get_recent_http_logs, get_table_columns, get_table_rows, update_table_row,
    create_role, update_role, delete_role, create_permission, assign_permission_to_role,
    deassign_permission_from_role, get_role_permissions, update_user, bulk_assign_roles_to_user,
    delete_user,
    create_user, has_totp_enabled, update_session_2fa_state, create_totp_secret, verify_and_enable_totp,
    verify_totp_code, disable_totp, get_session_2fa_state, cleanup_http_logs_older_than,
    get_http_log_summary, get_http_log_status_breakdown, get_http_log_timeline,
    get_top_http_subdomains, get_top_http_paths, get_recent_http_errors, delete_http_logs
)

load_dotenv()

# ====== CONFIG ======

ROOT_DOMAIN = os.getenv("ROOT_DOMAIN", "ppowicz.pl")
PROJECTS_ROOT = Path(os.getenv("PROJECTS_ROOT", "/home/ppowicz/projects"))
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

PROCESS_START_TIME = time.time()
LOGGER = get_logger("proxy")


def log_event(message: str, level: str = "info", console: bool = False, exc_info=False):
    log_func = getattr(LOGGER, level.lower(), LOGGER.info)
    log_func(message, exc_info=exc_info if exc_info else None)
    if console:
        print(message)


def log_operational(message: str):
    log_event(message, level="info", console=True)


def log_error(message: str, exc_info=False):
    log_event(message, level="error", console=True, exc_info=exc_info)


def _parse_log_timestamp(line: str) -> Optional[datetime]:
    timestamp_str = line[:23]
    try:
        return datetime.strptime(timestamp_str, "%Y-%m-%d %H:%M:%S,%f")
    except ValueError:
        return None


def cleanup_log_file(retention_days: int) -> int:
    if retention_days <= 0 or not LOG_FILE_PATH.is_file():
        return 0

    cutoff = datetime.now() - timedelta(days=retention_days)
    temp_path = LOG_FILE_PATH.with_suffix(".tmp")
    removed = 0
    try:
        with LOG_FILE_PATH.open("r", encoding="utf-8") as src, temp_path.open("w", encoding="utf-8") as dst:
            for line in src:
                timestamp = _parse_log_timestamp(line)
                if timestamp and timestamp < cutoff:
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

# HTTPS bind:
BIND_HOST = "0.0.0.0"
BIND_PORT = 443

# certy Let's Encrypt
CERT_FILE = "/etc/letsencrypt/live/ppowicz.pl/fullchain.pem"
KEY_FILE = "/etc/letsencrypt/live/ppowicz.pl/privkey.pem"

SCAN_INTERVAL_SECONDS = 5.0  # co ile sekund odświeżać konfigurację

# ====== ERROR MESSAGES ======

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


def _b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode().rstrip("=")


def _b64url_decode(data: str) -> bytes:
    padding = "=" * (-len(data) % 4)
    return base64.urlsafe_b64decode(data + padding)


def _now() -> int:
    return int(time.time())


def _host_is_allowed(host: str) -> bool:
    if not host:
        return False
    host = host.lower()
    for suffix in ALLOWED_HOST_SUFFIXES or [ROOT_DOMAIN]:
        suffix = suffix.lstrip(".")
        if host == suffix or host.endswith(f".{suffix}"):
            return True
    return False


def _project_password_fingerprint(password: Optional[str]) -> str:
    if not password:
        return ""
    return hashlib.sha256(password.encode()).hexdigest()


def _sign_proxy_payload(payload: bytes) -> bytes:
    if not PROXY_AUTH_TOKEN_KEY:
        raise ValueError("Missing PROXY_AUTH_TOKEN_KEY")
    return hmac.new(PROXY_AUTH_TOKEN_KEY, payload, hashlib.sha256).digest()


def build_proxy_auth_token(proj: 'ProjectConfig') -> Optional[str]:
    if not PROXY_AUTH_TOKEN_KEY or not proj.password:
        return None
    payload_obj = {
        "subdomain": proj.subdomain,
        "pwd": _project_password_fingerprint(proj.password),
        "ts": _now(),
    }
    payload = json.dumps(payload_obj, separators=(",", ":"), sort_keys=True).encode()
    signature = _sign_proxy_payload(payload)
    return f"{_b64url_encode(payload)}.{_b64url_encode(signature)}"


def verify_proxy_auth_token(token: str, proj: 'ProjectConfig') -> bool:
    if not token or not PROXY_AUTH_TOKEN_KEY or not proj.password:
        return False
    try:
        payload_b64, signature_b64 = token.split(".", 1)
        payload = _b64url_decode(payload_b64)
        expected_sig = _sign_proxy_payload(payload)
        provided_sig = _b64url_decode(signature_b64)
    except Exception:
        return False
    if not hmac.compare_digest(expected_sig, provided_sig):
        return False
    try:
        payload_obj = json.loads(payload)
    except Exception:
        return False
    if payload_obj.get("subdomain") != proj.subdomain:
        return False
    if payload_obj.get("pwd") != _project_password_fingerprint(proj.password):
        return False
    issued_at = int(payload_obj.get("ts") or 0)
    if issued_at <= 0 or (_now() - issued_at) > PROXY_AUTH_COOKIE_TTL:
        return False
    return True


def sanitize_headers(headers: Dict[str, str]) -> Dict[str, str]:
    sanitized = {}
    for key, value in headers.items():
        sanitized[key] = "<redacted>" if key.lower() in SENSITIVE_REQUEST_HEADERS else value
    return sanitized


def sanitize_cookies(cookies: Dict[str, str]) -> Dict[str, str]:
    return {name: "<redacted>" for name in cookies.keys()}


def prepare_body_for_logging(raw_body: bytes, content_type: str) -> Tuple[str, bool, bool]:
    if not raw_body:
        return "", False, False
    try:
        decoded = raw_body.decode("utf-8", errors="replace")
    except Exception:
        decoded = repr(raw_body)
    lowered_ct = (content_type or "").lower()
    if any(marker in lowered_ct for marker in ("application/json", "application/x-www-form-urlencoded", "multipart/form-data")):
        return "[REDACTED]", False, True
    if any(keyword in decoded.lower() for keyword in SENSITIVE_BODY_KEYWORDS):
        return "[REDACTED]", False, True
    truncated = False
    if HTTP_BODY_LOG_BYTES and len(decoded) > HTTP_BODY_LOG_BYTES:
        decoded = decoded[:HTTP_BODY_LOG_BYTES]
        truncated = True
    return decoded, truncated, False


class RateLimiter:
    def __init__(self):
        self._hits: Dict[str, deque] = defaultdict(deque)
        self._lock = threading.Lock()

    def hit(self, bucket: str, key: str, limit: int, window_seconds: int) -> bool:
        if limit <= 0 or window_seconds <= 0:
            return True
        now = time.time()
        composite = f"{bucket}:{key}"
        with self._lock:
            dq = self._hits[composite]
            while dq and dq[0] <= now - window_seconds:
                dq.popleft()
            dq.append(now)
            return len(dq) <= limit


RATE_LIMITER = RateLimiter()


def _read_meminfo() -> Dict[str, int]:
    info: Dict[str, int] = {}
    try:
        with open("/proc/meminfo", "r", encoding="utf-8") as fh:
            for line in fh:
                if ":" not in line:
                    continue
                key, raw_value = line.split(":", 1)
                value = raw_value.strip().split(" ")[0]
                try:
                    info[key] = int(value)
                except ValueError:
                    continue
    except (FileNotFoundError, PermissionError):
        return {}
    return info


def _get_system_resource_snapshot() -> Dict[str, Any]:
    cpu_percent = None
    load_averages = None
    try:
        load_averages = os.getloadavg()
        cpu_count = os.cpu_count() or 1
        cpu_percent = min(100.0, max(0.0, (load_averages[0] / cpu_count) * 100.0))
    except (AttributeError, OSError):
        pass

    mem_info = _read_meminfo()
    mem_total = mem_info.get("MemTotal")
    mem_available = mem_info.get("MemAvailable")
    mem_used = None
    mem_percent = None
    if mem_total and mem_available is not None:
        mem_used = max(mem_total - mem_available, 0)
        mem_percent = float(mem_used) / float(mem_total) * 100.0 if mem_total else None

    try:
        disk_path = PROJECTS_ROOT if PROJECTS_ROOT.exists() else PROJECTS_ROOT.parent
        if not str(disk_path):
            disk_path = Path("/")
        disk_usage = shutil.disk_usage(str(disk_path))
        disk_percent = (disk_usage.used / disk_usage.total) * 100.0 if disk_usage.total else None
        disk_total = disk_usage.total
        disk_used = disk_usage.used
    except Exception:
        disk_percent = disk_total = disk_used = None

    return {
        "cpu_percent": cpu_percent,
        "load_averages": load_averages,
        "memory_total_kb": mem_total,
        "memory_used_kb": mem_used,
        "memory_percent": mem_percent,
        "disk_total_bytes": disk_total,
        "disk_used_bytes": disk_used,
        "disk_percent": disk_percent,
    }


def _check_db_health(timeout_seconds: float = 2.0) -> bool:
    conn = None
    try:
        conn = DBConnection.get_connection()
        if not conn:
            return False
        with conn:
            with conn.cursor() as cur:
                cur.execute("SELECT 1")
        return True
    except Exception:
        return False
    finally:
        if conn:
            try:
                conn.close()
            except Exception:
                pass


def _get_dashboard_metrics() -> Dict[str, Any]:
    system = _get_system_resource_snapshot()
    summary_hour = get_http_log_summary(60) or {}
    summary_five = get_http_log_summary(5) or {}
    window_five = max(1, summary_five.get("window_minutes", 5) or 5)
    per_minute = (summary_five.get("total_requests", 0) or 0) / window_five

    return {
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "system": {
            "cpu_percent": system.get("cpu_percent"),
            "load": system.get("load_averages"),
            "memory_percent": system.get("memory_percent"),
            "memory_total_kb": system.get("memory_total_kb"),
            "memory_used_kb": system.get("memory_used_kb"),
            "disk_percent": system.get("disk_percent"),
            "disk_total_bytes": system.get("disk_total_bytes"),
            "disk_used_bytes": system.get("disk_used_bytes"),
            "uptime_seconds": int(time.time() - PROCESS_START_TIME),
        },
        "services": {
            "db": _check_db_health(),
            "proxy": True,
            "projects_loaded": len(PROJECTS),
            "projects_broken": len(BROKEN_PROJECTS),
            "threads": threading.active_count(),
        },
        "requests": {
            "per_hour": summary_hour.get("total_requests", 0) or 0,
            "per_minute": per_minute,
            "unique_clients": summary_hour.get("unique_clients", 0) or 0,
            "error_rate": summary_hour.get("error_rate", 0.0) or 0.0,
            "avg_backend_ms": summary_hour.get("avg_backend_ms", 0.0) or 0.0,
        },
    }

# ====== GLOBAL STATE ======

@dataclass
class ProjectConfig:
    folder: Path
    subdomain: str
    port: int
    password: Optional[str]
    permission: Optional[str]
    error: Optional[str] = None


PROJECTS: Dict[str, ProjectConfig] = {}
BROKEN_PROJECTS: Dict[str, str] = {}
LAST_SCAN: float = 0.0
LAST_LOG_CLEANUP: float = 0.0

def render_error_page(key: str) -> Tuple[int, str]:
    msg = ERROR_MESSAGES.get(key) or ERROR_MESSAGES["500"]
    status_code = int(key) if key.isdigit() else 500

    # Use template if loaded, otherwise use inline default
    if ERROR_TEMPLATE:
        html = (
            ERROR_TEMPLATE
            .replace("{TAB_TITLE}", msg.get("TAB_TITLE", "Error"))
            .replace("{TITLE}", msg.get("TITLE", "Error"))
            .replace("{CODE}", msg.get("CODE", "XXX"))
            .replace("{SUBTITLE}", msg.get("SUBTITLE", "Wystąpił błąd."))
        )
    else:
        # Inline default error page
        html = f"<html><head><title>{msg.get('TAB_TITLE', 'Error')}</title></head><body><h1>{msg.get('CODE', 'XXX')}</h1><p>{msg.get('TITLE', 'Error')}</p><p>{msg.get('SUBTITLE', '')}</p></body></html>"
    
    return status_code, html

# ====== CONFIG SCANNING ======

def load_projects():
    global PROJECTS, BROKEN_PROJECTS, LAST_SCAN

    new_projects: Dict[str, ProjectConfig] = {}
    new_broken: Dict[str, str] = {}

    if not PROJECTS_ROOT.is_dir():
        PROJECTS = {}
        BROKEN_PROJECTS = {}
        LAST_SCAN = time.time()
        return

    for item in PROJECTS_ROOT.iterdir():
        if not item.is_dir():
            continue

        cfg_path = item / "proxy-config.json"
        if not cfg_path.is_file():
            continue

        try:
            text = cfg_path.read_text(encoding="utf-8")
            data = json.loads(text)
        except Exception as e:
            log_error(f"[CONFIG] Failed to load JSON for {cfg_path}: {e}")
            continue

        subdomain = data.get("subdomain")
        port_raw = data.get("port")
        password = data.get("password")
        permission = data.get("permission")

        error_msg = None
        if not isinstance(subdomain, str) or not subdomain:
            error_msg = "Missing or invalid 'subdomain' in config."
        try:
            port = int(port_raw)
            if not (1 <= port <= 65535):
                raise ValueError("Port out of range")
        except Exception:
            error_msg = error_msg or "Missing or invalid 'port' in config."
            port = 0

        if subdomain in new_projects or subdomain in new_broken:
            error_msg = (error_msg or "") + " Duplicate subdomain."

        if error_msg:
            if isinstance(subdomain, str) and subdomain:
                new_broken[subdomain] = error_msg
                log_error(f"[CONFIG] Broken config for subdomain '{subdomain}': {error_msg}")
            else:
                log_error(f"[CONFIG] Config error in {cfg_path}: {error_msg}")
            continue

        proj = ProjectConfig(
            folder=item,
            subdomain=subdomain,
            port=port,
            password=password if password not in (None, "") else None,
            permission=permission,
            error=None,
        )
        new_projects[subdomain] = proj

    PROJECTS = new_projects
    BROKEN_PROJECTS = new_broken
    LAST_SCAN = time.time()
    log_operational(f"[CONFIG] Projects reloaded: {list(PROJECTS.keys())}, broken: {list(BROKEN_PROJECTS.keys())}")


def maybe_reload_projects():
    global LAST_SCAN
    now = time.time()
    if now - LAST_SCAN < SCAN_INTERVAL_SECONDS:
        return
    try:
        load_projects()
    except Exception:
        LAST_SCAN = now
        log_error("[CONFIG] Exception while reloading projects", exc_info=True)


def maybe_cleanup_logs():
    global LAST_LOG_CLEANUP
    now = time.time()
    if now - LAST_LOG_CLEANUP < LOG_CLEANUP_INTERVAL_SECONDS:
        return

    LAST_LOG_CLEANUP = now

    cleanup_log_file(LOG_RETENTION_DAYS)

    removed_rows = 0
    try:
        removed_rows = cleanup_http_logs_older_than(LOG_RETENTION_DAYS)
    except Exception as exc:
        log_error(f"[LOG ROTATE] Failed to cleanup database http_logs: {exc}")
    else:
        if removed_rows:
            log_event(
                f"[LOG ROTATE] Removed {removed_rows} http_log rows older than {LOG_RETENTION_DAYS} days",
                console=False,
            )

# ====== PROXY SERVER ======

class ThreadedHTTPServer(ThreadingMixIn, HTTPServer):
    daemon_threads = True


class ProxyHandler(BaseHTTPRequestHandler):
    server_version = "PythonProxy/0.1"

    def log_message(self, format, *args):
        return

    def send_error_page(self, key: str, *, log_request: bool = True, error_message: Optional[str] = None):
        status_code, html = render_error_page(key)
        log_error(f"[HTTP] {status_code} response for {self.command} {self.path}")
        err_text = None
        if log_request:
            msg = ERROR_MESSAGES.get(key) or {}
            err_text = error_message or msg.get("TITLE") or "Error"
        self._send_html_response(
            status_code,
            html,
            log_request=log_request,
            is_error=True,
            error_message=err_text,
        )

    def get_subdomain(self) -> Optional[str]:
        host = self.headers.get("Host", "")
        if not host:
            return None
        host = host.split(":", 1)[0].strip().lower()
        if not _host_is_allowed(host):
            return None

        if host == ROOT_DOMAIN:
            return ROOT_DOMAIN.split(".")[0]

        parts = host.split(".")
        if len(parts) > len(ROOT_DOMAIN.split(".")):
            return parts[0]
        return None

    def check_password(self, expected_password: str) -> bool:
        auth_header = self.headers.get("Authorization")
        if not auth_header or not auth_header.startswith("Basic "):
            return False
        try:
            encoded = auth_header.split(" ", 1)[1].strip()
            decoded = base64.b64decode(encoded).decode("utf-8")
            _, _, password = decoded.partition(":")
            return password == expected_password
        except Exception:
            return False

    def get_cookie_value(self, name: str) -> Optional[str]:
        cookie = self.headers.get("Cookie")
        if not cookie:
            return None
        parts = [p.strip() for p in cookie.split(";")]
        for p in parts:
            if "=" in p:
                k, v = p.split("=", 1)
                if k.strip() == name:
                    return v
        return None

    def _format_cookie(self, name: str, value: str, *, max_age: Optional[int] = None,
                        http_only: bool = True, same_site: str = "Lax") -> str:
        parts = [f"{name}={value}", "Path=/"]
        if SESSION_COOKIE_DOMAIN:
            parts.append(f"Domain={SESSION_COOKIE_DOMAIN}")
        if max_age is not None:
            parts.append(f"Max-Age={int(max_age)}")
        parts.append("Secure")
        if http_only:
            parts.append("HttpOnly")
        if same_site:
            parts.append(f"SameSite={same_site}")
        return "; ".join(parts)

    def _set_cookie(self, name: str, value: str, **kwargs):
        self.send_header("Set-Cookie", self._format_cookie(name, value, **kwargs))

    def _clear_cookie(self, name: str):
        self._set_cookie(name, "", max_age=0)

    def _get_pending_or_active_session_id(self) -> Optional[str]:
        return self.get_cookie_value("session_id") or self.get_cookie_value("pending_session")

    def _promote_session(self, session_id: Optional[str]):
        if not session_id:
            return
        self._set_cookie("session_id", session_id)
        self._clear_cookie("pending_session")

    def _send_rate_limited(self, message: str):
        html = f"<html><head><title>Too Many Attempts</title></head><body><h1>429 Too Many Requests</h1><p>{message}</p></body></html>"
        self._send_html_response(429, html, error_message=message)

    def _check_rate_limit(self, bucket: str, key: str, limit: int, window_seconds: int, message: str) -> bool:
        if limit <= 0 or window_seconds <= 0:
            return True
        allowed = RATE_LIMITER.hit(bucket, key, limit, window_seconds)
        if not allowed:
            self._send_rate_limited(message)
        return allowed

    def verify_proxy_cookie(self, proj: ProjectConfig) -> bool:
        token = self.get_cookie_value("proxy_auth")
        if not token:
            return False
        if verify_proxy_auth_token(token, proj):
            return True
        # Legacy cookie fallback for existing sessions
        try:
            decoded = base64.b64decode(token).decode("utf-8")
            expect = f"{proj.subdomain}:{proj.password}"
            return decoded == expect
        except Exception:
            return False

    def get_session_user(self) -> Optional[Dict]:
        """Get logged-in user from session cookie. Returns user dict or None."""
        if hasattr(self, "_cached_session_user"):
            return self._cached_session_user

        session_id = self.get_cookie_value("session_id")
        if not session_id:
            return None
        
        session = get_session(session_id)
        if not session:
            return None
        
        extra = session.get('extra_data') or {}
        if not extra.get('2fa_verified'):
            return None

        update_session_activity(session_id)
        user = get_user_by_id(session['user_id'])
        self._cached_session_user = user
        return user

    def _parse_request_cookies(self) -> Dict[str, str]:
        cookies = {}
        cookie_header = self.headers.get("Cookie")
        if cookie_header:
            for part in [p.strip() for p in cookie_header.split(";") if p.strip()]:
                if "=" in part:
                    k, v = part.split("=", 1)
                    cookies[k.strip()] = v.strip()
        return cookies

    def _set_request_body(self, text: str, truncated: bool = False):
        self._raw_request_body = text or ""
        self._raw_request_body_truncated = bool(truncated)

    def _get_base_log_record(self) -> Dict:
        cached = getattr(self, "_base_log_record", None)
        if cached:
            return cached.copy()
        request_headers = sanitize_headers({k: v for k, v in self.headers.items()})
        cookies = sanitize_cookies(self._parse_request_cookies())
        host = self.headers.get("Host")
        subdomain = self.get_subdomain()
        domain = None
        if host:
            host_without_port = host.split(":", 1)[0]
            parts = host_without_port.split(".")
            domain = ".".join(parts[-2:]) if len(parts) >= 2 else host_without_port
        path = self.path.split("?", 1)[0]
        query = self.path.split("?", 1)[1] if "?" in self.path else ""
        session_id = self.get_cookie_value("session_id")
        user = self.get_session_user()
        request_body = getattr(self, "_raw_request_body", "")
        request_body_truncated = getattr(self, "_raw_request_body_truncated", False)

        record = {
            'client_ip': self.client_address[0],
            'client_port': self.client_address[1] if len(self.client_address) > 1 else None,
            'user_agent': self.headers.get('User-Agent'),
            'referer': self.headers.get('Referer'),
            'host': host,
            'subdomain': subdomain,
            'domain': domain,
            'server_port': BIND_PORT,
            'method': self.command,
            'scheme': 'https',
            'path': path,
            'query_string': query,
            'full_url': f"https://{host}{self.path}" if host else None,
            'http_version': getattr(self, 'request_version', 'HTTP/1.1'),
                'request_headers': request_headers,
                'request_cookies': cookies,
                'request_body': request_body,
                'request_body_truncated': request_body_truncated,
            'response_status': None,
            'response_bytes': 0,
            'response_headers': None,
            'backend_host': None,
            'backend_port': None,
            'backend_path': None,
            'backend_duration_ms': None,
            'is_authenticated': bool(user),
            'auth_user_id': user['id'] if user else None,
            'auth_username': user['username'] if user else None,
            'session_id': session_id,
            'is_error': False,
            'error_message': None,
        }

        self._base_log_record = record
        return record.copy()

    def _log_request_event(self, **overrides):
        force = overrides.pop('force', False)
        if getattr(self, '_log_record_written', False) and not force:
            return

        record = self._get_base_log_record()
        record.update({k: v for k, v in overrides.items() if v is not None or k in ('response_status', 'response_bytes', 'is_error', 'request_body', 'request_body_truncated', 'backend_duration_ms', 'backend_host', 'backend_port', 'backend_path', 'response_headers', 'error_message')})

        if record.get('response_status') is None:
            record['response_status'] = 0

        if 'is_error' not in overrides:
            status = record.get('response_status') or 0
            record['is_error'] = bool(status >= 400)

        record.setdefault('response_bytes', 0)

        try:
            insert_http_log(record)
            self._log_record_written = True
        except Exception as log_err:
            log_error(f"[LOG] Failed to write request log: {log_err}", exc_info=True)

    def _log_simple_response(self, status: int, body_length: int = 0, *, is_error: bool = False, error_message: Optional[str] = None):
        self._log_request_event(
            response_status=status,
            response_bytes=body_length,
            is_error=is_error or status >= 400,
            error_message=error_message
        )

    def _send_html_response(
        self,
        status: int,
        html: str,
        *,
        content_type: str = "text/html; charset=utf-8",
        headers: Optional[Dict[str, str]] = None,
        log_request: bool = True,
        is_error: Optional[bool] = None,
        error_message: Optional[str] = None,
    ) -> None:
        """Write HTML content with common headers and optional logging."""
        body = html.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        if headers:
            for key, value in headers.items():
                self.send_header(key, value)
        self.end_headers()
        self.wfile.write(body)
        if log_request:
            effective_error = is_error if is_error is not None else status >= 400
            self._log_simple_response(status, len(body), is_error=effective_error, error_message=error_message)

    def send_password_page(self, message: str = ""):
        if not PASSWORD_TEMPLATE:
            # Password template not found, show 404
            self.send_error_page("404")
            return
        
        html = (
            PASSWORD_TEMPLATE
            .replace("{TAB_TITLE}", "Wprowadź hasło")
            .replace("{MESSAGE}", message or "")
        )
        self._send_html_response(
            200,
            html,
            is_error=bool(message),
            error_message=message or None,
        )

    def handle_proxy(self):
        try:
            self._log_record_written = False
            self._base_log_record = None
            self._raw_request_body = ""
            self._raw_request_body_truncated = False
            if hasattr(self, '_cached_session_user'):
                delattr(self, '_cached_session_user')

            maybe_cleanup_logs()
            maybe_reload_projects()

            # Record request start time for backend timing/logging
            request_start_ts = time.time()
            subdomain = self.get_subdomain()
            if not subdomain:
                self.send_error_page("404")
                return

            # Obsługuj specjalne trasy na ppowicz.pl
            if subdomain == "ppowicz":
                if self.path == "/login" or self.path.startswith("/login?"):
                    core_handle_login(
                        self,
                        login_rate_limit_per_ip=LOGIN_RATE_LIMIT_PER_IP,
                        login_rate_limit_per_user=LOGIN_RATE_LIMIT_PER_USER,
                        login_rate_limit_window_seconds=LOGIN_RATE_LIMIT_WINDOW_SECONDS,
                        pending_session_max_age=PENDING_SESSION_MAX_AGE,
                    )
                    return
                elif self.path == "/register" or self.path.startswith("/register?"):
                    core_handle_register(
                        self,
                        register_rate_limit_per_ip=REGISTER_RATE_LIMIT_PER_IP,
                        register_rate_limit_window_seconds=REGISTER_RATE_LIMIT_WINDOW_SECONDS,
                    )
                    return
                elif self.path == "/login/setup-2fa" or self.path.startswith("/login/setup-2fa?"):
                    core_handle_2fa_setup(
                        self,
                        rate_limit_per_session=TWO_FA_RATE_LIMIT_PER_SESSION,
                        rate_limit_window_seconds=TWO_FA_RATE_LIMIT_WINDOW_SECONDS,
                    )
                    return
                elif self.path == "/login/2fa" or self.path.startswith("/login/2fa?"):
                    core_handle_2fa_challenge(self)
                    return
                elif self.path == "/login/skip-2fa-setup" or self.path.startswith("/login/skip-2fa-setup?"):
                    core_handle_skip_2fa_setup(self)
                    return
                elif self.path == "/panel" or self.path.startswith("/panel?"):
                    core_handle_user_panel(self, PROJECTS)
                    return
                elif self.path == "/logout" or self.path.startswith("/logout?"):
                    core_handle_logout(self)
                    return

            # Obsługuj admin panel
            if subdomain == "admin":
                # Admin API routes under /api/ should be handled separately
                if self.path.startswith("/api/"):
                    self.handle_admin_api()
                    return
                self.handle_admin_panel()
                return

            # Obsługuj zwykłe projekty
            if subdomain in BROKEN_PROJECTS:
                self.send_error_page("bad_config")
                return

            proj = PROJECTS.get(subdomain)
            if not proj:
                self.send_error_page("404")
                return

            # Priority 1: Check permission (if set)
            if proj.permission:
                user = self.get_session_user()
                if not user:
                    # User not logged in, require login
                    next_param = f"next=https://{self.headers.get('Host')}{self.path}"
                    self.send_response(302)
                    self.send_header("Location", f"https://ppowicz.pl/login?{next_param}")
                    self.end_headers()
                    return
                
                # User is logged in, check if they have the required permission
                if not user_has_permission(user['id'], proj.permission):
                    # User doesn't have required permission
                    self.send_error_page("401")
                    return

            # Priority 2: Check password (if set)
            if proj.password:
                if not self.verify_proxy_cookie(proj):
                    # Handle POST from password form
                    if self.command == "POST":
                        content_length = int(self.headers.get("Content-Length", "0") or "0")
                        body = self.rfile.read(content_length) if content_length > 0 else b""
                        submitted = ""
                        try:
                            data = parse_qs(body.decode("utf-8", errors="ignore"))
                            submitted = data.get("password", [""])[0]
                        except Exception:
                            submitted = ""

                        if submitted == proj.password:
                            token = build_proxy_auth_token(proj)
                            if token:
                                cookie_value = token
                            else:
                                cookie_value = base64.b64encode(f"{proj.subdomain}:{proj.password}".encode()).decode()
                            # Set cookie and redirect (303) back
                            self.send_response(303)
                            self.send_header("Location", self.path)
                            self._set_cookie("proxy_auth", cookie_value, same_site="Strict")
                            self.end_headers()
                            return
                        else:
                            self.send_password_page("Nieprawidłowe hasło")
                            return
                    else:
                        # Show password form
                        self.send_password_page()
                        return

            # Read request body (if any) once, and prepare forwarded headers
            content_length = int(self.headers.get("Content-Length", "0") or "0")
            raw_body = self.rfile.read(content_length) if content_length > 0 else b""

            # Prepare request metadata for logging (in sanitized form)
            request_headers = sanitize_headers({k: v for k, v in self.headers.items()})
            cookies = sanitize_cookies(self._parse_request_cookies())

            body_text, body_truncated, _ = prepare_body_for_logging(raw_body, self.headers.get("Content-Type", ""))
            self._set_request_body(body_text, body_truncated)

            forward_headers = {}
            for k, v in self.headers.items():
                kl = k.lower()
                if kl in ("host", "connection", "proxy-connection", "keep-alive", "upgrade"):
                    continue
                forward_headers[k] = v

            forward_headers["Host"] = f"127.0.0.1:{proj.port}"
            client_ip = self.client_address[0]
            client_port = self.client_address[1] if len(self.client_address) > 1 else None
            existing_xff = self.headers.get("X-Forwarded-For")
            xff = f"{existing_xff}, {client_ip}" if existing_xff else client_ip
            forward_headers["X-Forwarded-For"] = xff
            forward_headers["X-Forwarded-Proto"] = "https"

            # Auth/session info
            session_id = self.get_cookie_value("session_id")
            user = self.get_session_user()
            # Authenticated if: user logged in OR (password protected and cookie valid)
            is_authenticated = bool(user) or (proj.password and self.verify_proxy_cookie(proj))
            auth_user_id = user['id'] if user else None
            auth_username = user['username'] if user else None

            conn = http.client.HTTPConnection("127.0.0.1", proj.port, timeout=10)
            try:
                backend_start = time.time()
                conn.request(self.command, self.path, body=raw_body if raw_body else None, headers=forward_headers)
                resp = conn.getresponse()
                response_body = resp.read()
                backend_end = time.time()
                backend_duration_ms = int((backend_end - backend_start) * 1000)
            except Exception as e:
                log_error(f"[BACKEND] Error for {subdomain}: {e}")
                # Log the backend failure
                try:
                    record = {
                        'client_ip': client_ip,
                        'client_port': client_port,
                        'user_agent': self.headers.get('User-Agent'),
                        'referer': self.headers.get('Referer'),
                        'host': self.headers.get('Host'),
                        'subdomain': subdomain,
                        'domain': '.'.join((self.headers.get('Host') or '').split('.')[-2:]) if self.headers.get('Host') else None,
                        'server_port': BIND_PORT,
                        'method': self.command,
                        'scheme': 'https',
                        'path': self.path.split('?')[0],
                        'query_string': self.path.split('?', 1)[1] if '?' in self.path else '',
                        'full_url': f"https://{self.headers.get('Host')}{self.path}",
                        'http_version': getattr(self, 'request_version', 'HTTP/1.1'),
                        'request_headers': request_headers,
                        'request_cookies': cookies,
                        'request_body': body_text,
                        'request_body_truncated': body_truncated,
                        'response_status': None,
                        'response_bytes': 0,
                        'response_headers': None,
                        'backend_host': '127.0.0.1',
                        'backend_port': proj.port,
                        'backend_path': self.path,
                        'backend_duration_ms': None,
                        'is_authenticated': is_authenticated,
                        'auth_user_id': auth_user_id,
                        'auth_username': auth_username,
                        'session_id': session_id,
                        'is_error': True,
                        'error_message': str(e),
                    }
                    try:
                        self._log_request_event(**record)
                    except Exception as log_err:
                        log_error(f"[LOG] Failed to insert backend error log: {log_err}", exc_info=True)
                except Exception:
                    pass

                self.send_error_page("502")
                return
            finally:
                conn.close()

            # Build and send response to client, and log the transaction
            try:
                # Prepare response headers and body
                status = resp.status
                reason = resp.reason
                # If slave returned error, render via template when available
                if status >= 400:
                    status_code = str(status)
                    if status_code in ERROR_MESSAGES:
                        self.send_error_page(status_code)
                    else:
                        # Build fallback HTML using template or simple fallback
                        body_text = ERROR_TEMPLATE
                        if "{TAB_TITLE}" in body_text:
                            html = (
                                ERROR_TEMPLATE
                                .replace("{TAB_TITLE}", f"{status} Error")
                                .replace("{TITLE}", str(status))
                                .replace("{CODE}", str(status))
                                .replace("{SUBTITLE}", reason or "")
                            )
                        else:
                            html = f"<html><body><h1>{status}</h1><p>{reason}</p></body></html>"
                        self._send_html_response(status, html, error_message=reason or str(status))
                else:
                    # Forward successful response
                    self.send_response(status, reason)
                    for k, v in resp.getheaders():
                        kl = k.lower()
                        if kl in ("transfer-encoding", "connection", "keep-alive", "proxy-connection"):
                            continue
                        self.send_header(k, v)
                    self.end_headers()
                    if response_body:
                        self.wfile.write(response_body)

                # Prepare log record
                response_headers = {k: v for k, v in resp.getheaders()}
                response_bytes = len(response_body) if response_body else 0
                record = {
                    'client_ip': client_ip,
                    'client_port': client_port,
                    'user_agent': self.headers.get('User-Agent'),
                    'referer': self.headers.get('Referer'),
                    'host': self.headers.get('Host'),
                    'subdomain': subdomain,
                    'domain': '.'.join((self.headers.get('Host') or '').split('.')[-2:]) if self.headers.get('Host') else None,
                    'server_port': BIND_PORT,
                    'method': self.command,
                    'scheme': 'https',
                    'path': self.path.split('?')[0],
                    'query_string': self.path.split('?', 1)[1] if '?' in self.path else '',
                    'full_url': f"https://{self.headers.get('Host')}{self.path}",
                    'http_version': getattr(self, 'request_version', 'HTTP/1.1'),
                    'request_headers': request_headers,
                    'request_cookies': cookies,
                    'request_body': body_text,
                    'request_body_truncated': body_truncated,
                    'response_status': status,
                    'response_bytes': response_bytes,
                    'response_headers': response_headers,
                    'backend_host': '127.0.0.1',
                    'backend_port': proj.port,
                    'backend_path': self.path,
                    'backend_duration_ms': backend_duration_ms,
                    'is_authenticated': is_authenticated,
                    'auth_user_id': auth_user_id,
                    'auth_username': auth_username,
                    'session_id': session_id,
                    'is_error': status >= 400,
                    'error_message': reason if status >= 400 else None,
                }
                try:
                    self._log_request_event(**record)
                except Exception as log_err:
                    log_error(f"[LOG] Failed to insert http_log: {log_err}", exc_info=True)
            except Exception:
                # If anything goes wrong while sending response, log and return 500
                log_error("[HTTP] Exception while returning response", exc_info=True)
                try:
                    self.send_error_page("500")
                except Exception:
                    pass

        except Exception:
            log_error("[PROXY] Unhandled exception in proxy handler", exc_info=True)
            try:
                self.send_error_page("500")
            except Exception:
                try:
                    self.send_response(500)
                    self.send_header("Content-Type", "text/plain; charset=utf-8")
                    self.end_headers()
                    self.wfile.write(b"Internal server error.")
                except Exception:
                    pass

    def handle_admin_panel(self):
        """Handle admin panel at admin.ppowicz.pl."""
        core_handle_admin_panel(self)
    
    def send_json(self, obj, status: int = 200):
        """Send JSON response."""
        try:
            body = json.dumps(obj, default=str).encode('utf-8')
        except Exception:
            body = json.dumps({'error': 'serialization error'}).encode('utf-8')
        self.send_response(status)
        self.send_header('Content-Type', 'application/json; charset=utf-8')
        self.send_header('Content-Length', str(len(body)))
        self.end_headers()
        self.wfile.write(body)
        error_text = None
        if status >= 400:
            if isinstance(obj, dict):
                error_text = obj.get('error') or obj.get('message') or str(obj)
            else:
                error_text = str(obj)
        self._log_simple_response(status, len(body), is_error=status >= 400, error_message=error_text)

    def handle_admin_api(self):
        """Handle admin JSON API under /api/..."""
        core_handle_admin_api(
            self,
            log_error=log_error,
            get_dashboard_metrics=_get_dashboard_metrics,
            projects=PROJECTS,
        )

    def do_GET(self):
        self.handle_proxy()

    def do_POST(self):
        self.handle_proxy()

    def do_PUT(self):
        self.handle_proxy()

    def do_DELETE(self):
        self.handle_proxy()

    def do_HEAD(self):
        self.handle_proxy()

    def do_OPTIONS(self):
        self.handle_proxy()


def run():
    log_operational("\n" + "="*60)
    log_operational("[STARTUP] Proxy server initialization")
    log_operational("="*60)
    maybe_cleanup_logs()
    
    # Test database connection
    log_operational("[DB] Testing database connection...")
    conn = DBConnection.get_connection()
    if conn:
        log_operational("[DB] ✓ Database connection successful")
        conn.close()
    else:
        log_error("[DB] ✗ Database connection FAILED - check credentials in db.py")
        log_operational("[DB] Continuing anyway, but user authentication will not work")
    
    # Load projects
    log_operational(f"[CONFIG] Loading projects from {PROJECTS_ROOT}")
    try:
        load_projects()
        log_operational(f"[CONFIG] ✓ Loaded {len(PROJECTS)} projects, {len(BROKEN_PROJECTS)} broken configs")
        if PROJECTS:
            for subdomain, proj in PROJECTS.items():
                pwd_str = "[PASSWORD]" if proj.password else "[PUBLIC]"
                log_operational(f"  - {subdomain} → 127.0.0.1:{proj.port} {pwd_str}")
        if BROKEN_PROJECTS:
            for subdomain, error in BROKEN_PROJECTS.items():
                log_error(f"  ✗ {subdomain}: {error}")
    except Exception as e:
        log_error(f"[CONFIG] ✗ Failed to load projects: {e}", exc_info=True)

    # Load templates
    log_operational(f"[TEMPLATES] Loading error template from {ERROR_TEMPLATE_PATH}")
    log_operational(f"[TEMPLATES] ✓ Error template loaded ({len(ERROR_TEMPLATE)} bytes)")
    log_operational(f"[TEMPLATES] Loading password template from {PASSWORD_TEMPLATE_PATH}")
    log_operational(f"[TEMPLATES] ✓ Password template loaded ({len(PASSWORD_TEMPLATE)} bytes)")
    for key, path in ADMIN_PAGE_FILES.items():
        tpl = ADMIN_PAGE_TEMPLATES.get(key, "")
        log_operational(f"[TEMPLATES] Loading admin template '{key}' from {path}")
        log_operational(f"[TEMPLATES] ✓ Admin template '{key}' loaded ({len(tpl)} bytes)")
    log_operational(f"[TEMPLATES] Loading 2FA setup template from {TWO_FA_SETUP_TEMPLATE_PATH}")
    log_operational(f"[TEMPLATES] ✓ 2FA setup template loaded ({len(TWO_FA_SETUP_TEMPLATE)} bytes)")
    log_operational(f"[TEMPLATES] Loading 2FA challenge template from {TWO_FA_CHALLENGE_TEMPLATE_PATH}")
    log_operational(f"[TEMPLATES] ✓ 2FA challenge template loaded ({len(TWO_FA_CHALLENGE_TEMPLATE)} bytes)")

    # Setup server
    log_operational("[SERVER] Setting up HTTPS proxy...")
    server_address = (BIND_HOST, BIND_PORT)
    httpd = ThreadedHTTPServer(server_address, ProxyHandler)
    log_operational(f"[SERVER] ✓ Server created (bind: {BIND_HOST}:{BIND_PORT})")

    # Setup TLS
    log_operational("[TLS] Setting up SSL/TLS certificates...")
    try:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(
            certfile=CERT_FILE,
            keyfile=KEY_FILE,
        )
        httpd.socket = context.wrap_socket(httpd.socket, server_side=True)
        log_operational("[TLS] ✓ Certificates loaded")
        log_operational(f"[TLS]   - Certificate: {CERT_FILE}")
        log_operational(f"[TLS]   - Key: {KEY_FILE}")
    except Exception as e:
        log_error(f"[TLS] ✗ Failed to setup TLS: {e}", exc_info=True)
        return

    # Ready
    log_operational("\n" + "="*60)
    log_operational(f"[READY] HTTPS proxy listening on https://ppowicz.pl:{BIND_PORT}")
    log_operational("="*60)
    log_operational("[ROUTES] Available routes:")
    log_operational("  - https://ppowicz.pl/login          (user login)")
    log_operational("  - https://ppowicz.pl/panel          (user panel)")
    log_operational("  - https://ppowicz.pl/logout         (user logout)")
    log_operational("  - https://admin.ppowicz.pl          (admin panel)")
    log_operational("  - https://<project>.ppowicz.pl      (proxied projects)")
    log_operational("="*60 + "\n")

    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        log_operational("\n[SHUTDOWN] Keyboard interrupt received")
    finally:
        log_operational("[SHUTDOWN] Closing server...")
        httpd.server_close()
        log_operational("[SHUTDOWN] ✓ Server closed")


if __name__ == "__main__":
    run()

#!/usr/bin/env python3
"""
Database module for user, session, and permission management.
Uses PostgreSQL with psycopg2.
"""

import os
import base64
import fnmatch
import hashlib
import json
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Tuple
from uuid import uuid4

import psycopg2
import psycopg2.extras
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError, VerificationError
from cryptography.fernet import Fernet, InvalidToken
from dotenv import load_dotenv
from core.logging import get_logger

# ====== DATABASE LAYOUT ======

"""
#  table_schema |    table_name    |      column_name       |          data_type          | is_nullable |             column_default              
# --------------+------------------+------------------------+-----------------------------+-------------+-----------------------------------------
#  public       | http_logs        | id                     | bigint                      | NO          | nextval('http_logs_id_seq'::regclass)
#  public       | http_logs        | created_at             | timestamp with time zone    | NO          | now()
#  public       | http_logs        | client_ip              | inet                        | YES         | 
#  public       | http_logs        | client_port            | integer                     | YES         | 
#  public       | http_logs        | user_agent             | text                        | YES         | 
#  public       | http_logs        | referer                | text                        | YES         | 
#  public       | http_logs        | host                   | text                        | YES         | 
#  public       | http_logs        | subdomain              | text                        | YES         | 
#  public       | http_logs        | domain                 | text                        | YES         | 
#  public       | http_logs        | server_port            | integer                     | YES         | 
#  public       | http_logs        | method                 | text                        | YES         | 
#  public       | http_logs        | scheme                 | text                        | YES         | 
#  public       | http_logs        | path                   | text                        | YES         | 
#  public       | http_logs        | query_string           | text                        | YES         | 
#  public       | http_logs        | full_url               | text                        | YES         | 
#  public       | http_logs        | http_version           | text                        | YES         | 
#  public       | http_logs        | request_headers        | jsonb                       | YES         | 
#  public       | http_logs        | request_cookies        | jsonb                       | YES         | 
#  public       | http_logs        | request_body           | text                        | YES         | 
#  public       | http_logs        | request_body_truncated | boolean                     | NO          | false
#  public       | http_logs        | response_status        | integer                     | YES         | 
#  public       | http_logs        | response_bytes         | bigint                      | YES         | 
#  public       | http_logs        | response_headers       | jsonb                       | YES         | 
#  public       | http_logs        | backend_host           | text                        | YES         | 
#  public       | http_logs        | backend_port           | integer                     | YES         | 
#  public       | http_logs        | backend_path           | text                        | YES         | 
#  public       | http_logs        | backend_duration_ms    | integer                     | YES         | 
#  public       | http_logs        | is_authenticated       | boolean                     | YES         | 
#  public       | http_logs        | auth_user_id           | bigint                      | YES         | 
#  public       | http_logs        | auth_username          | text                        | YES         | 
#  public       | http_logs        | session_id             | uuid                        | YES         | 
#  public       | http_logs        | is_error               | boolean                     | NO          | false
#  public       | http_logs        | error_message          | text                        | YES         | 
#  public       | permissions      | id                     | bigint                      | NO          | nextval('permissions_id_seq'::regclass)
#  public       | permissions      | code                   | text                        | NO          | 
#  public       | permissions      | description            | text                        | YES         | 
#  public       | role_permissions | role_id                | bigint                      | NO          | 
#  public       | role_permissions | permission_id          | bigint                      | NO          | 
#  public       | roles            | id                     | bigint                      | NO          | nextval('roles_id_seq'::regclass)
#  public       | roles            | name                   | text                        | NO          | 
#  public       | roles            | description            | text                        | YES         | 
#  public       | sessions         | id                     | uuid                        | NO          | 
#  public       | sessions         | user_id                | bigint                      | NO          | 
#  public       | sessions         | created_at             | timestamp with time zone    | NO          | now()
#  public       | sessions         | last_seen_at           | timestamp with time zone    | NO          | now()
#  public       | sessions         | expires_at             | timestamp with time zone    | NO          | (now() + '7 days'::interval)
#  public       | sessions         | ip_address             | inet                        | YES         | 
#  public       | sessions         | user_agent             | text                        | YES         | 
#  public       | sessions         | extra_data             | jsonb                       | YES         | 
#  public       | user_roles       | user_id                | bigint                      | NO          | 
#  public       | user_roles       | role_id                | bigint                      | NO          | 
#  public       | users            | id                     | bigint                      | NO          | nextval('users_id_seq'::regclass)
#  public       | users            | email                  | USER-DEFINED                | NO          | 
#  public       | users            | username               | text                        | NO          | 
#  public       | users            | password_hash          | text                        | NO          | 
#  public       | users            | is_active              | boolean                     | NO          | true
#  public       | users            | created_at             | timestamp with time zone    | NO          | now()
#  public       | users            | last_login_at          | timestamp with time zone    | YES         | 
#  public       | users            | totp_secret            | text                        | YES         | 
#  public       | users            | totp_enabled           | boolean                     | YES         | false
#  public       | users            | totp_setup_at          | timestamp without time zone | YES         | 
"""

# ====== DATABASE CONFIG ======
load_dotenv()

LOGGER = get_logger("proxy.db")

DB_HOST = os.getenv("DB_HOST", "localhost")
DB_NAME = os.getenv("DB_NAME", "proxy")
DB_USER = os.getenv("DB_USER", "proxy")
DB_PASSWORD = os.getenv("DB_PASSWORD", "")
DB_PORT = int(os.getenv("DB_PORT", "5432"))

PASSWORD_HASHER = PasswordHasher(
    time_cost=int(os.getenv("ARGON2_TIME_COST", "3")),
    memory_cost=int(os.getenv("ARGON2_MEMORY_COST", str(64 * 1024))),
    parallelism=int(os.getenv("ARGON2_PARALLELISM", "2")),
    hash_len=int(os.getenv("ARGON2_HASH_LENGTH", "32")),
    salt_len=int(os.getenv("ARGON2_SALT_LENGTH", "16"))
)

CONTACT_ICON_DEFAULT_URL = os.getenv(
    "CONTACT_DEFAULT_ICON_URL",
    "https://cdn.jsdelivr.net/npm/lucide-static@0.408.0/icons/link.svg",
)
CONTACT_METHOD_DEFAULTS: List[Dict[str, str]] = [
    {
        "label": os.getenv("CONTACT_DEFAULT_LABEL_EMAIL", "Email"),
        "value": os.getenv("CONTACT_DEFAULT_EMAIL", "kontakt@ppowicz.pl"),
        "href": os.getenv("CONTACT_DEFAULT_EMAIL_LINK", "mailto:kontakt@ppowicz.pl"),
        "icon_url": os.getenv(
            "CONTACT_DEFAULT_EMAIL_ICON",
            "https://cdn.jsdelivr.net/npm/lucide-static@0.408.0/icons/mail.svg",
        ),
    },
    {
        "label": os.getenv("CONTACT_DEFAULT_LABEL_PHONE", "Telefon"),
        "value": os.getenv("CONTACT_DEFAULT_PHONE", "+48 600 111 222"),
        "href": os.getenv("CONTACT_DEFAULT_PHONE_LINK", "tel:+48600111222"),
        "icon_url": os.getenv(
            "CONTACT_DEFAULT_PHONE_ICON",
            "https://cdn.jsdelivr.net/npm/lucide-static@0.408.0/icons/phone.svg",
        ),
    },
    {
        "label": os.getenv("CONTACT_DEFAULT_LABEL_GITHUB", "GitHub"),
        "value": os.getenv("CONTACT_DEFAULT_GITHUB", "github.com/ppowicz"),
        "href": os.getenv("CONTACT_DEFAULT_GITHUB_LINK", "https://github.com/ppowicz"),
        "icon_url": os.getenv(
            "CONTACT_DEFAULT_GITHUB_ICON",
            "https://cdn.jsdelivr.net/npm/simple-icons@9.16.0/icons/github.svg",
        ),
    },
]

_TOTP_SECRET_KEY = os.getenv("TOTP_SECRET_KEY", "").strip()
_FERNET = None
if _TOTP_SECRET_KEY:
    try:
        _FERNET = Fernet(_TOTP_SECRET_KEY)
    except Exception as exc:
        LOGGER.warning(f"[TOTP] Invalid TOTP_SECRET_KEY: {exc}")
        _FERNET = None


def _is_legacy_sha256(hash_value: Optional[str]) -> bool:
    if not hash_value or len(hash_value) != 64:
        return False
    try:
        int(hash_value, 16)
        return True
    except (TypeError, ValueError):
        return False


def _update_user_password_hash(user_id: int, password_hash: str) -> bool:
    conn = DBConnection.get_connection()
    if not conn:
        return False
    try:
        with conn:
            with conn.cursor() as cur:
                cur.execute(
                    "UPDATE users SET password_hash = %s WHERE id = %s",
                    (password_hash, user_id)
                )
        return True
    except Exception as exc:
        LOGGER.error(f"[DB ERROR] Failed to store password hash for user {user_id}: {exc}")
        return False


def _mark_successful_login(user_id: int):
    conn = DBConnection.get_connection()
    if not conn:
        return
    try:
        with conn:
            with conn.cursor() as cur:
                cur.execute(
                    "UPDATE users SET last_login_at = now() WHERE id = %s",
                    (user_id,)
                )
    except Exception:
        pass


def _encrypt_totp_secret(secret: str) -> str:
    if not secret:
        return secret
    if not _FERNET:
        return secret
    try:
        return _FERNET.encrypt(secret.encode()).decode()
    except Exception as exc:
        LOGGER.error(f"[TOTP] Failed to encrypt secret: {exc}")
        return secret


def _decrypt_totp_secret(user_id: int, secret: Optional[str]) -> Optional[str]:
    if not secret:
        return None
    if not _FERNET:
        return secret
    try:
        return _FERNET.decrypt(secret.encode()).decode()
    except InvalidToken:
        # Assume legacy plaintext secret; attempt to upgrade storage
        _persist_totp_secret(user_id, secret)
        return secret
    except Exception as exc:
        LOGGER.error(f"[TOTP] Failed to decrypt secret for user {user_id}: {exc}")
        return None


def _persist_totp_secret(user_id: int, plain_secret: str) -> bool:
    encrypted = _encrypt_totp_secret(plain_secret)
    conn = DBConnection.get_connection()
    if not conn:
        return False
    try:
        with conn:
            with conn.cursor() as cur:
                cur.execute(
                    "UPDATE users SET totp_secret = %s, totp_setup_at = COALESCE(totp_setup_at, now()), totp_enabled = true WHERE id = %s",
                    (encrypted, user_id)
                )
        return True
    except Exception as exc:
        LOGGER.error(f"[DB ERROR] Failed to persist encrypted TOTP secret for user {user_id}: {exc}")
        return False

# ====== CONNECTION POOL ======
class DBConnection:
    """Thread-safe database connection manager."""
    
    @staticmethod
    def get_connection():
        """Get a database connection."""
        try:
            conn = psycopg2.connect(
                host=DB_HOST,
                database=DB_NAME,
                user=DB_USER,
                password=DB_PASSWORD,
                port=DB_PORT,
                cursor_factory=psycopg2.extras.RealDictCursor
            )
            return conn
        except Exception as e:
            LOGGER.exception(f"[DB ERROR] Failed to connect to database: {e}")
            return None

# ====== USER MANAGEMENT ======

def hash_password(password: str) -> str:
    """Hash password using Argon2id."""
    return PASSWORD_HASHER.hash(password)

def create_user(username: str, email: str, password: str) -> Optional[int]:
    """Create new user. Returns user_id on success, None on failure."""
    conn = DBConnection.get_connection()
    if not conn:
        return None
    
    try:
        with conn:
            with conn.cursor() as cur:
                password_hash = hash_password(password)
                cur.execute(
                    """
                    INSERT INTO users (username, email, password_hash, is_active, created_at)
                    VALUES (%s, %s, %s, false, now())
                    RETURNING id
                    """,
                    (username, email, password_hash)
                )
                result = cur.fetchone()
                return result['id'] if result else None
    except psycopg2.IntegrityError:
        LOGGER.warning(f"[DB] Username or email already exists: {username}, {email}")
        return None
    except Exception as e:
        LOGGER.exception(f"[DB ERROR] Failed to create user: {e}")
        return None

def get_user_by_username(username: str) -> Optional[Dict]:
    """Get user by username."""
    conn = DBConnection.get_connection()
    if not conn:
        return None
    
    try:
        with conn:
            with conn.cursor() as cur:
                cur.execute("SELECT * FROM users WHERE username = %s", (username,))
                return cur.fetchone()
    except Exception as e:
        LOGGER.error(f"[DB ERROR] Failed to get user: {e}")
        return None

def get_user_by_id(user_id: int) -> Optional[Dict]:
    """Get user by ID."""
    conn = DBConnection.get_connection()
    if not conn:
        return None
    
    try:
        with conn:
            with conn.cursor() as cur:
                cur.execute("SELECT * FROM users WHERE id = %s", (user_id,))
                return cur.fetchone()
    except Exception as e:
        LOGGER.error(f"[DB ERROR] Failed to get user by ID: {e}")
        return None

def verify_password(username: str, password: str) -> Optional[int]:
    """Verify password for user. Returns user_id on success, None on failure."""
    user = get_user_by_username(username)
    if not user or not user.get('is_active'):
        return None

    stored = user.get('password_hash') or ''
    user_id = user['id']

    if stored.startswith('$argon2'):
        try:
            PASSWORD_HASHER.verify(stored, password)
            if PASSWORD_HASHER.check_needs_rehash(stored):
                _update_user_password_hash(user_id, hash_password(password))
            _mark_successful_login(user_id)
            return user_id
        except VerifyMismatchError:
            return None
        except VerificationError:
            return None
    elif _is_legacy_sha256(stored):
        legacy_hash = hashlib.sha256(password.encode()).hexdigest()
        if legacy_hash == stored:
            _update_user_password_hash(user_id, hash_password(password))
            _mark_successful_login(user_id)
            return user_id

    return None

# ====== SESSION MANAGEMENT ======

def create_session(user_id: int, ip_address: str, user_agent: str, extra_data: Optional[Dict] = None) -> Optional[str]:
    """Create new session. Returns session_id (UUID) on success."""
    session_id = str(uuid4())
    conn = DBConnection.get_connection()
    if not conn:
        return None
    
    # Initialize extra_data with 2FA flags if not provided
    if extra_data is None:
        extra_data = {
            "2fa_pending": False,
            "2fa_verified": False,
            "2fa_setup_pending": False,
            "original_next": "",
            "csrf_token": ""
        }
    
    try:
        with conn:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    INSERT INTO sessions (id, user_id, created_at, last_seen_at, expires_at, ip_address, user_agent, extra_data)
                    VALUES (%s, %s, now(), now(), now() + interval '7 days', %s, %s, %s)
                    """,
                    (session_id, user_id, ip_address, user_agent, psycopg2.extras.Json(extra_data))
                )
        return session_id
    except Exception as e:
        LOGGER.exception(f"[DB ERROR] Failed to create session: {e}")
        return None

def get_session(session_id: str) -> Optional[Dict]:
    """Get session by ID. Returns None if expired."""
    conn = DBConnection.get_connection()
    if not conn:
        return None
    
    try:
        with conn:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    SELECT * FROM sessions 
                    WHERE id = %s AND expires_at > now()
                    """,
                    (session_id,)
                )
                return cur.fetchone()
    except Exception as e:
        LOGGER.error(f"[DB ERROR] Failed to get session: {e}")
        return None

def update_session_activity(session_id: str) -> bool:
    """Update last_seen_at for session."""
    conn = DBConnection.get_connection()
    if not conn:
        return False
    
    try:
        with conn:
            with conn.cursor() as cur:
                cur.execute(
                    "UPDATE sessions SET last_seen_at = now() WHERE id = %s",
                    (session_id,)
                )
        return True
    except Exception as e:
        LOGGER.error(f"[DB ERROR] Failed to update session: {e}")
        return False

def expire_session(session_id: str) -> bool:
    """Expire a session."""
    conn = DBConnection.get_connection()
    if not conn:
        return False
    
    try:
        with conn:
            with conn.cursor() as cur:
                cur.execute(
                    "UPDATE sessions SET expires_at = now() WHERE id = %s",
                    (session_id,)
                )
        return True
    except Exception as e:
        LOGGER.error(f"[DB ERROR] Failed to expire session: {e}")
        return False

# ====== PERMISSION & ROLE MANAGEMENT ======

def get_user_roles(user_id: int) -> List[Dict]:
    """Get all roles for user."""
    conn = DBConnection.get_connection()
    if not conn:
        return []
    
    try:
        with conn:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    SELECT r.* FROM roles r
                    JOIN user_roles ur ON ur.role_id = r.id
                    WHERE ur.user_id = %s
                    """,
                    (user_id,)
                )
                return cur.fetchall() or []
    except Exception as e:
        LOGGER.error(f"[DB ERROR] Failed to get user roles: {e}")
        return []

def get_user_permissions(user_id: int) -> List[Dict]:
    """Get all permissions for user (via roles)."""
    conn = DBConnection.get_connection()
    if not conn:
        return []
    
    try:
        with conn:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    SELECT DISTINCT p.* FROM permissions p
                    JOIN role_permissions rp ON rp.permission_id = p.id
                    JOIN user_roles ur ON ur.role_id = rp.role_id
                    WHERE ur.user_id = %s
                    """,
                    (user_id,)
                )
                return cur.fetchall() or []
    except Exception as e:
        LOGGER.error(f"[DB ERROR] Failed to get user permissions: {e}")
        return []

def user_has_permission(user_id: int, permission_code: str) -> bool:
    """Check if user has specific permission. Admin (*) has all permissions."""
    perms = get_user_permissions(user_id)
    for p in perms:
        code = (p.get('code') or "").strip()
        if not code:
            continue
        if code == "*":  # Admin permission
            return True
        if code == permission_code:
            return True
        if "*" in code or "?" in code:
            if fnmatch.fnmatchcase(permission_code, code):
                return True
    return False

def user_is_admin(user_id: int) -> bool:
    """Check if user is admin (has * permission)."""
    return user_has_permission(user_id, "*")

# ====== ADMIN QUERIES ======

def get_all_users() -> List[Dict]:
    """Get all users (admin only)."""
    conn = DBConnection.get_connection()
    if not conn:
        return []
    
    try:
        with conn:
            with conn.cursor() as cur:
                cur.execute("SELECT id, username, email, is_active, created_at, last_login_at, totp_enabled FROM users")
                return cur.fetchall() or []
    except Exception as e:
        LOGGER.error(f"[DB ERROR] Failed to get all users: {e}")
        return []

def get_all_sessions() -> List[Dict]:
    """Get all active sessions (admin only)."""
    conn = DBConnection.get_connection()
    if not conn:
        return []
    
    try:
        with conn:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    SELECT s.id, s.user_id, u.username, s.created_at, s.last_seen_at, s.expires_at, s.ip_address, s.user_agent
                    FROM sessions s
                    JOIN users u ON u.id = s.user_id
                    WHERE s.expires_at > now()
                    ORDER BY s.last_seen_at DESC
                    """
                )
                return cur.fetchall() or []
    except Exception as e:
        LOGGER.error(f"[DB ERROR] Failed to get sessions: {e}")
        return []

def get_all_roles() -> List[Dict]:
    """Get all roles."""
    conn = DBConnection.get_connection()
    if not conn:
        return []
    
    try:
        with conn:
            with conn.cursor() as cur:
                cur.execute("SELECT * FROM roles")
                return cur.fetchall() or []
    except Exception as e:
        LOGGER.error(f"[DB ERROR] Failed to get roles: {e}")
        return []

def get_all_permissions() -> List[Dict]:
    """Get all permissions."""
    conn = DBConnection.get_connection()
    if not conn:
        return []
    
    try:
        with conn:
            with conn.cursor() as cur:
                cur.execute("SELECT * FROM permissions")
                return cur.fetchall() or []
    except Exception as e:
        LOGGER.error(f"[DB ERROR] Failed to get permissions: {e}")
        return []

def assign_role_to_user(user_id: int, role_id: int) -> bool:
    """Assign role to user."""
    conn = DBConnection.get_connection()
    if not conn:
        return False
    
    try:
        with conn:
            with conn.cursor() as cur:
                cur.execute(
                    "INSERT INTO user_roles (user_id, role_id) VALUES (%s, %s) ON CONFLICT DO NOTHING",
                    (user_id, role_id)
                )
        return True
    except Exception as e:
        LOGGER.error(f"[DB ERROR] Failed to assign role: {e}")
        return False

def deassign_role_from_user(user_id: int, role_id: int) -> bool:
    """Remove role from user."""
    conn = DBConnection.get_connection()
    if not conn:
        return False
    
    try:
        with conn:
            with conn.cursor() as cur:
                cur.execute(
                    "DELETE FROM user_roles WHERE user_id = %s AND role_id = %s",
                    (user_id, role_id)
                )
        return True
    except Exception as e:
        LOGGER.error(f"[DB ERROR] Failed to deassign role: {e}")
        return False

def delete_user(user_id: int) -> bool:
    """Permanently delete a user and their sessions/role links."""
    conn = DBConnection.get_connection()
    if not conn:
        return False

    try:
        with conn:
            with conn.cursor() as cur:
                cur.execute("DELETE FROM user_roles WHERE user_id = %s", (user_id,))
                cur.execute("DELETE FROM sessions WHERE user_id = %s", (user_id,))
                cur.execute("DELETE FROM users WHERE id = %s", (user_id,))
                deleted = cur.rowcount or 0
        return bool(deleted)
    except Exception as e:
        LOGGER.error(f"[DB ERROR] Failed to delete user: {e}")
        return False


# ====== HTTP LOGS & GENERIC TABLE HELPERS ======

from psycopg2 import sql
import json

def insert_http_log(record: Dict) -> bool:
    """Insert an http_logs record. `record` is a dict with keys matching columns."""
    conn = DBConnection.get_connection()
    if not conn:
        LOGGER.info(f"[DB LOG] No DB connection available")
        return False
    # prepare identifiers and values
    cols = []
    vals = []
    for k, v in record.items():
        # skip invalid keys
        if not isinstance(k, str) or not k.isidentifier():
            LOGGER.info(f"[DB LOG] Skipping invalid key: {k}")
            continue
        cols.append(sql.Identifier(k))
        # JSON-serialize dicts
        if isinstance(v, (dict, list)):
            vals.append(json.dumps(v))
        else:
            vals.append(v)
    if not cols:
        LOGGER.info(f"[DB LOG] No valid columns in record")
        return False
    try:
        with conn:
            with conn.cursor() as cur:
                col_names = sql.SQL(', ').join(cols)
                placeholders = sql.SQL(', ').join(sql.Placeholder() * len(vals))
                query = sql.SQL('INSERT INTO http_logs ({}) VALUES ({})').format(col_names, placeholders)
                LOGGER.info(f"[DB LOG] Executing: {query.as_string(cur)}")
                cur.execute(query, vals)
        LOGGER.info(f"[DB LOG] HTTP log inserted successfully ({len(cols)} columns)")
        return True
    except Exception as e:
        LOGGER.exception(f"[DB ERROR] Failed to insert http_log: {e}")
        return False

def get_recent_http_logs(limit: int = 200) -> List[Dict]:
    conn = DBConnection.get_connection()
    if not conn:
        return []
    try:
        with conn:
            with conn.cursor() as cur:
                cur.execute("""
                    SELECT 
                        id, created_at, client_ip, method, path, 
                        subdomain,
                        response_status, backend_duration_ms, 
                        auth_username, is_error, error_message
                    FROM http_logs 
                    ORDER BY created_at DESC 
                    LIMIT %s
                """, (limit,))
                return cur.fetchall() or []
    except Exception as e:
        LOGGER.error(f"[DB ERROR] Failed to get http logs: {e}")
        return []


def cleanup_http_logs_older_than(days: int) -> int:
    """Delete http_logs records older than the provided number of days."""
    if days <= 0:
        return 0

    conn = DBConnection.get_connection()
    if not conn:
        return 0

    removed = 0
    try:
        with conn:
            with conn.cursor() as cur:
                cur.execute(
                    "DELETE FROM http_logs WHERE created_at < now() - INTERVAL '1 day' * %s",
                    (int(days),)
                )
                removed = cur.rowcount or 0
    except Exception as e:
        LOGGER.exception(f"[DB ERROR] Failed to cleanup http_logs older than {days} days: {e}")
        return 0

    return removed


def _sanitize_minutes(minutes: int, default: int = 1440) -> int:
    try:
        value = int(minutes)
    except (TypeError, ValueError):
        value = default
    return max(1, value)


def get_http_log_summary(minutes: int = 1440) -> Dict:
    """Return aggregate summary metrics for http_logs within the given time window (in minutes)."""
    window_minutes = _sanitize_minutes(minutes)
    conn = DBConnection.get_connection()
    if not conn:
        return {}
    try:
        with conn:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    SELECT
                        COUNT(*) AS total_requests,
                        COUNT(DISTINCT COALESCE(subdomain, '')) AS unique_apps,
                        COUNT(DISTINCT client_ip) AS unique_clients,
                        COUNT(DISTINCT auth_username) FILTER (WHERE auth_username IS NOT NULL AND auth_username <> '') AS unique_users,
                        COALESCE(AVG(backend_duration_ms), 0) AS avg_backend_ms,
                        SUM(CASE WHEN is_error THEN 1 ELSE 0 END) AS error_count
                    FROM http_logs
                    WHERE created_at >= now() - INTERVAL '1 minute' * %s
                    """,
                    (window_minutes,)
                )
                row = cur.fetchone() or {}
                total = row.get('total_requests', 0) or 0
                errors = row.get('error_count', 0) or 0
                error_rate = float(errors) / float(total) if total else 0.0
                return {
                    'total_requests': total,
                    'unique_apps': row.get('unique_apps', 0) or 0,
                    'unique_clients': row.get('unique_clients', 0) or 0,
                    'unique_users': row.get('unique_users', 0) or 0,
                    'avg_backend_ms': float(row.get('avg_backend_ms') or 0),
                    'error_count': errors,
                    'error_rate': error_rate,
                    'window_minutes': window_minutes,
                }
    except Exception as e:
        LOGGER.exception(f"[DB ERROR] Failed to compute http_log summary: {e}")
        return {}


def get_http_log_status_breakdown(minutes: int = 1440) -> Dict:
    """Return counts per status family (2xx/3xx/4xx/5xx) and explicit error count."""
    window_minutes = _sanitize_minutes(minutes)
    conn = DBConnection.get_connection()
    if not conn:
        return {}
    try:
        with conn:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    SELECT
                        SUM(CASE WHEN response_status BETWEEN 200 AND 299 THEN 1 ELSE 0 END) AS s2xx,
                        SUM(CASE WHEN response_status BETWEEN 300 AND 399 THEN 1 ELSE 0 END) AS s3xx,
                        SUM(CASE WHEN response_status BETWEEN 400 AND 499 THEN 1 ELSE 0 END) AS s4xx,
                        SUM(CASE WHEN response_status >= 500 THEN 1 ELSE 0 END) AS s5xx,
                        SUM(CASE WHEN is_error THEN 1 ELSE 0 END) AS error_count
                    FROM http_logs
                    WHERE created_at >= now() - INTERVAL '1 minute' * %s
                    """,
                    (window_minutes,)
                )
                row = cur.fetchone() or {}
                return {
                    's2xx': row.get('s2xx', 0) or 0,
                    's3xx': row.get('s3xx', 0) or 0,
                    's4xx': row.get('s4xx', 0) or 0,
                    's5xx': row.get('s5xx', 0) or 0,
                    'error_count': row.get('error_count', 0) or 0,
                    'window_minutes': window_minutes,
                }
    except Exception as e:
        LOGGER.exception(f"[DB ERROR] Failed to compute status breakdown: {e}")
        return {}


def get_http_log_timeline(minutes: int = 1440, bucket_minutes: int = 60, limit_points: int = 200) -> List[Dict]:
    """Return counts grouped into time buckets for charts."""
    window_minutes = _sanitize_minutes(minutes)
    bucket_size = _sanitize_minutes(bucket_minutes, default=5)
    limit_points = max(1, int(limit_points or 1))
    conn = DBConnection.get_connection()
    if not conn:
        return []
    try:
        with conn:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    WITH series AS (
                        SELECT generate_series(
                            date_trunc('minute', now() - INTERVAL '1 minute' * %s),
                            date_trunc('minute', now()),
                            INTERVAL '1 minute' * %s
                        ) AS bucket_start
                    )
                    SELECT
                        s.bucket_start,
                        COUNT(hl.id) AS total,
                        COALESCE(SUM(CASE WHEN hl.is_error THEN 1 ELSE 0 END), 0) AS errors
                    FROM series s
                    LEFT JOIN http_logs hl
                        ON hl.created_at >= s.bucket_start
                        AND hl.created_at < s.bucket_start + INTERVAL '1 minute' * %s
                    GROUP BY s.bucket_start
                    ORDER BY s.bucket_start DESC
                    LIMIT %s
                    """,
                    (
                        window_minutes,
                        bucket_size,
                        bucket_size,
                        limit_points,
                    ),
                )
                rows = cur.fetchall() or []
                return list(reversed([
                    {
                        'bucket_start': row['bucket_start'].isoformat() if row.get('bucket_start') else None,
                        'total': row.get('total', 0) or 0,
                        'errors': row.get('errors', 0) or 0,
                    }
                    for row in rows
                ]))
    except Exception as e:
        LOGGER.exception(f"[DB ERROR] Failed to compute timeline: {e}")
        return []


def get_top_http_subdomains(minutes: int = 1440, limit: int = 5) -> List[Dict]:
    window_minutes = _sanitize_minutes(minutes)
    limit = max(1, int(limit or 1))
    conn = DBConnection.get_connection()
    if not conn:
        return []
    try:
        with conn:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    SELECT
                        COALESCE(subdomain, '') AS subdomain,
                        COUNT(*) AS total,
                        SUM(CASE WHEN is_error THEN 1 ELSE 0 END) AS errors,
                        COALESCE(AVG(backend_duration_ms), 0) AS avg_backend_ms
                    FROM http_logs
                    WHERE created_at >= now() - INTERVAL '1 minute' * %s
                    GROUP BY COALESCE(subdomain, '')
                    ORDER BY total DESC
                    LIMIT %s
                    """,
                    (window_minutes, limit),
                )
                return cur.fetchall() or []
    except Exception as e:
        LOGGER.exception(f"[DB ERROR] Failed to compute top subdomains: {e}")
        return []


def get_top_http_paths(minutes: int = 1440, limit: int = 5) -> List[Dict]:
    window_minutes = _sanitize_minutes(minutes)
    limit = max(1, int(limit or 1))
    conn = DBConnection.get_connection()
    if not conn:
        return []
    try:
        with conn:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    SELECT
                        COALESCE(path, '') AS path,
                        COALESCE(subdomain, '') AS subdomain,
                        COUNT(*) AS total,
                        SUM(CASE WHEN is_error THEN 1 ELSE 0 END) AS errors
                    FROM http_logs
                    WHERE created_at >= now() - INTERVAL '1 minute' * %s
                    GROUP BY COALESCE(path, ''), COALESCE(subdomain, '')
                    ORDER BY total DESC
                    LIMIT %s
                    """,
                    (window_minutes, limit),
                )
                return cur.fetchall() or []
    except Exception as e:
        LOGGER.exception(f"[DB ERROR] Failed to compute top paths: {e}")
        return []


def get_recent_http_errors(limit: int = 20) -> List[Dict]:
    limit = max(1, int(limit or 1))
    conn = DBConnection.get_connection()
    if not conn:
        return []
    try:
        with conn:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    SELECT 
                        id,
                        created_at,
                        subdomain,
                        path,
                        method,
                        response_status,
                        error_message,
                        backend_duration_ms
                    FROM http_logs
                    WHERE is_error = true OR response_status >= 400
                    ORDER BY created_at DESC
                    LIMIT %s
                    """,
                    (limit,),
                )
                return cur.fetchall() or []
    except Exception as e:
        LOGGER.exception(f"[DB ERROR] Failed to fetch recent errors: {e}")
        return []


def delete_http_logs(log_ids: List[int]) -> int:
    """Delete http log rows by id, returning number removed."""
    if not log_ids:
        return 0
    clean_ids = []
    for raw in log_ids:
        try:
            clean_ids.append(int(raw))
        except (TypeError, ValueError):
            continue
    if not clean_ids:
        return 0
    conn = DBConnection.get_connection()
    if not conn:
        return 0
    try:
        with conn:
            with conn.cursor() as cur:
                cur.execute(
                    "DELETE FROM http_logs WHERE id = ANY(%s)",
                    (clean_ids,)
                )
                return cur.rowcount or 0
    except Exception as e:
        LOGGER.exception(f"[DB ERROR] Failed to delete http logs: {e}")
        return 0


# ====== CONTACT METHODS ======

def _fallback_contact_methods() -> List[Dict[str, str]]:
    defaults = []
    for item in CONTACT_METHOD_DEFAULTS:
        defaults.append({
            "id": None,
            "label": item.get("label", ""),
            "value": item.get("value", ""),
            "href": item.get("href", item.get("value", "")),
            "icon_url": item.get("icon_url") or CONTACT_ICON_DEFAULT_URL,
            "sort_order": len(defaults),
        })
    return defaults


def _sanitize_contact_methods(methods: List[Dict[str, str]]) -> List[Dict[str, str]]:
    sanitized: List[Dict[str, str]] = []
    for idx, raw in enumerate(methods or []):
        label = (raw.get("label") or "").strip()
        value = (raw.get("value") or "").strip()
        href = (raw.get("href") or "").strip() or value
        icon_url = (raw.get("icon_url") or "").strip() or CONTACT_ICON_DEFAULT_URL
        if not label or not value:
            continue
        sanitized.append({
            "label": label,
            "value": value,
            "href": href,
            "icon_url": icon_url,
            "sort_order": idx,
        })
    if not sanitized:
        return _fallback_contact_methods()
    return sanitized


def get_contact_methods() -> List[Dict[str, str]]:
    conn = DBConnection.get_connection()
    if not conn:
        return _fallback_contact_methods()
    try:
        with conn:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    SELECT id, label, value, href, icon_url, sort_order
                    FROM contact_methods
                    ORDER BY sort_order ASC, id ASC
                    """
                )
                rows = cur.fetchall() or []
                if not rows:
                    return _fallback_contact_methods()
                return rows
    except Exception as exc:
        LOGGER.error(f"[DB ERROR] Failed to load contact methods: {exc}")
        return _fallback_contact_methods()


def replace_contact_methods(methods: List[Dict[str, str]]) -> Optional[List[Dict[str, str]]]:
    sanitized = _sanitize_contact_methods(methods)
    conn = DBConnection.get_connection()
    if not conn:
        return None
    try:
        with conn:
            with conn.cursor() as cur:
                cur.execute("DELETE FROM contact_methods")
                for idx, item in enumerate(sanitized):
                    cur.execute(
                        """
                        INSERT INTO contact_methods (label, value, href, icon_url, sort_order, updated_at)
                        VALUES (%s, %s, %s, %s, %s, now())
                        """,
                        (
                            item["label"],
                            item["value"],
                            item["href"],
                            item["icon_url"],
                            idx,
                        ),
                    )
        return get_contact_methods()
    except Exception as exc:
        LOGGER.error(f"[DB ERROR] Failed to replace contact methods: {exc}")
        return None

def get_table_columns(table: str) -> List[str]:
    """Return list of column names for a table. Sanitize table name."""
    if not isinstance(table, str) or not table.isidentifier():
        return []
    conn = DBConnection.get_connection()
    if not conn:
        return []
    try:
        with conn:
            with conn.cursor() as cur:
                cur.execute("SELECT column_name FROM information_schema.columns WHERE table_name = %s ORDER BY ordinal_position", (table,))
                rows = cur.fetchall() or []
                return [r['column_name'] for r in rows]
    except Exception as e:
        LOGGER.error(f"[DB ERROR] Failed to get columns for {table}: {e}")
        return []

def get_table_rows(table: str, limit: int = 200) -> List[Dict]:
    if not isinstance(table, str) or not table.isidentifier():
        return []
    conn = DBConnection.get_connection()
    if not conn:
        return []
    try:
        with conn:
            with conn.cursor() as cur:
                query = sql.SQL('SELECT * FROM {} ORDER BY 1 LIMIT %s').format(sql.Identifier(table))
                cur.execute(query, (limit,))
                return cur.fetchall() or []
    except Exception as e:
        LOGGER.error(f"[DB ERROR] Failed to get rows for {table}: {e}")
        return []

def update_table_row(table: str, pk_name: str, pk_value, column: str, value) -> bool:
    # basic validation
    if not (isinstance(table, str) and table.isidentifier() and isinstance(column, str) and column.isidentifier() and isinstance(pk_name, str) and pk_name.isidentifier()):
        return False
    conn = DBConnection.get_connection()
    if not conn:
        return False
    try:
        with conn:
            with conn.cursor() as cur:
                query = sql.SQL('UPDATE {} SET {} = %s WHERE {} = %s').format(
                    sql.Identifier(table), sql.Identifier(column), sql.Identifier(pk_name)
                )
                cur.execute(query, (value, pk_value))
        return True
    except Exception as e:
        LOGGER.exception(f"[DB ERROR] Failed to update {table}.{column}: {e}")
        return False


# ====== ROLES & PERMISSIONS MANAGEMENT ======

def create_role(name: str, description: str = "") -> Optional[int]:
    """Create new role. Returns role_id on success."""
    conn = DBConnection.get_connection()
    if not conn:
        return None
    try:
        with conn:
            with conn.cursor() as cur:
                cur.execute(
                    "INSERT INTO roles (name, description) VALUES (%s, %s) RETURNING id",
                    (name, description)
                )
                result = cur.fetchone()
                return result['id'] if result else None
    except Exception as e:
        LOGGER.error(f"[DB ERROR] Failed to create role: {e}")
        return None

def update_role(role_id: int, name: str = None, description: str = None) -> bool:
    """Update role name and/or description."""
    if name is None and description is None:
        return True
    conn = DBConnection.get_connection()
    if not conn:
        return False
    try:
        with conn:
            with conn.cursor() as cur:
                if name is not None and description is not None:
                    cur.execute("UPDATE roles SET name = %s, description = %s WHERE id = %s", (name, description, role_id))
                elif name is not None:
                    cur.execute("UPDATE roles SET name = %s WHERE id = %s", (name, role_id))
                elif description is not None:
                    cur.execute("UPDATE roles SET description = %s WHERE id = %s", (description, role_id))
        return True
    except Exception as e:
        LOGGER.error(f"[DB ERROR] Failed to update role: {e}")
        return False

def delete_role(role_id: int) -> bool:
    """Delete role (and deassign all users)."""
    conn = DBConnection.get_connection()
    if not conn:
        return False
    try:
        with conn:
            with conn.cursor() as cur:
                cur.execute("DELETE FROM user_roles WHERE role_id = %s", (role_id,))
                cur.execute("DELETE FROM role_permissions WHERE role_id = %s", (role_id,))
                cur.execute("DELETE FROM roles WHERE id = %s", (role_id,))
        return True
    except Exception as e:
        LOGGER.error(f"[DB ERROR] Failed to delete role: {e}")
        return False

def create_permission(code: str, description: str = "") -> Optional[int]:
    """Create new permission. Returns permission_id on success."""
    conn = DBConnection.get_connection()
    if not conn:
        return None
    try:
        with conn:
            with conn.cursor() as cur:
                cur.execute(
                    "INSERT INTO permissions (code, description) VALUES (%s, %s) RETURNING id",
                    (code, description)
                )
                result = cur.fetchone()
                return result['id'] if result else None
    except Exception as e:
        LOGGER.error(f"[DB ERROR] Failed to create permission: {e}")
        return None

def assign_permission_to_role(role_id: int, permission_id: int) -> bool:
    """Assign permission to role."""
    conn = DBConnection.get_connection()
    if not conn:
        return False
    try:
        with conn:
            with conn.cursor() as cur:
                # Check if already exists
                cur.execute("SELECT 1 FROM role_permissions WHERE role_id = %s AND permission_id = %s", (role_id, permission_id))
                if cur.fetchone():
                    return True  # Already assigned
                cur.execute("INSERT INTO role_permissions (role_id, permission_id) VALUES (%s, %s)", (role_id, permission_id))
        return True
    except Exception as e:
        LOGGER.error(f"[DB ERROR] Failed to assign permission to role: {e}")
        return False

def deassign_permission_from_role(role_id: int, permission_id: int) -> bool:
    """Remove permission from role."""
    conn = DBConnection.get_connection()
    if not conn:
        return False
    try:
        with conn:
            with conn.cursor() as cur:
                cur.execute("DELETE FROM role_permissions WHERE role_id = %s AND permission_id = %s", (role_id, permission_id))
        return True
    except Exception as e:
        LOGGER.error(f"[DB ERROR] Failed to deassign permission from role: {e}")
        return False

def get_role_permissions(role_id: int) -> List[Dict]:
    """Get all permissions assigned to a role."""
    conn = DBConnection.get_connection()
    if not conn:
        return []
    try:
        with conn:
            with conn.cursor() as cur:
                cur.execute(
                    "SELECT p.* FROM permissions p JOIN role_permissions rp ON p.id = rp.permission_id WHERE rp.role_id = %s",
                    (role_id,)
                )
                return cur.fetchall() or []
    except Exception as e:
        LOGGER.error(f"[DB ERROR] Failed to get role permissions: {e}")
        return []

def update_user(user_id: int, username: str = None, email: str = None, is_active: bool = None, password: str = None) -> bool:
    """Update user profile."""
    if all(x is None for x in [username, email, is_active, password]):
        return True
    conn = DBConnection.get_connection()
    if not conn:
        return False
    try:
        with conn:
            with conn.cursor() as cur:
                updates = []
                params = []
                if username is not None:
                    updates.append("username = %s")
                    params.append(username)
                if email is not None:
                    updates.append("email = %s")
                    params.append(email)
                if is_active is not None:
                    updates.append("is_active = %s")
                    params.append(is_active)
                if password is not None:
                    updates.append("password_hash = %s")
                    params.append(hash_password(password))
                if updates:
                    params.append(user_id)
                    query = "UPDATE users SET " + ", ".join(updates) + " WHERE id = %s"
                    cur.execute(query, params)
        return True
    except Exception as e:
        LOGGER.error(f"[DB ERROR] Failed to update user: {e}")
        return False

def bulk_assign_roles_to_user(user_id: int, role_ids: List[int]) -> bool:
    """Replace all user roles with the provided list."""
    conn = DBConnection.get_connection()
    if not conn:
        return False
    try:
        with conn:
            with conn.cursor() as cur:
                # Delete existing roles
                cur.execute("DELETE FROM user_roles WHERE user_id = %s", (user_id,))
                # Insert new roles
                for role_id in role_ids:
                    cur.execute("INSERT INTO user_roles (user_id, role_id) VALUES (%s, %s)", (user_id, role_id))
        return True
    except Exception as e:
        LOGGER.error(f"[DB ERROR] Failed to assign roles to user: {e}")
        return False

# ====== TOTP 2FA MANAGEMENT ======

def create_totp_secret(user_id: int) -> Optional[Tuple[str, str]]:
    """
    Generate new TOTP secret and QR code.
    Returns tuple (secret_base32, qr_code_data_uri) on success, None on failure.
    Secret is NOT saved to DB yet - user must verify first.
    """
    try:
        import pyotp
        import qrcode
        from io import BytesIO
        import base64
        
        user = get_user_by_id(user_id)
        if not user:
            return None
        
        # Generate TOTP secret
        secret = pyotp.random_base32()
        
        # Create QR code for Google Authenticator
        totp = pyotp.TOTP(secret)
        uri = totp.provisioning_uri(
            name=user['username'],
            issuer_name='ppowicz.pl'
        )
        
        # Generate QR code image
        qr = qrcode.QRCode(version=1, box_size=10, border=5)
        qr.add_data(uri)
        qr.make(fit=True)
        
        # Convert to data URI
        img = qr.make_image(fill_color="white", back_color="transparent")
        buffered = BytesIO()
        img.save(buffered, format="PNG")
        img_data = base64.b64encode(buffered.getvalue()).decode()
        qr_data_uri = f"data:image/png;base64,{img_data}"
        
        return (secret, qr_data_uri)
    except Exception as e:
        LOGGER.exception(f"[DB ERROR] Failed to create TOTP secret: {e}")
        return None

def verify_and_enable_totp(user_id: int, totp_code: str, secret: str) -> bool:
    """
    Verify TOTP code and enable 2FA for user if valid.
    Returns True on success, False on failure.
    """
    try:
        import pyotp
        
        # Verify code with grace window (30 seconds)
        totp = pyotp.TOTP(secret)
        if not totp.verify(totp_code, valid_window=1):
            return False
        
        # Code is valid, save secret and enable TOTP
        conn = DBConnection.get_connection()
        if not conn:
            return False
        
        return _persist_totp_secret(user_id, secret)
    except Exception as e:
        LOGGER.exception(f"[DB ERROR] Failed to enable TOTP: {e}")
        return False

def verify_totp_code(user_id: int, code: str) -> bool:
    """
    Verify TOTP code against user's stored secret.
    Returns True if code is valid, False otherwise.
    """
    try:
        import pyotp
        
        user = get_user_by_id(user_id)
        if not user:
            return False

        secret = _decrypt_totp_secret(user_id, user.get('totp_secret'))
        if not secret:
            return False

        # Verify code with grace window (30 seconds)
        totp = pyotp.TOTP(secret)
        return totp.verify(code, valid_window=1)
    except Exception as e:
        LOGGER.error(f"[DB ERROR] Failed to verify TOTP code: {e}")
        return False

def has_totp_enabled(user_id: int) -> bool:
    """Check if user has TOTP 2FA enabled."""
    try:
        user = get_user_by_id(user_id)
        return bool(user and user.get('totp_enabled'))
    except Exception:
        return False

def disable_totp(user_id: int) -> bool:
    """Disable TOTP 2FA for user."""
    try:
        conn = DBConnection.get_connection()
        if not conn:
            return False
        
        with conn:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    UPDATE users 
                    SET totp_secret = NULL, totp_enabled = false
                    WHERE id = %s
                    """,
                    (user_id,)
                )
        return True
    except Exception as e:
        LOGGER.error(f"[DB ERROR] Failed to disable TOTP: {e}")
        return False

def update_session_2fa_state(session_id: str, state_updates: Dict) -> bool:
    """Update session extra_data 2FA state. Example: {'2fa_pending': True, 'original_next': '/path'}"""
    try:
        conn = DBConnection.get_connection()
        if not conn:
            return False
        
        with conn:
            with conn.cursor() as cur:
                # Get current session
                cur.execute(
                    "SELECT extra_data FROM sessions WHERE id = %s AND expires_at > now()",
                    (session_id,)
                )
                result = cur.fetchone()
                if not result:
                    LOGGER.error(f"[DB ERROR] Session {session_id} not found or expired")
                    return False
                
                # Get extra_data from dict (psycopg2 auto-decodes JSONB to dict)
                extra_data = result.get('extra_data', {})
                if extra_data is None:
                    extra_data = {}
                
                # Update with new state
                extra_data.update(state_updates)
                
                # Save back - use Json wrapper for JSONB type
                cur.execute(
                    "UPDATE sessions SET extra_data = %s WHERE id = %s",
                    (psycopg2.extras.Json(extra_data), session_id)
                )
        return True
    except Exception as e:
        LOGGER.exception(f"[DB ERROR] Failed to update session 2FA state: {type(e).__name__}: {str(e)}")
        return False

def get_session_2fa_state(session_id: str) -> Optional[Dict]:
    """Get session 2FA state from extra_data."""
    try:
        session = get_session(session_id)
        if not session:
            return None
        
        extra_data = session.get('extra_data', {})
        if extra_data is None:
            extra_data = {}
        
        return {
            "2fa_pending": extra_data.get('2fa_pending', False),
            "2fa_verified": extra_data.get('2fa_verified', False),
            "2fa_setup_pending": extra_data.get('2fa_setup_pending', False),
            "original_next": extra_data.get('original_next', ''),
            "temp_totp_secret": extra_data.get('temp_totp_secret', ''),
            "csrf_token": extra_data.get('csrf_token', '')
        }
    except Exception as e:
        LOGGER.exception(f"[DB ERROR] Failed to get session 2FA state: {type(e).__name__}: {str(e)}")
        return None

from __future__ import annotations

from typing import Dict, TYPE_CHECKING
from urllib.parse import parse_qs

from core.templates import (
    LOGIN_TEMPLATE,
    REGISTER_PENDING_TEMPLATE,
    REGISTER_TEMPLATE,
    USER_PANEL_TEMPLATE,
)
from db import (
    create_session,
    create_user,
    expire_session,
    get_user_by_username,
    has_totp_enabled,
    update_session_2fa_state,
    verify_password,
)

if TYPE_CHECKING:  # pragma: no cover - circular import guard
    from proxy import ProjectConfig, ProxyHandler


def _escape_attr(value: str) -> str:
    return value.replace("\"", "&quot;").replace("'", "&#39;") if value else ""


def _render_login_form(error: str = "", next_url: str = "") -> str:
    next_url_escaped = _escape_attr(next_url)
    if LOGIN_TEMPLATE:
        html = LOGIN_TEMPLATE.replace("{ERROR_MESSAGE}", error or "")
        return html.replace("{NEXT_URL}", next_url_escaped)
    return f"""<!DOCTYPE html>
<html lang=\"pl\">
<head><meta charset=\"utf-8\"><title>Logowanie</title></head>
<body>
    <form method=\"post\">
        <input type=\"hidden\" name=\"next\" value=\"{next_url_escaped}\" />
        <input type=\"text\" name=\"username\" placeholder=\"Nazwa użytkownika\" autofocus />
        <input type=\"password\" name=\"password\" placeholder=\"Hasło\" />
        <input type=\"submit\" value=\"Zaloguj\" />
    </form>
    <div style=\"color: #ff8080;\">{error if error else ''}</div>
</body>
</html>"""


def _render_register_form(error: str = "", next_url: str = "") -> str:
    next_url_escaped = _escape_attr(next_url)
    if REGISTER_TEMPLATE:
        html = REGISTER_TEMPLATE.replace("{ERROR_MESSAGE}", error or "")
        return html.replace("{NEXT_URL}", next_url_escaped)
    return f"""<!DOCTYPE html>
<html lang=\"pl\">
<head><meta charset=\"utf-8\"><title>Rejestracja</title></head>
<body>
    <form method=\"post\">
        <input type=\"hidden\" name=\"next\" value=\"{next_url_escaped}\" />
        <input type=\"text\" name=\"username\" placeholder=\"Nazwa użytkownika\" autofocus />
        <input type=\"email\" name=\"email\" placeholder=\"Adres e-mail\" />
        <input type=\"password\" name=\"password\" placeholder=\"Hasło\" />
        <input type=\"password\" name=\"password_confirm\" placeholder=\"Powtórz hasło\" />
        <input type=\"submit\" value=\"Zarejestruj\" />
    </form>
    <div style=\"color: #ff8080;\">{error if error else ''}</div>
</body>
</html>"""


def _render_register_pending() -> str:
    if REGISTER_PENDING_TEMPLATE:
        return REGISTER_PENDING_TEMPLATE
    return """<!DOCTYPE html>
<html lang=\"pl\">
<head><meta charset=\"utf-8\"><title>Konto oczekuje</title></head>
<body style=\"background:#050508;color:#f5f5f5;font-family:Arial;height:100vh;display:flex;align-items:center;justify-content:center;flex-direction:column;text-align:center;\">
    <h1>Dziękujemy za rejestrację</h1>
    <h2 style=\"font-size:64px;letter-spacing:0.3em;text-transform:uppercase;margin:20px 0;\">Oczekuje</h2>
    <p>Administrator musi aktywować Twoje konto zanim się zalogujesz.</p>
    <a href=\"/login\" style=\"color:#4ade80;text-decoration:none;margin-top:20px;\">Wróć do logowania</a>
</body>
</html>"""


def _render_user_panel(user: Dict, projects: Dict[str, 'ProjectConfig']) -> str:
    available = []
    for subdomain, proj in projects.items():
        if not proj.password:
            available.append(subdomain)
    projects_html = ''.join(
        f'<li><a href="https://{sub}.ppowicz.pl">→ {sub}</a></li>' for sub in available
    ) or '<li>Brak dostępu do projektów</li>'
    if USER_PANEL_TEMPLATE:
        return (
            USER_PANEL_TEMPLATE
            .replace("{USERNAME}", user['username'])
            .replace("{PROJECTS_HTML}", projects_html)
        )
    return f"""<!DOCTYPE html>
<html lang=\"pl\">
<head><meta charset=\"utf-8\"><title>Panel użytkownika</title></head>
<body>
    <h1>Witaj, {user['username']}!</h1>
    <h2>Twoje projekty:</h2>
    <ul>{projects_html}</ul>
    <a href=\"https://ppowicz.pl/logout\">Wyloguj się</a>
</body>
</html>"""


def _extract_next(handler: 'ProxyHandler') -> str:
    if "?" not in handler.path:
        return ""
    qs = handler.path.split("?", 1)[1]
    params = parse_qs(qs) if qs else {}
    return params.get("next", [""])[0]


def handle_login(
    handler: 'ProxyHandler',
    *,
    login_rate_limit_per_ip: int,
    login_rate_limit_per_user: int,
    login_rate_limit_window_seconds: int,
    pending_session_max_age: int,
) -> None:
    next_url = _extract_next(handler)
    if handler.command == "POST":
        content_length = int(handler.headers.get("Content-Length", "0") or "0")
        body = handler.rfile.read(content_length) if content_length > 0 else b""
        username = ""
        password = ""
        posted_next = ""
        try:
            data = parse_qs(body.decode("utf-8", errors="ignore"))
            username = data.get("username", [""])[0]
            password = data.get("password", [""])[0]
            posted_next = data.get("next", [""])[0]
        except Exception:
            pass

        ip_key = handler.client_address[0]
        if not handler._check_rate_limit(
            "login-ip",
            ip_key,
            login_rate_limit_per_ip,
            login_rate_limit_window_seconds,
            "Zbyt wiele prób logowania z tego adresu IP. Odczekaj chwilę.",
        ):
            return
        if username and not handler._check_rate_limit(
            "login-user",
            username.lower(),
            login_rate_limit_per_user,
            login_rate_limit_window_seconds,
            "Zbyt wiele prób logowania dla tego konta. Odczekaj chwilę.",
        ):
            return

        pending_user = get_user_by_username(username) if username else None
        if pending_user and not pending_user.get('is_active'):
            html = _render_login_form("Twoje konto czeka na zatwierdzenie przez administratora.", next_url)
            handler._send_html_response(200, html, is_error=False)
            return

        if username and password:
            user_id = verify_password(username, password)
            if user_id:
                session_id = create_session(
                    user_id,
                    handler.client_address[0],
                    handler.headers.get("User-Agent", ""),
                )
                if session_id:
                    final_next = posted_next or "/panel"
                    if has_totp_enabled(user_id):
                        update_session_2fa_state(session_id, {
                            "2fa_pending": True,
                            "original_next": final_next,
                        })
                        redirect_url = f"/login/2fa?next={final_next}"
                    else:
                        update_session_2fa_state(session_id, {
                            "2fa_setup_pending": True,
                            "original_next": final_next,
                        })
                        redirect_url = f"/login/setup-2fa?next={final_next}"
                    handler.send_response(303)
                    handler.send_header("Location", redirect_url)
                    handler._clear_cookie("session_id")
                    handler._set_cookie(
                        "pending_session",
                        session_id,
                        max_age=pending_session_max_age,
                        same_site="Strict",
                    )
                    handler.end_headers()
                    return

        html = _render_login_form("Nieprawidłowe dane logowania", next_url)
        handler._send_html_response(200, html, is_error=True, error_message="Nieprawidłowe dane logowania")
        return

    user = handler.get_session_user()
    if user:
        handler.send_response(302)
        handler.send_header("Location", "/panel")
        handler.end_headers()
        return

    html = _render_login_form("", next_url)
    handler._send_html_response(200, html, is_error=False)


def handle_register(
    handler: 'ProxyHandler',
    *,
    register_rate_limit_per_ip: int,
    register_rate_limit_window_seconds: int,
) -> None:
    next_url = _extract_next(handler)
    if handler.command == "POST":
        content_length = int(handler.headers.get("Content-Length", "0") or "0")
        body = handler.rfile.read(content_length) if content_length > 0 else b""
        username = email = password = confirm = ""
        try:
            data = parse_qs(body.decode("utf-8", errors="ignore"))
            username = data.get("username", [""])[0].strip()
            email = data.get("email", [""])[0].strip()
            password = data.get("password", [""])[0]
            confirm = data.get("password_confirm", [""])[0]
        except Exception:
            pass

        ip_key = handler.client_address[0]
        if not handler._check_rate_limit(
            "register-ip",
            ip_key,
            register_rate_limit_per_ip,
            register_rate_limit_window_seconds,
            "Zbyt wiele prób rejestracji z tego adresu IP. Spróbuj ponownie później.",
        ):
            return

        error = ""
        if not username or len(username) < 3:
            error = "Nazwa użytkownika musi mieć co najmniej 3 znaki."
        elif not email or "@" not in email:
            error = "Podaj poprawny adres e-mail."
        elif not password or len(password) < 8:
            error = "Hasło musi mieć co najmniej 8 znaków."
        elif password != confirm:
            error = "Hasła nie są takie same."

        if error:
            html = _render_register_form(error, next_url)
            handler._send_html_response(200, html, is_error=True, error_message=error)
            return

        user_id = create_user(username, email, password)
        if not user_id:
            html = _render_register_form("Nazwa użytkownika lub email jest już zajęty.", next_url)
            handler._send_html_response(200, html, is_error=True, error_message="Nazwa użytkownika lub email jest już zajęty.")
            return

        html = _render_register_pending()
        handler._send_html_response(200, html, is_error=False)
        return

    user = handler.get_session_user()
    if user:
        handler.send_response(302)
        handler.send_header("Location", "/panel")
        handler.end_headers()
        return

    html = _render_register_form("", next_url)
    handler._send_html_response(200, html, is_error=False)


def handle_user_panel(handler: 'ProxyHandler', projects: Dict[str, 'ProjectConfig']) -> None:
    user = handler.get_session_user()
    if not user:
        next_param = "next=https://ppowicz.pl/panel"
        handler.send_response(302)
        handler.send_header("Location", f"https://ppowicz.pl/login?{next_param}")
        handler.end_headers()
        return

    html = _render_user_panel(user, projects)
    handler._send_html_response(200, html, is_error=False)


def handle_logout(handler: 'ProxyHandler') -> None:
    session_id = handler._get_pending_or_active_session_id()
    if session_id:
        expire_session(session_id)
    handler.send_response(302)
    handler.send_header("Location", "https://ppowicz.pl/login")
    handler._clear_cookie("session_id")
    handler._clear_cookie("pending_session")
    handler.end_headers()

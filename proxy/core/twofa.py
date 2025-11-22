import base64
from io import BytesIO
from typing import Optional, TYPE_CHECKING
from urllib.parse import parse_qs

from core.logging import get_logger
from core.templates import TWO_FA_CHALLENGE_TEMPLATE, TWO_FA_SETUP_TEMPLATE
from db import (
    create_totp_secret,
    get_session,
    get_session_2fa_state,
    get_user_by_id,
    update_session_2fa_state,
    verify_and_enable_totp,
    verify_totp_code,
)

LOGGER = get_logger("proxy.2fa")

if TYPE_CHECKING:  # pragma: no cover - circular import guard
    from proxy import ProxyHandler


DEFAULT_RATE_LIMIT_MESSAGE = "Zbyt wiele nieudanych prób kodu 2FA. Spróbuj ponownie później."


def _escape_attr(value: str) -> str:
    return value.replace("\"", "&quot;").replace("'", "&#39;") if value else ""


def _extract_next(path: str) -> str:
    if "?" not in path:
        return ""
    qs = path.split("?", 1)[1]
    params = parse_qs(qs) if qs else {}
    return params.get("next", [""])[0]


def _render_2fa_setup_form(
    error: str = "",
    next_url: str = "",
    qr_data_uri: str = "",
    secret: str = "",
) -> str:
    next_url_escaped = _escape_attr(next_url)
    if TWO_FA_SETUP_TEMPLATE:
        html = TWO_FA_SETUP_TEMPLATE.replace("{NEXT_URL}", next_url_escaped)
        html = html.replace("{ERROR_MESSAGE}", f'<div class="error">{error}</div>' if error else "")
        html = html.replace("{QR_CODE}", f'<img src="{qr_data_uri}" alt="QR Code">' if qr_data_uri else "")
        html = html.replace("{SECRET_KEY}", secret or "")
        return html

    return f"""<!DOCTYPE html>
<html lang=\"pl\">
<head>
    <meta charset=\"utf-8\">
    <title>Konfiguracja 2FA</title>
    <style>
        body {{ font-family: Arial, sans-serif; padding: 40px; }}
        .container {{ max-width: 600px; margin: 0 auto; }}
        .error {{ color: #ff8080; margin-bottom: 20px; }}
        .qr-code {{ margin: 20px 0; text-align: center; }}
        .qr-code img {{ max-width: 300px; }}
        .secret {{ background: #f0f0f0; padding: 10px; margin: 20px 0; font-family: monospace; word-break: break-all; }}
        .form-group {{ margin: 20px 0; }}
        input {{ padding: 10px; margin: 5px 0; width: 100%; box-sizing: border-box; }}
        button {{ padding: 10px 20px; margin-right: 10px; cursor: pointer; }}
    </style>
</head>
<body>
    <div class=\"container\">
        <h1>Konfiguracja uwierzytelniania dwuetapowego</h1>
        {f'<div class=\"error\">{error}</div>' if error else ''}
        <p>Aby włączyć uwierzytelnianie dwuetapowe, zeskanuj kod QR za pomocą aplikacji takiej jak Google Authenticator lub Microsoft Authenticator.</p>
        {'<div class=\"qr-code\"><img src="' + qr_data_uri + '" alt="QR Code"></div>' if qr_data_uri else ''}
        {'<div><p><strong>Jeśli nie możesz zeskanować kodu QR, wpisz ręcznie:</strong></p><div class=\"secret\">' + secret + '</div></div>' if secret else ''}
        <form method=\"post\">
            <input type=\"hidden\" name=\"next\" value=\"{next_url_escaped}\" />
            <div class=\"form-group\">
                <label>Wpisz 6-cyfrowy kod z aplikacji:</label>
                <input type=\"text\" name=\"code\" placeholder=\"000000\" maxlength=\"6\" autofocus required />
            </div>
            <div>
                <button type=\"submit\">Aktywuj 2FA</button>
                <a href=\"/login/skip-2fa-setup\"><button type=\"button\">Pomiń na razie</button></a>
            </div>
        </form>
    </div>
</body>
</html>"""


def _render_2fa_challenge_form(error: str = "", next_url: str = "") -> str:
    next_url_escaped = _escape_attr(next_url)
    if TWO_FA_CHALLENGE_TEMPLATE:
        html = TWO_FA_CHALLENGE_TEMPLATE.replace("{NEXT_URL}", next_url_escaped)
        html = html.replace("{ERROR_MESSAGE}", f'<div class="error">{error}</div>' if error else "")
        return html

    return f"""<!DOCTYPE html>
<html lang=\"pl\">
<head>
    <meta charset=\"utf-8\">
    <title>Weryfikacja 2FA</title>
    <style>
        body {{ font-family: Arial, sans-serif; padding: 40px; }}
        .container {{ max-width: 600px; margin: 0 auto; }}
        .error {{ color: #ff8080; margin-bottom: 20px; }}
        .form-group {{ margin: 20px 0; }}
        input {{ padding: 10px; margin: 5px 0; width: 100%; box-sizing: border-box; }}
        button {{ padding: 10px 20px; cursor: pointer; }}
    </style>
</head>
<body>
    <div class=\"container\">
        <h1>Weryfikacja uwierzytelniania dwuetapowego</h1>
        {f'<div class=\"error\">{error}</div>' if error else ''}
        <p>Wpisz 6-cyfrowy kod z aplikacji do uwierzytelniania:</p>
        <form method=\"post\">
            <input type=\"hidden\" name=\"next\" value=\"{next_url_escaped}\" />
            <div class=\"form-group\">
                <input type=\"text\" name=\"code\" placeholder=\"000000\" maxlength=\"6\" autofocus required />
            </div>
            <button type=\"submit\">Weryfikuj</button>
        </form>
    </div>
</body>
</html>"""


def _generate_qr_from_secret(user_id: int, secret: str) -> str:
    if not secret:
        return ""
    try:
        import pyotp
        import qrcode

        user = get_user_by_id(user_id)
        if not user:
            return ""

        totp = pyotp.TOTP(secret)
        uri = totp.provisioning_uri(name=user['username'], issuer_name='ppowicz.pl')
        qr = qrcode.QRCode(version=1, box_size=10, border=5)
        qr.add_data(uri)
        qr.make(fit=True)

        img = qr.make_image(fill_color="white", back_color="transparent")
        buffered = BytesIO()
        img.save(buffered, format="PNG")
        img_data = base64.b64encode(buffered.getvalue()).decode()
        return f"data:image/png;base64,{img_data}"
    except Exception as exc:  # pragma: no cover - defensive logging
        LOGGER.error("[2FA] Failed to regenerate QR: %s", exc)
        return ""


def handle_2fa_setup(
    handler: 'ProxyHandler',
    *,
    rate_limit_per_session: int,
    rate_limit_window_seconds: int,
    rate_limit_message: str = DEFAULT_RATE_LIMIT_MESSAGE,
) -> None:
    next_url = _extract_next(handler.path)
    session_id = handler._get_pending_or_active_session_id()
    session = get_session(session_id) if session_id else None

    if not session:
        handler.send_response(302)
        handler.send_header("Location", "https://ppowicz.pl/login")
        handler.end_headers()
        return

    user_id = session.get('user_id')
    state = get_session_2fa_state(session_id)
    if not state or not state.get('2fa_setup_pending'):
        handler.send_response(302)
        handler.send_header("Location", "/panel")
        handler.end_headers()
        return

    if handler.command == "POST":
        content_length = int(handler.headers.get("Content-Length", "0") or "0")
        body = handler.rfile.read(content_length) if content_length > 0 else b""
        totp_code = ""
        try:
            data = parse_qs(body.decode("utf-8", errors="ignore"))
            totp_code = data.get("code", [""])[0]
        except Exception:
            totp_code = ""

        if not handler._check_rate_limit(
            "2fa-session",
            session_id,
            rate_limit_per_session,
            rate_limit_window_seconds,
            rate_limit_message,
        ):
            return

        if totp_code and state.get('temp_totp_secret'):
            if verify_and_enable_totp(user_id, totp_code, state['temp_totp_secret']):
                update_session_2fa_state(session_id, {
                    "2fa_pending": False,
                    "2fa_verified": True,
                    "2fa_setup_pending": False,
                    "temp_totp_secret": "",
                })
                redirect_url = state.get('original_next', "/panel")
                handler.send_response(302)
                handler.send_header("Location", redirect_url)
                handler._promote_session(session_id)
                handler.end_headers()
                return

            qr_data_uri = _generate_qr_from_secret(user_id, state.get('temp_totp_secret', ''))
            html = _render_2fa_setup_form("Nieprawidłowy kod", next_url, qr_data_uri, state.get('temp_totp_secret', ''))
            handler._send_html_response(200, html, is_error=True, error_message="Nieprawidłowy kod")
            return

        html = _render_2fa_setup_form("Brak kodu weryfikacyjnego", next_url, "", state.get('temp_totp_secret', ''))
        handler._send_html_response(200, html, is_error=True, error_message="Brak kodu weryfikacyjnego")
        return

    temp_secret = state.get('temp_totp_secret', '')
    if not temp_secret:
        secret_result = create_totp_secret(user_id)
        if not secret_result:
            html = _render_2fa_setup_form("Nie udało się wygenerować kodu QR", next_url, "", "")
            handler._send_html_response(200, html, is_error=True, error_message="Nie udało się wygenerować kodu QR")
            return
        temp_secret, qr_data_uri = secret_result
        update_session_2fa_state(session_id, {"temp_totp_secret": temp_secret})
    else:
        qr_data_uri = _generate_qr_from_secret(user_id, temp_secret)

    html = _render_2fa_setup_form("", next_url, qr_data_uri, temp_secret)
    handler._send_html_response(200, html, is_error=False)


def handle_2fa_challenge(handler: 'ProxyHandler') -> None:
    next_url = _extract_next(handler.path)
    session_id = handler._get_pending_or_active_session_id()
    session = get_session(session_id) if session_id else None

    if not session:
        handler.send_response(302)
        handler.send_header("Location", "https://ppowicz.pl/login")
        handler.end_headers()
        return

    user_id = session.get('user_id')
    state = get_session_2fa_state(session_id)
    if not state or not state.get('2fa_pending'):
        handler.send_response(302)
        handler.send_header("Location", "/panel")
        handler.end_headers()
        return

    if handler.command == "POST":
        content_length = int(handler.headers.get("Content-Length", "0") or "0")
        body = handler.rfile.read(content_length) if content_length > 0 else b""
        totp_code = ""
        try:
            data = parse_qs(body.decode("utf-8", errors="ignore"))
            totp_code = data.get("code", [""])[0]
        except Exception:
            totp_code = ""

        if totp_code and verify_totp_code(user_id, totp_code):
            update_session_2fa_state(session_id, {
                "2fa_pending": False,
                "2fa_verified": True,
            })
            redirect_url = state.get('original_next', "/panel")
            handler.send_response(302)
            handler.send_header("Location", redirect_url)
            handler._promote_session(session_id)
            handler.end_headers()
            return

        html = _render_2fa_challenge_form("Nieprawidłowy kod", next_url)
        handler._send_html_response(200, html, is_error=True, error_message="Nieprawidłowy kod")
        return

    html = _render_2fa_challenge_form("", next_url)
    handler._send_html_response(200, html, is_error=False)


def handle_skip_2fa_setup(handler: 'ProxyHandler') -> None:
    session_id = handler._get_pending_or_active_session_id()
    session = get_session(session_id) if session_id else None

    if not session:
        handler.send_response(302)
        handler.send_header("Location", "https://ppowicz.pl/login")
        handler.end_headers()
        return

    state = get_session_2fa_state(session_id)
    if not state or not state.get('2fa_setup_pending'):
        handler.send_response(302)
        handler.send_header("Location", "/panel")
        handler.end_headers()
        return

    update_session_2fa_state(session_id, {
        "2fa_setup_pending": False,
        "2fa_verified": True,
    })
    redirect_url = state.get('original_next', "/panel")
    handler.send_response(302)
    handler.send_header("Location", redirect_url)
    handler._promote_session(session_id)
    handler.end_headers()

import http.client
import json
import time
from typing import Any, Callable, Dict, Mapping
from urllib.parse import parse_qs

from core.templates import ADMIN_PAGE_TEMPLATES, ADMIN_ROUTE_TO_TEMPLATE
from db import (
    DBConnection,
    assign_permission_to_role,
    assign_role_to_user,
    bulk_assign_roles_to_user,
    create_permission,
    create_role,
    deassign_permission_from_role,
    deassign_role_from_user,
    delete_http_logs,
    delete_user,
    disable_totp,
    get_all_permissions,
    get_all_roles,
    get_all_users,
    get_http_log_status_breakdown,
    get_http_log_summary,
    get_http_log_timeline,
    get_recent_http_errors,
    get_recent_http_logs,
    get_role_permissions,
    get_table_columns,
    get_table_rows,
    get_top_http_paths,
    get_top_http_subdomains,
    get_user_roles,
    update_role,
    update_table_row,
    update_user,
    user_is_admin,
)


def _parse_query(qs: str) -> Dict[str, str]:
    if not qs:
        return {}
    return {k: v[0] for k, v in parse_qs(qs).items() if v}


def _read_json_body(handler: Any) -> Dict[str, Any]:
    length = int(handler.headers.get('Content-Length', '0') or '0')
    body = handler.rfile.read(length) if length > 0 else b''
    if not body:
        return {}
    try:
        return json.loads(body.decode('utf-8') or '{}')
    except Exception:
        return {}


def render_admin_panel(user: Dict[str, Any], page_key: str) -> str:
    template = ADMIN_PAGE_TEMPLATES.get(page_key) or ""
    if not template:
        return "<html><body><h1>Admin panel</h1><p>Template not loaded</p></body></html>"
    return template.replace("{ADMIN_USERNAME}", user['username'])


def handle_admin_panel(handler: Any) -> None:
    user = handler.get_session_user()
    if not user:
        next_param = "next=https://admin.ppowicz.pl"
        handler.send_response(302)
        handler.send_header("Location", f"https://ppowicz.pl/login?{next_param}")
        handler.end_headers()
        return

    if not user_is_admin(user['id']):
        handler.send_error_page("401")
        return

    path_only = handler.path.split('?', 1)[0] if '?' in handler.path else handler.path
    path_only = path_only or '/'
    if path_only != '/' and path_only.endswith('/'):
        path_only = path_only.rstrip('/')
    page_key = ADMIN_ROUTE_TO_TEMPLATE.get(path_only)
    if not page_key:
        handler.send_error_page("404")
        return

    html = render_admin_panel(user, page_key)
    handler._send_html_response(200, html, is_error=False)


def handle_admin_api(
    handler: Any,
    *,
    log_error: Callable[..., None],
    get_dashboard_metrics: Callable[[], Dict[str, Any]],
    projects: Mapping[str, Any],
) -> None:
    user = handler.get_session_user()
    if not user:
        handler.send_response(302)
        handler.send_header("Location", "https://ppowicz.pl/login")
        handler.end_headers()
        return
    if not user_is_admin(user['id']):
        handler.send_error_page('401')
        return

    path = handler.path[len('/api/') :]
    path_only = path.split('?', 1)[0]
    qs = ''
    if '?' in path:
        qs = path.split('?', 1)[1]

    try:
        if handler.command == 'GET' and path_only == 'logs':
            params = _parse_query(qs)
            limit = int(params.get('limit', 200)) if params.get('limit') else 200
            rows = get_recent_http_logs(limit)
            return handler.send_json(rows)

        if handler.command == 'GET' and path_only == 'logs/analytics':
            params = _parse_query(qs)
            window_minutes = int(params.get('minutes', 1440)) if params.get('minutes') else 1440
            bucket_minutes = int(params.get('bucket_minutes', max(5, window_minutes // 24 or 5)))
            top_limit = int(params.get('top_limit', 5)) if params.get('top_limit') else 5
            timeline_points = int(params.get('points', 60)) if params.get('points') else 60
            analytics = {
                'summary': get_http_log_summary(window_minutes),
                'status_breakdown': get_http_log_status_breakdown(window_minutes),
                'timeline': get_http_log_timeline(window_minutes, bucket_minutes, timeline_points),
                'top_subdomains': get_top_http_subdomains(window_minutes, top_limit),
                'top_paths': get_top_http_paths(window_minutes, top_limit),
                'recent_errors': get_recent_http_errors(top_limit * 2),
            }
            return handler.send_json(analytics)

        if handler.command == 'POST' and path_only == 'logs/delete':
            data = _read_json_body(handler)
            log_ids = data.get('log_ids') or []
            removed = delete_http_logs(log_ids)
            return handler.send_json({'removed': removed})

        if handler.command == 'GET' and path_only.startswith('db/'):
            parts = path_only.split('/')
            if len(parts) == 2 and parts[1] == 'tables':
                conn = DBConnection.get_connection()
                tables = []
                if conn:
                    try:
                        with conn:
                            with conn.cursor() as cur:
                                cur.execute(
                                    "SELECT table_name FROM information_schema.tables "
                                    "WHERE table_schema='public' AND table_type='BASE TABLE' ORDER BY table_name"
                                )
                                rows = cur.fetchall() or []
                                tables = [r['table_name'] for r in rows]
                    except Exception:
                        tables = []
                    finally:
                        conn.close()
                return handler.send_json(tables)

            table = parts[1]
            params = _parse_query(qs)
            limit = int(params.get('limit', 200)) if params.get('limit') else 200
            cols = get_table_columns(table)
            rows = get_table_rows(table, limit)
            return handler.send_json({'columns': cols, 'rows': rows})

        if handler.command == 'POST' and path_only.startswith('db/') and path_only.endswith('/update'):
            table = path_only.split('/')[1]
            data = _read_json_body(handler)
            ok = update_table_row(
                table,
                data.get('pk_name'),
                data.get('pk_value'),
                data.get('column'),
                data.get('value'),
            )
            return handler.send_json({'ok': bool(ok)})

        if handler.command == 'GET' and path_only == 'users':
            users = get_all_users()
            for u in users:
                u['roles'] = [r['id'] for r in get_user_roles(u['id'])]
            return handler.send_json(users)

        if handler.command == 'GET' and path_only == 'roles':
            return handler.send_json(get_all_roles())

        if handler.command == 'GET' and path_only == 'permissions':
            return handler.send_json(get_all_permissions())

        if handler.command == 'POST' and path_only == 'users/assign_role':
            data = _read_json_body(handler)
            ok = assign_role_to_user(data.get('user_id'), data.get('role_id'))
            return handler.send_json({'ok': bool(ok)})

        if handler.command == 'POST' and path_only == 'users/set_active':
            data = _read_json_body(handler)
            user_id = data.get('user_id')
            is_active = data.get('is_active')
            if user_id is None or is_active is None:
                return handler.send_json({'ok': False})
            active_flag = bool(is_active) if isinstance(is_active, bool) else str(is_active).lower() in ('1', 'true', 'yes')
            ok = update_user(user_id, is_active=active_flag)
            return handler.send_json({'ok': bool(ok)})

        if handler.command == 'POST' and path_only == 'users/delete':
            data = _read_json_body(handler)
            target_id = data.get('user_id')
            if target_id is None:
                return handler.send_json({'ok': False, 'error': 'missing_user_id'}, status=400)
            try:
                target_id = int(target_id)
            except (TypeError, ValueError):
                return handler.send_json({'ok': False, 'error': 'invalid_user_id'}, status=400)
            if target_id == user['id']:
                return handler.send_json({'ok': False, 'error': 'cannot_delete_self'}, status=400)
            ok = delete_user(target_id)
            return handler.send_json({'ok': bool(ok)})

        if handler.command == 'POST' and path_only == 'users/deassign_role':
            data = _read_json_body(handler)
            ok = deassign_role_from_user(data.get('user_id'), data.get('role_id'))
            return handler.send_json({'ok': bool(ok)})

        if handler.command == 'POST' and path_only == 'users/disable-2fa':
            data = _read_json_body(handler)
            target_id = data.get('user_id')
            if target_id:
                ok = disable_totp(target_id)
                return handler.send_json({'ok': bool(ok)})
            return handler.send_json({'ok': False})

        if handler.command == 'GET' and path_only == 'dashboard/metrics':
            return handler.send_json(get_dashboard_metrics())

        if handler.command == 'GET' and path_only == 'projects/status':
            results = []
            for subdomain, proj in projects.items():
                status = 'down'
                rt = None
                try:
                    conn = http.client.HTTPConnection('127.0.0.1', proj.port, timeout=2)
                    t0 = time.time()
                    conn.request('GET', '/')
                    resp = conn.getresponse()
                    resp.read(64)
                    t1 = time.time()
                    rt = int((t1 - t0) * 1000)
                    status = 'ok' if resp.status < 500 else 'error'
                    conn.close()
                except Exception:
                    status = 'down'
                results.append({'subdomain': subdomain, 'status': status, 'response_time_ms': rt})
            return handler.send_json(results)

        if handler.command == 'POST' and path_only == 'roles':
            data = _read_json_body(handler)
            role_id = create_role(data.get('name', ''), data.get('description', ''))
            return handler.send_json({'ok': bool(role_id), 'id': role_id})

        if handler.command == 'POST' and path_only.startswith('roles/') and path_only.endswith('/update'):
            role_id = int(path_only.split('/')[1])
            data = _read_json_body(handler)
            ok = update_role(role_id, data.get('name'), data.get('description'))
            return handler.send_json({'ok': ok})

        if handler.command == 'POST' and path_only.startswith('roles/') and path_only.endswith('/permissions'):
            parts = path_only.split('/')
            role_id = int(parts[1])
            data = _read_json_body(handler)
            perm_id = data.get('permission_id')
            action = data.get('action', 'assign')
            if action == 'assign':
                ok = assign_permission_to_role(role_id, perm_id)
            else:
                ok = deassign_permission_from_role(role_id, perm_id)
            return handler.send_json({'ok': ok})

        if handler.command == 'GET' and path_only.startswith('roles/') and path_only.endswith('/permissions'):
            role_id = int(path_only.split('/')[1])
            perms = get_role_permissions(role_id)
            return handler.send_json(perms)

        if handler.command == 'POST' and path_only == 'permissions':
            data = _read_json_body(handler)
            perm_id = create_permission(data.get('code', ''), data.get('description', ''))
            return handler.send_json({'ok': bool(perm_id), 'id': perm_id})

        if handler.command == 'POST' and path_only == 'users/update':
            data = _read_json_body(handler)
            ok = update_user(
                data.get('user_id'),
                username=data.get('username'),
                email=data.get('email'),
                is_active=data.get('is_active'),
                password=data.get('password'),
            )
            return handler.send_json({'ok': ok})

        if handler.command == 'POST' and path_only.startswith('users/') and path_only.endswith('/roles'):
            user_id = int(path_only.split('/')[1])
            data = _read_json_body(handler)
            role_ids = data.get('role_ids', [])
            ok = bulk_assign_roles_to_user(user_id, role_ids)
            return handler.send_json({'ok': ok})

    except Exception:
        log_error('[ADMIN API] Exception while handling request', exc_info=True)
        return handler.send_json({'error': 'internal'}, status=500)

    return handler.send_json({'error': 'not_found'}, status=404)

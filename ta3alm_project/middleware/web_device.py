"""ta3alm_project.middleware.web_device
Extracted from ta3alm_project/middleware.py.
"""

from django.shortcuts import (
    render,
    redirect,
)
from django.http import JsonResponse
from django.contrib.auth import logout
from django.conf import settings as django_settings


class WebDeviceSecurityMiddleware:
    """
    يطبّق نفس معايير الأمان وبصمة الأجهزة (fp_v1) وحدود الأجهزة وإدارة الجلسات على موقع الويب
    بالكامل بالتوازي مع تطبيق الأندرويد، كما يضيف ترويسات الحماية الأمنية لاستجابات الويب.
    """
    SKIP_PREFIXES = (
        '/api/',
        '/teacher/api/',
        '/static/',
        '/media/',
        '/admin/',
        '/admin-panel/',
        '/.well-known/',
        '/i18n/',
        '/robots.txt',
        '/sitemap.xml',
    )
    EXEMPT_PATHS = (
        '/devices/',
        '/verify-email/',
        '/accounts/logout/',
        '/banned/',
        '/privacy/',
        '/privacy-policy/',
        '/terms/',
    )

    def __init__(self, get_response):
        self.get_response = get_response

    def _strip_lang_prefix(self, path: str) -> str:
        if path.startswith('/ar/') or path.startswith('/en/'):
            return path[3:]
        return path

    def _apply_security_headers(self, request, response):
        response.setdefault('X-Content-Type-Options', 'nosniff')
        response.setdefault('Referrer-Policy', 'strict-origin-when-cross-origin')
        response.setdefault('Permissions-Policy', 'camera=(), microphone=(), geolocation=()')

        cookie_id = getattr(request, '_web_set_cookie_id', None)
        if cookie_id:
            from api_v1.device_security_service import WEB_COOKIE_NAME, WEB_COOKIE_SALT
            response.set_signed_cookie(
                WEB_COOKIE_NAME,
                cookie_id,
                salt=WEB_COOKIE_SALT,
                max_age=365 * 24 * 60 * 60,
                httponly=True,
                secure=bool(getattr(django_settings, 'SESSION_COOKIE_SECURE', not getattr(django_settings, 'DEBUG', False))),
                samesite='Lax',
            )
        return response

    def __call__(self, request):
        path_no_lang = self._strip_lang_prefix(request.path)
        if any(request.path.startswith(p) or path_no_lang.startswith(p) for p in self.SKIP_PREFIXES):
            return self.get_response(request)

        from api_v1.device_security_service import (
            build_web_device_info,
            check_device_allowed,
            evaluate_boot_security_gate,
            get_or_create_web_installation_id,
            register_or_update_device,
            verify_web_device_live_consistency,
        )
        from api_v1.models import DeviceSession

        user = getattr(request, 'user', None)
        is_admin = bool(
            user is not None
            and user.is_authenticated
            and (getattr(user, 'is_superuser', False) or getattr(user, 'role', '') == 'admin')
        )
        is_json_req = bool(
            (request.content_type and 'application/json' in request.content_type)
            or request.headers.get('X-Requested-With') == 'XMLHttpRequest'
        )
        installation_id = get_or_create_web_installation_id(request)

        # فحص بوابة البداية للويب للجميع (بما في ذلك الزوار قبل تسجيل الدخول)
        if not is_admin:
            try:
                boot_gate = evaluate_boot_security_gate(
                    request,
                    user=user if (user is not None and user.is_authenticated) else None,
                )
            except Exception:
                boot_gate = {'boot_allowed': True}
            if not boot_gate.get('boot_allowed'):
                gate_code = boot_gate.get('code') or 'BOOT_SECURITY_BLOCKED'
                allow_maintenance_login = (
                    gate_code == 'MAINTENANCE_MODE'
                    and bool(boot_gate.get('can_admin_login'))
                    and (path_no_lang.startswith('/accounts/login/') or path_no_lang.startswith('/accounts/logout/'))
                )
                if not allow_maintenance_login:
                    if user is not None and user.is_authenticated and gate_code == 'DEVICE_BLOCKED':
                        request.session.pop('web_device_registered_id', None)
                        request.session.pop('web_device_session_uuid', None)
                        logout(request)
                    http_st = 503 if gate_code == 'MAINTENANCE_MODE' else 403
                    if is_json_req:
                        return self._apply_security_headers(
                            request,
                            JsonResponse(
                                {
                                    'ok': False,
                                    'code': gate_code,
                                    'error': boot_gate.get('message', ''),
                                    'hardware_id': boot_gate.get('hardware_id', ''),
                                },
                                status=http_st,
                            ),
                        )
                    resp = render(
                        request,
                        'core/security_boot_gate.html',
                        {'gate': boot_gate, 'installation_id': installation_id},
                        status=http_st,
                    )
                    return self._apply_security_headers(request, resp)

        if (
            user is not None
            and user.is_authenticated
            and not is_admin
            and not getattr(user, 'is_banned', False)
        ):
            is_exempt = any(path_no_lang.startswith(p) for p in self.EXEMPT_PATHS)

            if request.session.get('web_device_registered_id') != installation_id:
                if not request.session.session_key:
                    request.session.save()
                result = register_or_update_device(
                    request=request,
                    user=user,
                    installation_id=installation_id,
                    device_info=build_web_device_info(request),
                    token_jti=f"web:{request.session.session_key or installation_id[:24]}",
                )
                if result.get('allowed'):
                    request.session['web_device_registered_id'] = installation_id
                    request.session['web_device_session_uuid'] = result.get('session_uuid', '')
                    request.session.pop('web_device_limit_error', None)
                else:
                    code = result.get('code')
                    if code == 'DEVICE_BLOCKED':
                        request.session.pop('web_device_registered_id', None)
                        request.session.pop('web_device_session_uuid', None)
                        logout(request)
                        if is_json_req:
                            return self._apply_security_headers(request, JsonResponse({'ok': False, 'code': code, 'error': result.get('error', '')}, status=403))
                        gate = {
                            'boot_allowed': False,
                            'code': 'DEVICE_BLOCKED',
                            'title': 'هذا الجهاز محظور من استخدام المنصة',
                            'message': result.get('error') or 'تم حظر هذا الجهاز من قِبل إدارة المنصة.',
                            'hardware_id': result.get('hardware_id', ''),
                        }
                        return self._apply_security_headers(
                            request,
                            render(request, 'core/security_boot_gate.html', {'gate': gate, 'installation_id': installation_id}, status=403),
                        )
                    elif code == 'WEB_FINGERPRINT_MISMATCH':
                        request.session.pop('web_device_registered_id', None)
                        request.session.pop('web_device_session_uuid', None)
                        logout(request)
                        if is_json_req:
                            return self._apply_security_headers(request, JsonResponse({'ok': False, 'code': code, 'error': result.get('error', '')}, status=403))
                        return self._apply_security_headers(request, redirect('account_login'))
                    else:
                        request.session['web_device_limit_error'] = result.get('error')
                        if is_json_req:
                            return self._apply_security_headers(request, JsonResponse({'ok': False, 'code': code, 'error': result.get('error', '')}, status=403))
                        if not is_exempt:
                            return self._apply_security_headers(request, redirect('web_trusted_devices'))
            else:
                live_ok, live_code, live_err = verify_web_device_live_consistency(request, user, installation_id)
                if not live_ok:
                    allowed, code, err = False, live_code, live_err
                else:
                    allowed, code, err = check_device_allowed(user, installation_id, request=request)
                sess_uuid = request.session.get('web_device_session_uuid')
                session_revoked_remotely = False
                if sess_uuid:
                    try:
                        session_revoked_remotely = DeviceSession.objects.filter(
                            session_uuid=sess_uuid,
                            status__in=('revoked', 'logged_out'),
                        ).exists()
                    except Exception:
                        session_revoked_remotely = False

                if session_revoked_remotely or (not allowed and code in ('DEVICE_REVOKED', 'WEB_FINGERPRINT_MISMATCH')):
                    request.session.pop('web_device_registered_id', None)
                    request.session.pop('web_device_session_uuid', None)
                    logout(request)
                    if is_json_req:
                        return self._apply_security_headers(
                            request,
                            JsonResponse({'ok': False, 'code': code or 'SESSION_REVOKED', 'error': err or ''}, status=403),
                        )
                    return self._apply_security_headers(request, redirect('account_login'))

                if not allowed:
                    if code == 'DEVICE_BLOCKED':
                        request.session.pop('web_device_registered_id', None)
                        request.session.pop('web_device_session_uuid', None)
                        logout(request)
                        if is_json_req:
                            return self._apply_security_headers(request, JsonResponse({'ok': False, 'code': code, 'error': err or ''}, status=403))
                        gate = {
                            'boot_allowed': False,
                            'code': 'DEVICE_BLOCKED',
                            'title': 'هذا الجهاز محظور من استخدام المنصة',
                            'message': err or 'تم حظر هذا الجهاز من قِبل إدارة المنصة.',
                            'hardware_id': '',
                        }
                        return self._apply_security_headers(
                            request,
                            render(request, 'core/security_boot_gate.html', {'gate': gate, 'installation_id': installation_id}, status=403),
                        )
                    request.session['web_device_limit_error'] = err
                    if is_json_req:
                        return self._apply_security_headers(request, JsonResponse({'ok': False, 'code': code, 'error': err or ''}, status=403))
                    if not is_exempt:
                        return self._apply_security_headers(request, redirect('web_trusted_devices'))

        response = self.get_response(request)
        return self._apply_security_headers(request, response)

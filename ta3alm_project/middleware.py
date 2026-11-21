"""
ta3alm_project/middleware.py — Middleware المخصص للمنصة
"""
from django.shortcuts import render, redirect
from django.urls import reverse, resolve, Resolver404
from django.http import Http404, JsonResponse
from rest_framework.authtoken.models import Token
from django.contrib.auth import login, logout
from django.conf import settings as django_settings
from core.models import SiteSetting


class SubdomainAdminMiddleware:
    """
    يعترض الطلبات القادمة على النطاق الفرعي admin.* ويُعيد
    توجيهها لـ dashboard_admin URLs دون أي تغيير في الرابط الظاهر.

    محلياً  : admin.localhost:8000  أو  admin.127.0.0.1
    إنتاج   : admin.ta3alm.online
    """

    def __init__(self, get_response):
        self.get_response = get_response

    def _is_admin_subdomain(self, host):
        """True إذا كان الـ host يبدأ بـ admin."""
        # أزِل رقم المنفذ لو موجود  (admin.localhost:8000 → admin.localhost)
        hostname = host.split(':')[0].lower()
        return hostname.startswith('admin.')

    def __call__(self, request):
        host = request.META.get('HTTP_HOST', '')

        if self._is_admin_subdomain(host):
            # أعِد كتابة المسار ليصل لـ dashboard_admin عبر prefix /admin-panel/
            original_path = request.path_info

            # تجنُّب إعادة الكتابة لو المسار أصلاً يحمل الـ prefix
            if not original_path.startswith('/admin-panel/'):
                # الصفحة الجذر → لوحة التحكم مباشرة
                if original_path in ('/', ''):
                    new_path = '/admin-panel/'
                else:
                    new_path = '/admin-panel' + original_path

                request.path_info = new_path
                request.path = new_path
                request.META['PATH_INFO'] = new_path

        return self.get_response(request)


class TokenAuthMiddleware:
    """
    يسمح بتسجيل الدخول عبر Token في Header أو Query Parameter.
    
    ⚠️ تحذير أمني: Auth Token في URL يُحفظ في Logs وBrowser History.
    الاستخدام المُفضَّل: Authorization: Token <key> في الـ Header.
    القيم في URL للتوافق مع Flutter Mobile App فقط.
    """
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        if not request.user.is_authenticated:
            # أولاً: ابحث في Authorization Header (الأكثر أماناً)
            auth_header = request.META.get('HTTP_AUTHORIZATION', '')
            token_key = None

            if auth_header.startswith('Token '):
                token_key = auth_header.split(' ', 1)[1].strip()
            else:
                # ثانياً: fallback لـ Query Parameter (للتوافق مع المحتوى القديم)
                token_key = request.GET.get('auth_token')

            if token_key:
                try:
                    token = Token.objects.select_related('user').get(key=token_key)
                    if token.user.is_active and not getattr(token.user, 'is_banned', False):
                        login(
                            request,
                            token.user,
                            backend='django.contrib.auth.backends.ModelBackend',
                        )
                except Token.DoesNotExist:
                    pass

        return self.get_response(request)


class BanMiddleware:
    """
    يمنع المستخدمين المحظورين من الوصول لأي صفحة.
    """
    EXEMPT_PATHS = None  # سيُحسب عند أول استخدام

    def __init__(self, get_response):
        self.get_response = get_response

    def _get_exempt_paths(self):
        if self.EXEMPT_PATHS is None:
            BanMiddleware.EXEMPT_PATHS = {
                reverse('account_logout'),
                reverse('banned_page'),
            }
        return self.EXEMPT_PATHS

    def __call__(self, request):
        # استثناء الـ API endpoints
        if request.path.startswith(('/api/', '/teacher/api/')):
            return self.get_response(request)

        if request.user.is_authenticated and request.user.is_banned:
            exempt = self._get_exempt_paths()
            if request.path not in exempt:
                return redirect('banned_page')

        return self.get_response(request)


class MaintenanceMiddleware:
    """
    يُظهر صفحة الصيانة لغير المشرفين عند تفعيل وضع الصيانة.
    """
    ALLOWED_PREFIXES = ('/admin/', '/admin-panel/', '/accounts/', '/static/', '/media/', '/.well-known/')

    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        # استثناء الـ API endpoints
        if request.path.startswith(('/api/', '/teacher/api/')):
            return self.get_response(request)

        # التعامل مع بادئة اللغة (مثال: /ar/admin/)
        path = request.path
        if path.startswith('/ar/') or path.startswith('/en/'):
            path = path[3:]

        # الصفحات المسموح بها دائماً
        if any(path.startswith(p) for p in self.ALLOWED_PREFIXES):
            return self.get_response(request)

        try:
            settings = SiteSetting.load()
            is_maintenance = settings.is_maintenance_mode
        except Exception:
            is_maintenance = False

        if is_maintenance and not (request.user.is_authenticated and request.user.is_superuser):
            return render(request, 'core/maintenance.html', status=503)

        return self.get_response(request)


class EmailVerificationMiddleware:
    """
    يمنع أي حساب ويب مسجل دخول ولم يُؤكد بالـ OTP/البريد الإلكتروني من الدخول لأي صفحة
    في المنصة (ما عدا مسارات التأكيد وتسجيل الخروج والإدارة والملفات الثابتة).
    """
    ALLOWED_PREFIXES = (
        '/verify-email/',
        '/accounts/logout/',
        '/banned/',
        '/static/',
        '/media/',
        '/admin/',
        '/admin-panel/',
        '/i18n/',
        '/.well-known/',
    )

    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        if request.path.startswith(('/api/', '/teacher/api/')):
            return self.get_response(request)

        path = request.path
        if path.startswith('/ar/') or path.startswith('/en/'):
            path = path[3:]

        if any(path.startswith(prefix) for prefix in self.ALLOWED_PREFIXES):
            return self.get_response(request)

        user = getattr(request, 'user', None)
        if (
            user is not None
            and user.is_authenticated
            and not getattr(user, 'is_banned', False)
            and hasattr(user, 'requires_email_verification')
            and user.requires_email_verification()
        ):
            request.session['pending_verification_user_id'] = user.id
            return redirect('verify_email_page')

        return self.get_response(request)


class AppVersionEnforcementMiddleware:
    """
    يمنع نسخ تطبيق الأندرويد القديمة (أقل من الحد المطلوب في SiteSetting) من استخدام الـ API
    ويعيد استجابة 426 Upgrade Required مع بيانات التحديث الإجباري ورابط APK.
    """
    EXEMPT_API_PREFIXES = (
        '/api/v1/public/metadata/',
        '/api/v1/public/app-version/',
        '/api/v1/public/app-update/download/',
        '/api/v1/schema/',
        '/api/v1/docs/',
    )

    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        if not request.path.startswith('/api/v1/'):
            return self.get_response(request)

        if any(request.path.startswith(prefix) for prefix in self.EXEMPT_API_PREFIXES):
            return self.get_response(request)

        raw_build = str(request.META.get('HTTP_X_APP_BUILD', '')).strip()
        if not raw_build or not raw_build.isdigit():
            return self.get_response(request)

        client_build = int(raw_build)
        try:
            site_settings = SiteSetting.load()
            min_required = site_settings.get_effective_min_version_code()
        except Exception:
            return self.get_response(request)

        if client_build < min_required:
            payload = {
                'error': 'يتوفر تحديث إجباري جديد للتطبيق. يرجى تنزيل وتثبيت أحدث إصدار للمتابعة.',
                'code': 'APP_UPDATE_REQUIRED',
                'app_update': site_settings.build_app_update_payload(
                    request=request,
                    client_version_code=client_build,
                ),
            }
            return JsonResponse(payload, status=426)

        return self.get_response(request)


class ApiSecurityAndActivityAuditMiddleware:
    """
    مراقب الأمان الشامل لـ /api/v1/:
    1) منع الأجهزة المحظورة من استخدام الـ API.
    2) التحقق التشفيري من توقيع الطلبات (Anti-MITM / Anti-Replay) ومنع التلاعب عبر Burp / HttpCanary.
    3) تسجيل كافة الأنشطة والأحداث المهمة في سجل السلوك (DeviceActivity + UserSecurityProfile).
    """
    SKIP_SIGNATURE_PATHS = (
        '/api/v1/public/metadata/',
        '/api/v1/public/app-version/',
        '/api/v1/public/app-update/',
        '/api/v1/schema/',
        '/api/v1/docs/',
        '/api/v1/auth/google/callback/',
    )
    SKIP_BLOCK_CHECK_PATHS = (
        '/api/v1/auth/logout/',
        '/api/v1/public/app-version/',
        '/api/v1/public/app-update/',
        '/api/v1/security/events/report/',
    )
    SELF_LOGGED_PATHS = (
        '/api/v1/auth/login/',
        '/api/v1/auth/register/',
        '/api/v1/auth/logout/',
        '/api/v1/auth/refresh/',
        '/api/v1/auth/google/',
        '/api/v1/auth/one-time-login/',
        '/api/v1/auth/complete-profile/',
        '/api/v1/auth/change-password/',
        '/api/v1/auth/reset-password-nid/',
        '/api/v1/security/events/report/',
    )

    def __init__(self, get_response):
        self.get_response = get_response

    def _resolve_api_user(self, request):
        user = getattr(request, 'user', None)
        if user is not None and user.is_authenticated:
            return user
        auth_header = str(request.META.get('HTTP_AUTHORIZATION') or '').strip()
        if auth_header.lower().startswith('bearer '):
            raw_token = auth_header.split(' ', 1)[1].strip()
            if '.' in raw_token:
                try:
                    from django.contrib.auth import get_user_model
                    from api_v1.authentication import decode_jwt_token
                    payload = decode_jwt_token(raw_token, expected_type='access')
                    User = get_user_model()
                    return User.objects.filter(id=payload.get('user_id'), is_active=True).first()
                except Exception:
                    return None
        return None

    def _classify_activity(self, request) -> str | None:
        path = request.path
        method = request.method.upper()
        if method == 'GET':
            if '/watch' in path:
                return 'lecture_watch'
            if '/exam' in path:
                return 'exam_open'
            if '/wallet' in path or '/finance' in path:
                return 'finance_view'
            return None
        if '/join' in path:
            return 'group_join_request'
        if '/checkout' in path or '/pay' in path:
            return 'payment_action'
        if '/exam' in path:
            return 'exam_submit'
        if '/watch' in path:
            return 'lecture_unlock_or_watch'
        if '/admin/' in path:
            return 'admin_action'
        if '/security/' in path:
            return 'security_action'
        if '/teacher/' in path:
            return 'teacher_action'
        if '/assistant/' in path:
            return 'assistant_action'
        return f'api_{method.lower()}'

    def __call__(self, request):
        if not request.path.startswith('/api/v1/') or request.method == 'OPTIONS':
            return self.get_response(request)

        device_id = str(
            request.META.get('HTTP_X_DEVICE_ID')
            or request.META.get('HTTP_X_INSTALLATION_ID')
            or ''
        ).strip()
        resolved_user = self._resolve_api_user(request)

        # 1) رفض أي جهاز محظور إدارياً أو أمنياً
        if device_id and not any(request.path.startswith(p) for p in self.SKIP_BLOCK_CHECK_PATHS):
            try:
                from api_v1.device_security_service import get_active_device_block
                blk = get_active_device_block(device_id)
                if blk:
                    return JsonResponse(
                        {
                            'error': f'هذا الجهاز محظور من استخدام المنصة: {blk.reason}',
                            'code': 'DEVICE_BLOCKED',
                            'blocked': True,
                        },
                        status=403,
                    )
            except Exception:
                pass

        # 2) التحقق التشفيري من توقيع الطلب ومنع التعديل أو إعادة الإرسال (Burp / HttpCanary / MITM)
        if not any(request.path.startswith(p) for p in self.SKIP_SIGNATURE_PATHS):
            try:
                import sys
                from api_v1.security_engine import record_behavioral_activity, verify_client_request_signature
                from api_v1.device_security_service import record_security_event

                sig_res = verify_client_request_signature(request)
                is_test_run = 'test' in sys.argv
                if not sig_res.get('valid') and not (is_test_run and not sig_res.get('present')):
                    signal_tag = 'replay_attack' if sig_res.get('code') == 'REPLAY_ATTACK_DETECTED' else 'request_tamper'
                    record_security_event(
                        event_type=sig_res.get('code', 'INVALID_SIGNATURE').lower(),
                        severity='critical',
                        risk_score=95,
                        user=resolved_user,
                        installation_id=device_id,
                        request=request,
                        action_taken='blocked_request',
                        details={'reason': sig_res.get('reason'), 'path': request.path, 'method': request.method},
                    )
                    if resolved_user is not None:
                        record_behavioral_activity(
                            request=request,
                            user=resolved_user,
                            installation_id=device_id,
                            activity_type=sig_res.get('code', 'INVALID_SIGNATURE').lower(),
                            signal_tag=signal_tag,
                            risk_delta=90,
                            metadata={'path': request.path, 'method': request.method},
                        )
                    return JsonResponse(
                        {
                            'error': sig_res.get('reason') or 'فشل التحقق الأمني للطلب.',
                            'code': sig_res.get('code') or 'INVALID_REQUEST_SIGNATURE',
                        },
                        status=403,
                    )
            except Exception:
                pass

        response = self.get_response(request)

        # 3) تسجيل كافة الحركات والأفعال المهمة في سجل النشاط السلوكي
        if (
            resolved_user is not None
            and 200 <= getattr(response, 'status_code', 500) < 400
            and not any(request.path.startswith(p) for p in self.SELF_LOGGED_PATHS)
        ):
            activity_type = self._classify_activity(request)
            if activity_type:
                try:
                    from api_v1.security_engine import record_behavioral_activity
                    record_behavioral_activity(
                        request=request,
                        user=resolved_user,
                        installation_id=device_id,
                        activity_type=activity_type,
                        endpoint=request.path,
                        metadata={'method': request.method, 'status': response.status_code},
                    )
                except Exception:
                    pass

        return response


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

        user = getattr(request, 'user', None)
        if (
            user is not None
            and user.is_authenticated
            and not getattr(user, 'is_superuser', False)
            and getattr(user, 'role', '') != 'admin'
            and not getattr(user, 'is_banned', False)
        ):
            from api_v1.device_security_service import (
                build_web_device_info,
                check_device_allowed,
                get_or_create_web_installation_id,
                register_or_update_device,
                verify_web_device_live_consistency,
            )
            from api_v1.models import DeviceSession

            installation_id = get_or_create_web_installation_id(request)
            is_exempt = any(path_no_lang.startswith(p) for p in self.EXEMPT_PATHS)
            is_json_req = bool(
                (request.content_type and 'application/json' in request.content_type)
                or request.headers.get('X-Requested-With') == 'XMLHttpRequest'
            )

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
                            from django.http import JsonResponse
                            return self._apply_security_headers(request, JsonResponse({'ok': False, 'code': code, 'error': result.get('error', '')}, status=403))
                        if not path_no_lang.startswith('/banned/'):
                            return self._apply_security_headers(request, redirect('banned_page'))
                    elif code == 'WEB_FINGERPRINT_MISMATCH':
                        request.session.pop('web_device_registered_id', None)
                        request.session.pop('web_device_session_uuid', None)
                        logout(request)
                        if is_json_req:
                            from django.http import JsonResponse
                            return self._apply_security_headers(request, JsonResponse({'ok': False, 'code': code, 'error': result.get('error', '')}, status=403))
                        return self._apply_security_headers(request, redirect('account_login'))
                    else:
                        request.session['web_device_limit_error'] = result.get('error')
                        if is_json_req:
                            from django.http import JsonResponse
                            return self._apply_security_headers(request, JsonResponse({'ok': False, 'code': code, 'error': result.get('error', '')}, status=403))
                        if not is_exempt:
                            return self._apply_security_headers(request, redirect('web_trusted_devices'))
            else:
                live_ok, live_code, live_err = verify_web_device_live_consistency(request, user, installation_id)
                if not live_ok:
                    allowed, code, err = False, live_code, live_err
                else:
                    allowed, code, err = check_device_allowed(user, installation_id)
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
                        from django.http import JsonResponse
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
                            from django.http import JsonResponse
                            return self._apply_security_headers(request, JsonResponse({'ok': False, 'code': code, 'error': err or ''}, status=403))
                        return self._apply_security_headers(request, redirect('banned_page'))
                    request.session['web_device_limit_error'] = err
                    if is_json_req:
                        from django.http import JsonResponse
                        return self._apply_security_headers(request, JsonResponse({'ok': False, 'code': code, 'error': err or ''}, status=403))
                    if not is_exempt:
                        return self._apply_security_headers(request, redirect('web_trusted_devices'))

        response = self.get_response(request)
        return self._apply_security_headers(request, response)

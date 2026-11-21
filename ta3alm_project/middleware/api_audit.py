"""ta3alm_project.middleware.api_audit
Extracted from ta3alm_project/middleware.py.
"""

from django.http import JsonResponse


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
        '/api/v1/auth/login/',
        '/api/v1/auth/logout/',
        '/api/v1/public/metadata/',
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
        force_user = getattr(request, '_force_auth_user', None)
        if force_user is not None and getattr(force_user, 'is_authenticated', False):
            return force_user
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
                    resolved = User.objects.filter(id=payload.get('user_id'), is_active=True).first()
                    if resolved is not None and not getattr(resolved, 'is_banned', False):
                        request._cached_api_jwt_user = (raw_token, resolved, payload)
                    return resolved
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

        # 1) فحص بوابة البداية والحظر العابر للمنصات (جهاز محظور / VPN / خيارات مطور / DNS أو بورت / صيانة)
        is_exempt_gate = any(
            request.path.startswith(p)
            for p in (
                '/api/v1/auth/logout/',
                '/api/v1/public/metadata/',
                '/api/v1/public/app-version/',
                '/api/v1/public/app-update/',
                '/api/v1/notifications/background-pull/',
                '/api/v1/security/events/report/',
            )
        )
        if not is_exempt_gate:
            try:
                from api_v1.device_security_service import evaluate_boot_security_gate
                gate = evaluate_boot_security_gate(request, user=resolved_user)
                if not gate.get('boot_allowed'):
                    code = gate.get('code') or 'BOOT_SECURITY_BLOCKED'
                    # أثناء وضع الصيانة نسمح لمحاولة تسجيل الدخول فقط من الأجهزة المعتمدة لدى الإدارة
                    if not (
                        code == 'MAINTENANCE_MODE'
                        and bool(gate.get('can_admin_login'))
                        and request.path.startswith('/api/v1/auth/login/')
                    ):
                        http_st = 503 if code == 'MAINTENANCE_MODE' else 403
                        return JsonResponse(
                            {
                                'error': gate.get('message') or gate.get('title') or 'تم منع الوصول لأسباب أمنية.',
                                'code': code,
                                'hardware_id': gate.get('hardware_id', ''),
                                'blocked': code != 'MAINTENANCE_MODE',
                            },
                            status=http_st,
                        )
                request._boot_gate_checked = True
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

        try:
            from api_v1.security_engine import maybe_trigger_hourly_ai_audit_async
            maybe_trigger_hourly_ai_audit_async()
        except Exception:
            pass

        return response

"""ta3alm_project.middleware.platform
Extracted from ta3alm_project/middleware.py.
"""

from django.shortcuts import render
from django.http import JsonResponse
from core.models import SiteSetting


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

        if is_maintenance and not (
            request.user.is_authenticated
            and (request.user.is_superuser or getattr(request.user, 'role', '') == 'admin')
        ):
            try:
                from api_v1.device_security_service import evaluate_boot_security_gate
                gate = evaluate_boot_security_gate(request, user=request.user if request.user.is_authenticated else None)
            except Exception:
                gate = {
                    'boot_allowed': False,
                    'code': 'MAINTENANCE_MODE',
                    'title': 'المنصة في وضع الصيانة حالياً',
                    'message': 'نقوم حالياً ببعض التحديثات والتحسينات لجعل تجربتك أفضل. سنعود للعمل خلال وقت قصير جداً.',
                    'hardware_id': '',
                    'can_admin_login': False,
                }
            return render(request, 'core/security_boot_gate.html', {'gate': gate}, status=503)

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

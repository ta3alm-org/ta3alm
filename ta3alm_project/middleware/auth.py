"""ta3alm_project.middleware.auth
Extracted from ta3alm_project/middleware.py.
"""

from django.shortcuts import redirect
from django.urls import reverse
from rest_framework.authtoken.models import Token
from django.contrib.auth import login


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

"""api_v1.views.auth.google
Extracted from api_v1/views_auth.py.
"""

from datetime import timedelta
import random
import urllib.parse
import urllib.request
from django.contrib.auth import get_user_model
from django.db import transaction
from django.http import HttpResponse
from django.utils import timezone
from rest_framework import status
from rest_framework.permissions import AllowAny
from rest_framework.response import Response
from rest_framework.views import APIView
from accounts.models import OneTimeLoginLink
from api_v1.authentication import generate_jwt_pair
from api_v1.serializers import UserDetailSerializer
from api_v1.security_engine import record_behavioral_activity

from api_v1.services.auth_service import (
    _ensure_verification_otp_sent,
    _extract_installation_id,
    _handle_auth_device_registration,
    _verify_google_tokens,
    ensure_user_role_profile,
)

User = get_user_model()


class GoogleLoginAPIView(APIView):
    """
    تسجيل الدخول أو إنشاء حساب عبر Google (Native Flutter google_sign_in).
    يستقبل id_token أو access_token + role الاختياري (student | teacher | assistant).
    """
    permission_classes = [AllowAny]

    @transaction.atomic
    def post(self, request):
        id_token = str(request.data.get('id_token', '')).strip()
        access_token = str(request.data.get('access_token', '')).strip()
        role = str(request.data.get('role', 'student')).strip().lower()
        if role not in ('student', 'teacher', 'assistant'):
            role = 'student'

        if not id_token and not access_token:
            return Response(
                {'error': 'يرجى تمرير رمز مصادقة جوجل (id_token أو access_token).'},
                status=status.HTTP_400_BAD_REQUEST,
            )

        google_info = _verify_google_tokens(id_token=id_token, access_token=access_token)
        if not google_info or not google_info.get('email'):
            return Response(
                {'error': 'تعذر التحقق من حساب جوجل أو انتهت صلاحية الرمز.'},
                status=status.HTTP_401_UNAUTHORIZED,
            )

        email = google_info['email']
        user = User.objects.filter(email__iexact=email).order_by('id').first()
        is_new_user = False

        if not user:
            is_new_user = True
            base_username = email
            if User.objects.filter(username__iexact=base_username).exists():
                base_username = f"{email.split('@')[0]}_{random.randint(1000, 9999)}"
            user = User.objects.create(
                username=base_username,
                email=email,
                first_name=google_info.get('first_name') or email.split('@')[0],
                last_name=google_info.get('last_name') or '',
                role=role,
                is_active=True,
            )
            user.set_unusable_password()
            user.save()
            ensure_user_role_profile(user)

            # ربط الحساب بـ django-allauth SocialAccount إن وجد
            try:
                from allauth.socialaccount.models import SocialAccount
                if google_info.get('sub'):
                    SocialAccount.objects.get_or_create(
                        user=user,
                        provider='google',
                        uid=google_info['sub'],
                        defaults={'extra_data': google_info},
                    )
            except Exception:
                pass

        if user.is_banned:
            return Response(
                {
                    'error': 'حسابك محظور من قِبل إدارة المنصة.',
                    'is_banned': True,
                },
                status=status.HTTP_403_FORBIDDEN,
            )

        tokens = generate_jwt_pair(user)
        dev_allowed, dev_outcome = _handle_auth_device_registration(request, user, tokens)
        if not dev_allowed:
            err_status = 426 if (dev_outcome or {}).get('code') == 'APP_UPDATE_REQUIRED' else status.HTTP_403_FORBIDDEN
            return Response(dev_outcome, status=err_status)

        requires_verification, otp_sent, otp_err = _ensure_verification_otp_sent(request, user)
        record_behavioral_activity(
            request=request,
            user=user,
            installation_id=_extract_installation_id(request),
            activity_type='google_login_success',
            metadata={'role': user.role, 'is_new_user': is_new_user},
        )
        user_data = UserDetailSerializer(user, context={'request': request}).data
        payload = {
            'message': 'تم تسجيل الدخول عبر جوجل بنجاح!',
            'is_new_user': is_new_user,
            'requires_verification': requires_verification,
            'otp_sent': otp_sent,
            **tokens,
            'user': user_data,
        }
        if otp_err:
            payload['otp_warning'] = otp_err
        if dev_outcome is not None:
            payload['device_security'] = dev_outcome
        return Response(payload, status=status.HTTP_200_OK)


class GoogleMobileCallbackView(APIView):
    """
    جسر OAuth مساند: عند إتمام تسجيل الدخول عبر جوجل في المتصفح (/accounts/google/login/)،
    يُصدِر كود دخول فوري لمرة واحدة يمكن للتطبيق استلامه أو نسخه بضغطة زر.
    """
    permission_classes = [AllowAny]

    def get(self, request):
        if not request.user.is_authenticated:
            role = request.GET.get('role', 'student')
            if role in ('student', 'teacher', 'assistant'):
                request.session['selected_role'] = role
            next_url = urllib.parse.quote('/api/v1/auth/google/callback/')
            return HttpResponse(
                f'<html><head><meta http-equiv="refresh" content="0;url=/accounts/google/login/?next={next_url}"></head></html>'
            )

        user = request.user
        role_in_session = request.session.pop('selected_role', None)
        if role_in_session in ('student', 'teacher', 'assistant') and not user.custom_id:
            user.role = role_in_session
            user.save(update_fields=['role'])

        expires = timezone.now() + timedelta(minutes=15)
        link = OneTimeLoginLink.objects.create(user=user, expires_at=expires)
        token_str = str(link.token)

        html = f"""<!DOCTYPE html>
<html lang="ar" dir="rtl">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>تم تسجيل الدخول بنجاح | منصة تعلّم</title>
    <style>
        body {{ font-family: 'Segoe UI', Tahoma, sans-serif; background: #4a0000; color: #fff; display: flex; align-items: center; justify-content: center; min-height: 100vh; margin: 0; padding: 16px; }}
        .card {{ background: #fff; color: #222; border-radius: 20px; max-width: 440px; width: 100%; padding: 28px; text-align: center; box-shadow: 0 12px 32px rgba(0,0,0,0.35); }}
        .code-box {{ background: #f8f9fa; border: 2px dashed #800000; border-radius: 12px; padding: 14px; font-family: monospace; font-size: 15px; font-weight: bold; color: #800000; word-break: break-all; margin: 16px 0; }}
        .btn {{ display: block; width: 100%; background: #800000; color: #FFD700; border: none; padding: 14px; border-radius: 12px; font-size: 16px; font-weight: bold; cursor: pointer; text-decoration: none; margin-top: 10px; }}
    </style>
</head>
<body>
    <div class="card">
        <h2 style="color:#800000; margin-top:0;">تم التحقق من حساب Google بنجاح!</h2>
        <p>انسخ كود التفعيل الفوري التالي والصقه في شاشة تسجيل الدخول داخل تطبيق تعلّم:</p>
        <div class="code-box" id="tokenBox">{token_str}</div>
        <button class="btn" onclick="navigator.clipboard.writeText('{token_str}'); this.innerText='تم نسخ الكود بنجاح ✓';">نسخ كود الدخول للتطبيق</button>
    </div>
</body>
</html>"""
        return HttpResponse(html)

"""api_v1.views.auth.otp
Extracted from api_v1/views_auth.py.
"""

import re
import secrets
import uuid
from django.contrib.auth import get_user_model
from django.db import transaction
from rest_framework import status
from rest_framework.permissions import (
    AllowAny,
    IsAuthenticated,
)
from rest_framework.response import Response
from rest_framework.views import APIView
from accounts.email_verification import (
    issue_email_verification,
    send_verification_email,
)
from accounts.models import EmailVerification
from api_v1.serializers import UserDetailSerializer
from api_v1.security_engine import record_behavioral_activity

from api_v1.services.auth_service import _extract_installation_id

User = get_user_model()


class VerifyEmailOTPAPIView(APIView):
    """
    التحقق من حساب المستخدم عبر كود OTP المكون من 6 أرقام (يتطلب توكن الجلسة)
    أو عبر رابط/توكن التفعيل المباشر (UUID من البريد الإلكتروني).
    """
    permission_classes = [AllowAny]

    @transaction.atomic
    def post(self, request):
        raw_code = re.sub(r'\D', '', str(request.data.get('code', '') or ''))
        raw_token = str(request.data.get('token', '') or '').strip()

        if raw_token:
            uuid_match = re.search(
                r'[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}',
                raw_token,
            )
            token_str = uuid_match.group(0) if uuid_match else raw_token
            try:
                token_uuid = uuid.UUID(token_str)
            except ValueError:
                return Response(
                    {'error': 'صيغة رمز التفعيل غير صحيحة.', 'code': 'INVALID_TOKEN'},
                    status=status.HTTP_400_BAD_REQUEST,
                )
            verification = (
                EmailVerification.objects.select_for_update()
                .select_related('user')
                .filter(token=token_uuid)
                .first()
            )
            if not verification:
                return Response(
                    {'error': 'رابط التفعيل غير مطابق لهذا الحساب أو تم استبداله.', 'code': 'INVALID_TOKEN'},
                    status=status.HTTP_400_BAD_REQUEST,
                )
            if request.user.is_authenticated and verification.user_id != request.user.id:
                return Response(
                    {'error': 'رابط التفعيل لا يخص الحساب المسجل حالياً.', 'code': 'INVALID_TOKEN'},
                    status=status.HTTP_403_FORBIDDEN,
                )
            if not verification.is_verified and verification.is_expired():
                return Response(
                    {'error': 'انتهت صلاحية رابط التفعيل. يرجى طلب كود جديد.', 'code': 'OTP_EXPIRED'},
                    status=status.HTTP_400_BAD_REQUEST,
                )
            verification.mark_verified()
            target_user = verification.user
            target_user.refresh_from_db()
            record_behavioral_activity(
                request=request,
                user=target_user,
                installation_id=_extract_installation_id(request),
                activity_type='email_verified',
                metadata={'method': 'token_link'},
            )
            resp = {
                'message': 'تم تأكيد وتفعيل حسابك بنجاح!',
                'is_email_verified': True,
                'requires_verification': False,
                'email': target_user.email,
            }
            if request.user.is_authenticated:
                resp['user'] = UserDetailSerializer(target_user, context={'request': request}).data
            return Response(resp, status=status.HTTP_200_OK)

        if not request.user or not request.user.is_authenticated:
            return Response(
                {'error': 'يرجى تسجيل الدخول أولاً قبل إدخال كود التحقق.', 'code': 'AUTH_REQUIRED'},
                status=status.HTTP_401_UNAUTHORIZED,
            )

        user = request.user
        if not user.requires_email_verification():
            return Response(
                {
                    'message': 'الحساب مفعّل بالفعل.',
                    'is_email_verified': True,
                    'requires_verification': False,
                    'user': UserDetailSerializer(user, context={'request': request}).data,
                },
                status=status.HTTP_200_OK,
            )

        if len(raw_code) != 6:
            return Response(
                {'error': 'يرجى إدخال كود التحقق المكون من 6 أرقام.', 'code': 'INVALID_OTP'},
                status=status.HTTP_400_BAD_REQUEST,
            )
        verification = (
            EmailVerification.objects.select_for_update()
            .filter(user=user)
            .first()
        )
        if not verification or not verification.code:
            return Response(
                {'error': 'لم يتم إصدار كود تحقق بعد. اضغط على إعادة إرسال الكود.', 'code': 'OTP_NOT_ISSUED'},
                status=status.HTTP_400_BAD_REQUEST,
            )
        if verification.is_expired():
            return Response(
                {'error': 'انتهت صلاحية كود التحقق. اضغط على إعادة إرسال الكود.', 'code': 'OTP_EXPIRED'},
                status=status.HTTP_400_BAD_REQUEST,
            )
        if not secrets.compare_digest(raw_code, verification.code):
            return Response(
                {'error': 'كود التحقق غير صحيح. يرجى التأكد من الأرقام الستة.', 'code': 'INVALID_OTP'},
                status=status.HTTP_400_BAD_REQUEST,
            )
        verification.mark_verified()

        user.refresh_from_db()
        record_behavioral_activity(
            request=request,
            user=user,
            installation_id=_extract_installation_id(request),
            activity_type='email_verified',
            metadata={'method': 'otp_code'},
        )
        return Response(
            {
                'message': 'تم تأكيد وتفعيل حسابك بنجاح!',
                'is_email_verified': True,
                'requires_verification': False,
                'user': UserDetailSerializer(user, context={'request': request}).data,
            },
            status=status.HTTP_200_OK,
        )


class ResendEmailOTPAPIView(APIView):
    """
    إعادة إرسال كود التحقق OTP (6 أرقام) + رابط التفعيل المباشر مع دعم تحديث البريد للحسابات غير المفعلة.
    """
    permission_classes = [IsAuthenticated]

    @transaction.atomic
    def post(self, request):
        user = request.user
        if not user.requires_email_verification():
            return Response(
                {
                    'message': 'الحساب مفعّل بالفعل.',
                    'is_email_verified': True,
                    'requires_verification': False,
                    'user': UserDetailSerializer(user, context={'request': request}).data,
                },
                status=status.HTTP_200_OK,
            )

        new_email = str(request.data.get('email', '') or '').strip().lower()
        email_changed = False
        if new_email and new_email != (user.email or '').strip().lower():
            if '@' not in new_email or '.' not in new_email.split('@')[-1]:
                return Response(
                    {'error': 'يرجى إدخال بريد إلكتروني صحيح.'},
                    status=status.HTTP_400_BAD_REQUEST,
                )
            if User.objects.filter(email__iexact=new_email).exclude(pk=user.pk).exists():
                return Response(
                    {'error': 'هذا البريد الإلكتروني مستخدم بالفعل في حساب آخر.'},
                    status=status.HTTP_400_BAD_REQUEST,
                )
            old_email = (user.email or '').strip().lower()
            user.email = new_email
            update_fields = ['email']
            if (user.username or '').strip().lower() == old_email and not User.objects.filter(username__iexact=new_email).exclude(pk=user.pk).exists():
                user.username = new_email
                update_fields.append('username')
            user.save(update_fields=update_fields)
            email_changed = True

        if not user.email:
            return Response(
                {'error': 'يرجى إدخال بريد إلكتروني صحيح لتتمكن من استلام كود التفعيل.'},
                status=status.HTTP_400_BAD_REQUEST,
            )

        try:
            verification = user.email_verification
        except EmailVerification.DoesNotExist:
            verification = None

        if verification is not None and not email_changed:
            retry_after = verification.remaining_resend_seconds(cooldown_seconds=60)
            if retry_after > 0:
                return Response(
                    {
                        'error': f'يرجى الانتظار {retry_after} ثانية قبل إعادة إرسال الكود.',
                        'code': 'RESEND_COOLDOWN',
                        'retry_after': retry_after,
                    },
                    status=status.HTTP_429_TOO_MANY_REQUESTS,
                )

        verification = issue_email_verification(user, update_sent_time=True)
        sent, err_msg = send_verification_email(request, user, verification)
        if not sent:
            return Response(
                {
                    'error': err_msg or 'تعذر إرسال كود التحقق حالياً.',
                    'code': 'EMAIL_SEND_FAILED',
                    'retry_after': 60,
                },
                status=status.HTTP_503_SERVICE_UNAVAILABLE,
            )

        return Response(
            {
                'message': f'تم إرسال كود التحقق (6 أرقام) إلى {user.email}.',
                'email': user.email,
                'retry_after': 60,
                'user': UserDetailSerializer(user, context={'request': request}).data,
            },
            status=status.HTTP_200_OK,
        )

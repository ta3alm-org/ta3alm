"""api_v1.views.auth.login
Extracted from api_v1/views_auth.py.
"""

from datetime import timedelta
import re
import uuid
from django.contrib.auth import (
    authenticate,
    get_user_model,
)
from django.db import transaction
from django.db.models import Q
from django.utils import timezone
from rest_framework import status
from rest_framework.authtoken.models import Token
from rest_framework.permissions import (
    AllowAny,
    IsAuthenticated,
)
from rest_framework.response import Response
from rest_framework.views import APIView
from accounts.models import OneTimeLoginLink
from api_v1.authentication import (
    generate_jwt_pair,
    decode_jwt_token,
)
from api_v1.device_security_service import (
    extract_network_context,
    get_active_device_block,
    get_server_observed_ip,
    record_device_activity,
    record_security_event,
)
from api_v1.models import (
    DeviceActivity,
    DeviceSession,
    DeviceTrustStatus,
    PlaybackSession,
    RegisteredDevice,
)
from api_v1.serializers import UserDetailSerializer
from api_v1.security_engine import record_behavioral_activity

from api_v1.services.auth_service import (
    _ensure_verification_otp_sent,
    _extract_installation_id,
    _handle_auth_device_registration,
)

User = get_user_model()


class LoginAPIView(APIView):
    """
    تسجيل الدخول عبر البريد الإلكتروني أو رقم الهاتف أو اسم المستخدم أو الكود التعريفي (custom_id).
    يُعيد JWT (access + refresh) + DRF Token + بيانات المستخدم الكاملة.
    """
    permission_classes = [AllowAny]

    def post(self, request):
        identifier = (
            request.data.get('identifier')
            or request.data.get('email')
            or request.data.get('username')
            or request.data.get('phone')
            or ''
        ).strip()
        password = request.data.get('password', '')

        if not identifier or not password:
            return Response(
                {'error': 'يرجى إدخال البريد الإلكتروني/الهاتف/الكود وكلمة المرور.'},
                status=status.HTTP_400_BAD_REQUEST,
            )

        candidate = None
        user = authenticate(request, username=identifier, password=password)
        if not user:
            candidate = User.objects.filter(
                Q(email__iexact=identifier)
                | Q(phone=identifier)
                | Q(username__iexact=identifier)
                | Q(custom_id__iexact=identifier)
            ).order_by('id').first()
            if candidate and candidate.check_password(password) and candidate.is_active:
                user = candidate

        if not user:
            inst_id = _extract_installation_id(request)
            ip = get_server_observed_ip(request)
            record_behavioral_activity(
                request=request,
                user=candidate,
                installation_id=inst_id,
                activity_type='login_failed',
                risk_delta=10,
                metadata={'identifier': identifier, 'installation_id': inst_id},
            )
            recent_window = timezone.now() - timedelta(minutes=10)
            fail_q = Q(user=candidate) if candidate else Q()
            if ip:
                fail_q = (fail_q | Q(ip_address=ip)) if candidate else Q(ip_address=ip)
            fail_count = (
                DeviceActivity.objects.filter(
                    fail_q,
                    activity_type='login_failed',
                    created_at__gte=recent_window,
                ).count()
                if (candidate or ip)
                else 0
            )
            if fail_count >= 5:
                record_security_event(
                    event_type='excessive_login_attempts',
                    severity='medium',
                    risk_score=35,
                    user=candidate,
                    installation_id=inst_id,
                    request=request,
                    action_taken='monitored',
                    details={
                        'identifier': identifier,
                        'recent_failures_10m': fail_count,
                        'title': 'محاولات تسجيل دخول فاشلة متكررة',
                    },
                )
            return Response(
                {'error': 'بيانات الدخول غير صحيحة. تأكد من البريد/الهاتف وكلمة المرور.'},
                status=status.HTTP_401_UNAUTHORIZED,
            )

        if user.is_banned:
            return Response(
                {
                    'error': 'حسابك محظور من قِبل إدارة المنصة.',
                    'code': 'ACCOUNT_BANNED',
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
            activity_type='login_success',
            metadata={'role': user.role, 'identifier': identifier},
        )
        user_data = UserDetailSerializer(user, context={'request': request}).data
        payload = {
            **tokens,
            'requires_verification': requires_verification,
            'otp_sent': otp_sent,
            'user': user_data,
        }
        if otp_err:
            payload['otp_warning'] = otp_err
        if dev_outcome is not None:
            payload['device_security'] = dev_outcome
        return Response(payload, status=status.HTTP_200_OK)


class TokenRefreshAPIView(APIView):
    """تحديث Access Token باستخدام Refresh Token مع التحقق من حالة الجلسة والجهاز."""
    permission_classes = [AllowAny]

    def post(self, request):
        refresh_token = request.data.get('refresh', '')
        if not refresh_token:
            return Response({'error': 'حقل refresh مطلوب.'}, status=status.HTTP_400_BAD_REQUEST)

        payload = decode_jwt_token(refresh_token, expected_type='refresh')
        try:
            user = User.objects.get(id=payload.get('user_id'), is_active=True)
        except User.DoesNotExist:
            return Response({'error': 'المستخدم غير موجود.'}, status=status.HTTP_401_UNAUTHORIZED)

        if user.is_banned:
            return Response(
                {'error': 'الحساب محظور.', 'code': 'ACCOUNT_BANNED', 'is_banned': True},
                status=status.HTTP_403_FORBIDDEN,
            )

        inst_id = _extract_installation_id(request)
        refresh_jti = str(payload.get('jti') or '')

        if inst_id:
            active_block = get_active_device_block(inst_id)
            if active_block:
                return Response(
                    {'error': f'تم حظر هذا الجهاز: {active_block.reason}', 'code': 'DEVICE_BLOCKED'},
                    status=status.HTTP_403_FORBIDDEN,
                )

        if refresh_jti and DeviceSession.objects.filter(
            user=user,
            refresh_jti=refresh_jti,
            status__in=('revoked', 'logged_out'),
        ).exists():
            return Response(
                {'error': 'تم إنهاء جلسة هذا الجهاز. يرجى إعادة تسجيل الدخول.', 'code': 'SESSION_REVOKED'},
                status=status.HTTP_401_UNAUTHORIZED,
            )

        reg_dev = (
            RegisteredDevice.objects.filter(user=user, installation_id=inst_id).first()
            if inst_id
            else None
        )
        if reg_dev:
            if reg_dev.trust_status == DeviceTrustStatus.BLOCKED:
                return Response(
                    {'error': 'تم حظر هذا الجهاز من قِبل إدارة المنصة.', 'code': 'DEVICE_BLOCKED'},
                    status=status.HTTP_403_FORBIDDEN,
                )
            if not reg_dev.is_active or reg_dev.trust_status == DeviceTrustStatus.REVOKED:
                return Response(
                    {'error': 'تم إلغاء تفعيل هذا الجهاز. يرجى إعادة تسجيل الدخول.', 'code': 'DEVICE_REVOKED'},
                    status=status.HTTP_401_UNAUTHORIZED,
                )

        tokens = generate_jwt_pair(user)
        now = timezone.now()
        net_ctx = extract_network_context(request)

        sess_q = DeviceSession.objects.filter(user=user, status='active')
        if refresh_jti and sess_q.filter(refresh_jti=refresh_jti).exists():
            active_sess = sess_q.filter(refresh_jti=refresh_jti).order_by('-last_seen_at').first()
        elif inst_id:
            active_sess = sess_q.filter(installation_id=inst_id).order_by('-last_seen_at').first()
        else:
            active_sess = None

        if active_sess:
            active_sess.token_jti = tokens['access_jti']
            active_sess.refresh_jti = tokens['refresh_jti']
            active_sess.last_seen_at = now
            if net_ctx.get('ip_address'):
                active_sess.ip_address = net_ctx['ip_address']
            if net_ctx.get('country_code'):
                active_sess.country_code = net_ctx['country_code']
            active_sess.save(
                update_fields=['token_jti', 'refresh_jti', 'last_seen_at', 'ip_address', 'country_code']
            )
            if not reg_dev:
                reg_dev = active_sess.device

        record_device_activity(
            request=request,
            user=user,
            device=reg_dev,
            session=active_sess,
            activity_type='token_refresh',
            net_ctx=net_ctx,
            metadata={'installation_id': inst_id},
        )
        recent_refreshes = DeviceActivity.objects.filter(
            user=user,
            activity_type='token_refresh',
            created_at__gte=now - timedelta(minutes=5),
        ).count()
        if recent_refreshes > 10:
            record_security_event(
                event_type='unusual_token_refresh',
                severity='medium',
                risk_score=35,
                user=user,
                device=reg_dev,
                installation_id=inst_id,
                request=request,
                net_ctx=net_ctx,
                action_taken='monitored',
                details={'refreshes_in_5m': recent_refreshes},
            )

        return Response(tokens, status=status.HTTP_200_OK)


class LogoutAPIView(APIView):
    """تسجيل الخروج وإنهاء جلسة الجهاز الحالية وإلغاء DRF Token."""
    permission_classes = [IsAuthenticated]

    def post(self, request):
        now = timezone.now()
        inst_id = _extract_installation_id(request)
        access_jti = request.auth.get('jti', '') if isinstance(request.auth, dict) else ''

        sess_qs = DeviceSession.objects.filter(user=request.user, status='active')
        matched_q = Q()
        if access_jti:
            matched_q |= Q(token_jti=access_jti)
        if inst_id:
            matched_q |= Q(installation_id=inst_id)
        if access_jti or inst_id:
            sess_qs.filter(matched_q).update(
                status='logged_out',
                ended_at=now,
                revoked_reason='user_logout',
            )

        if inst_id:
            PlaybackSession.objects.filter(
                user=request.user,
                device_id=inst_id,
                status='active',
            ).update(status='ended', revoked_reason='user_logout', view_window_expires_at=now)
        from api_v1.video_security import clear_watch_window
        clear_watch_window(request.user, now=now)

        reg_dev = (
            RegisteredDevice.objects.filter(user=request.user, installation_id=inst_id).first()
            if inst_id
            else None
        )
        record_behavioral_activity(
            request=request,
            user=request.user,
            device=reg_dev,
            installation_id=inst_id,
            activity_type='logout',
            metadata={'installation_id': inst_id},
        )
        Token.objects.filter(user=request.user).delete()
        return Response({'message': 'تم تسجيل الخروج بنجاح.'}, status=status.HTTP_200_OK)


class OneTimeLoginAPIView(APIView):
    """
    تسجيل الدخول المباشر باستخدام رابط/كود الدخول المؤقت لمرة واحدة (OneTimeLoginLink)
    الذي ينشئه الأدمن أو جسر مصادقة الويب.
    """
    permission_classes = [AllowAny]

    @transaction.atomic
    def post(self, request):
        raw_input = str(request.data.get('token', '')).strip()
        if not raw_input:
            return Response(
                {'error': 'يرجى إدخال رابط أو كود الدخول المباشر.'},
                status=status.HTTP_400_BAD_REQUEST,
            )

        # استخراج UUID إذا قام المستخدم بلصق الرابط الكامل https://.../login/auto/<uuid>/
        uuid_match = re.search(
            r'[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}',
            raw_input,
        )
        token_str = uuid_match.group(0) if uuid_match else raw_input

        try:
            token_uuid = uuid.UUID(token_str)
        except ValueError:
            return Response(
                {'error': 'صيغة كود أو رابط الدخول غير صحيحة.'},
                status=status.HTTP_400_BAD_REQUEST,
            )

        link = OneTimeLoginLink.objects.select_for_update().select_related('user').filter(token=token_uuid).first()
        if not link or not link.is_valid():
            return Response(
                {'error': 'رابط الدخول غير صالح أو منتهي الصلاحية أو تم استخدامه مسبقاً.'},
                status=status.HTTP_401_UNAUTHORIZED,
            )

        user = link.user
        if user.is_banned:
            return Response(
                {'error': 'هذا الحساب محظور.', 'is_banned': True},
                status=status.HTTP_403_FORBIDDEN,
            )

        link.is_used = True
        link.save(update_fields=['is_used'])

        tokens = generate_jwt_pair(user)
        dev_allowed, dev_outcome = _handle_auth_device_registration(request, user, tokens)
        if not dev_allowed:
            link.is_used = False
            link.save(update_fields=['is_used'])
            err_status = 426 if (dev_outcome or {}).get('code') == 'APP_UPDATE_REQUIRED' else status.HTTP_403_FORBIDDEN
            return Response(dev_outcome, status=err_status)

        requires_verification, otp_sent, otp_err = _ensure_verification_otp_sent(request, user)
        record_behavioral_activity(
            request=request,
            user=user,
            installation_id=_extract_installation_id(request),
            activity_type='one_time_login_success',
            metadata={'role': user.role},
        )
        user_data = UserDetailSerializer(user, context={'request': request}).data
        payload = {
            'message': f'تم تسجيل الدخول بنجاح! مرحباً {user.first_name or user.username}',
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

"""
api_v1/views_auth.py
نقاط النهاية الخاصة بالمصادقة، التسجيل، استكمال الملف الشخصي، وتحديث التوكنات.
"""
from datetime import timedelta
import json
import random
import re
import secrets
import string
import urllib.parse
import urllib.request
import uuid

from django.contrib.auth import authenticate, get_user_model
from django.db import transaction
from django.db.models import Q
from django.http import HttpResponse
from django.utils import timezone
from rest_framework import status
from rest_framework.authtoken.models import Token
from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView

from accounts.email_verification import issue_email_verification, send_verification_email
from accounts.models import EmailVerification, StudentProfile, OneTimeLoginLink
from assistants.models import AssistantProfile
from core.models import SiteSetting, Subject
from teachers.models import TeacherProfile, SubscriptionPlan

from .authentication import generate_jwt_pair, decode_jwt_token
from .device_security_service import (
    extract_network_context,
    get_active_device_block,
    get_server_observed_ip,
    record_device_activity,
    record_security_event,
    register_or_update_device,
)
from .models import (
    DeviceActivity,
    DeviceSession,
    DeviceTrustStatus,
    PlaybackSession,
    RegisteredDevice,
)
from .permissions import IsNotBanned
from .serializers import UserDetailSerializer
from .security_engine import record_behavioral_activity

User = get_user_model()


def _resolve_subject_input(raw_subject):
    if raw_subject in (None, ''):
        return None
    raw_str = str(raw_subject).strip()
    if not raw_str:
        return None
    if raw_str.isdigit():
        return Subject.objects.filter(id=int(raw_str)).first()
    subj = (
        Subject.objects.filter(name__iexact=raw_str).first()
        or Subject.objects.filter(name__icontains=raw_str).first()
    )
    if subj is None:
        subj = Subject.objects.create(name=raw_str[:100])
    return subj


def ensure_user_role_profile(user) -> None:
    """يضمن وجود ملف الدور للطالب والمساعد عند الإنشاء (بينما يُنشأ ملف المعلم فقط بعد استكمال البيانات ثم مراجعة الإدارة)."""
    if not user or not getattr(user, 'pk', None):
        return
    if user.role == 'student':
        StudentProfile.objects.get_or_create(user=user, defaults={'parent_phone': ''})
    elif user.role == 'assistant':
        AssistantProfile.objects.get_or_create(user=user, defaults={'phone': user.phone or ''})


def _notify_admins_teacher_pending(teacher_profile) -> None:
    try:
        from core.notifications_service import notify_users_bulk
        admins = User.objects.filter(Q(is_superuser=True) | Q(role='admin'), is_active=True)
        teacher_name = teacher_profile.user.get_full_name() or teacher_profile.user.email or teacher_profile.user.username
        notify_users_bulk(
            admins,
            'طلب اعتماد معلم جديد',
            f'قام المعلم {teacher_name} بالتسجيل وهو بانتظار موافقة الإدارة للظهور للطلاب.',
            link='/admin-panel/users/',
        )
    except Exception:
        pass


def _extract_installation_id(request) -> str:
    return str(
        request.data.get('installation_id')
        or request.data.get('device_id')
        or request.META.get('HTTP_X_DEVICE_ID')
        or request.META.get('HTTP_X_INSTALLATION_ID')
        or ''
    ).strip()


def _ensure_verification_otp_sent(request, user, force_new: bool = False) -> tuple[bool, bool, str]:
    """
    يتحقق مما إذا كان المستخدم غير مؤكد، ويُصدر/يُرسل كود OTP من 6 أرقام تلقائياً إذا لزم الأمر.
    يعيد: (requires_verification, otp_sent_now, message_or_error)
    """
    if not hasattr(user, 'requires_email_verification') or not user.requires_email_verification():
        return False, False, ''

    try:
        verification = user.email_verification
    except EmailVerification.DoesNotExist:
        verification = None

    should_issue = (
        force_new
        or verification is None
        or not verification.code
        or verification.is_expired()
    )
    if should_issue:
        if verification is None or force_new or verification.can_resend(cooldown_seconds=60):
            verification = issue_email_verification(user, update_sent_time=True)
            if user.email:
                sent, err = send_verification_email(request, user, verification)
                return True, sent, err
            return True, False, 'يرجى إضافة بريد إلكتروني صحيح لتأكيد الحساب.'
    return True, False, ''


def _handle_auth_device_registration(request, user, tokens: dict) -> tuple[bool, dict | None]:
    """يسجّل/يحدّث الجهاز بعد نجاح المصادقة عند توفر installation_id دون كسر العملاء القدامى."""
    installation_id = _extract_installation_id(request)
    raw_info = request.data.get('device_info')
    device_info = raw_info if isinstance(raw_info, dict) else {}
    if not installation_id and not device_info:
        return True, None

    raw_build = str(
        device_info.get('app_build_number')
        or request.META.get('HTTP_X_APP_BUILD')
        or ''
    ).strip()
    if raw_build.isdigit():
        try:
            site_settings = SiteSetting.load()
            client_build = int(raw_build)
            if client_build < site_settings.get_effective_min_version_code():
                return False, {
                    'error': 'يتوفر تحديث إجباري جديد للتطبيق. يرجى تحديث التطبيق لأحدث إصدار للمتابعة.',
                    'code': 'APP_UPDATE_REQUIRED',
                    'app_update': site_settings.build_app_update_payload(
                        request=request,
                        client_version_code=client_build,
                    ),
                }
        except Exception:
            pass

    outcome = register_or_update_device(
        request=request,
        user=user,
        installation_id=installation_id,
        device_info=device_info,
        token_jti=tokens.get('access_jti', ''),
        refresh_jti=tokens.get('refresh_jti', ''),
    )
    clean_outcome = {k: v for k, v in outcome.items() if k not in ('device_obj', 'session_obj')}
    return bool(clean_outcome.get('allowed')), clean_outcome


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


class RegisterAPIView(APIView):
    """
    إنشاء حساب جديد (طالب، معلم، مساعد) وإصدار التوكن مباشرة.
    """
    permission_classes = [AllowAny]

    @transaction.atomic
    def post(self, request):
        full_name = str(request.data.get('full_name', '')).strip()
        email = str(request.data.get('email', '')).strip().lower()
        phone = str(request.data.get('phone', '')).strip()
        password = str(request.data.get('password', ''))
        confirm_password = str(request.data.get('confirm_password', password))
        role = str(request.data.get('role', 'student')).strip().lower()

        if role not in ('student', 'teacher', 'assistant'):
            return Response({'error': 'نوع الحساب غير صالح.'}, status=status.HTTP_400_BAD_REQUEST)

        if not full_name or not email or not phone or not password:
            return Response({'error': 'جميع الحقول الأساسية مطلوبة.'}, status=status.HTTP_400_BAD_REQUEST)

        if password != confirm_password:
            return Response({'error': 'كلمتا المرور غير متطابقتين.'}, status=status.HTTP_400_BAD_REQUEST)

        if len(password) < 6:
            return Response({'error': 'كلمة المرور يجب ألا تقل عن 6 أحرف.'}, status=status.HTTP_400_BAD_REQUEST)

        if not phone.isdigit() or len(phone) < 11:
            return Response({'error': 'رقم الهاتف يجب أن يتكون من 11 رقماً على الأقل.'}, status=status.HTTP_400_BAD_REQUEST)

        if User.objects.filter(email__iexact=email).exists():
            return Response({'error': 'هذا البريد الإلكتروني مستخدم بالفعل.'}, status=status.HTTP_400_BAD_REQUEST)

        if User.objects.filter(phone=phone).exists():
            return Response({'error': 'رقم الهاتف هذا مستخدم بالفعل.'}, status=status.HTTP_400_BAD_REQUEST)

        parts = full_name.split(' ', 1)
        first_name = parts[0]
        last_name = parts[1] if len(parts) > 1 else ''

        user = User.objects.create_user(
            username=email,
            email=email,
            password=password,
            phone=phone,
            role=role,
            first_name=first_name,
            last_name=last_name,
        )
        ensure_user_role_profile(user)

        tokens = generate_jwt_pair(user)
        dev_allowed, dev_outcome = _handle_auth_device_registration(request, user, tokens)
        if not dev_allowed:
            err_status = 426 if (dev_outcome or {}).get('code') == 'APP_UPDATE_REQUIRED' else status.HTTP_403_FORBIDDEN
            return Response(dev_outcome, status=err_status)

        requires_verification, otp_sent, otp_err = _ensure_verification_otp_sent(
            request,
            user,
            force_new=True,
        )
        record_behavioral_activity(
            request=request,
            user=user,
            installation_id=_extract_installation_id(request),
            activity_type='register_account',
            metadata={'role': user.role},
        )
        user_data = UserDetailSerializer(user, context={'request': request}).data
        payload = {
            'message': 'تم إنشاء الحساب بنجاح! يرجى إدخال كود التحقق (OTP) المرسل إلى بريدك الإلكتروني لتفعيل الحساب.',
            **tokens,
            'requires_verification': requires_verification,
            'otp_sent': otp_sent,
            'user': user_data,
        }
        if otp_err:
            payload['otp_warning'] = otp_err
        if dev_outcome is not None:
            payload['device_security'] = dev_outcome
        return Response(payload, status=status.HTTP_201_CREATED)


class CompleteProfileAPIView(APIView):
    """
    استكمال بيانات الملف الشخصي للطالب أو المعلم أو المساعد (مطابق تماماً لـ accounts.views.complete_profile).
    """
    permission_classes = [IsAuthenticated, IsNotBanned]

    @transaction.atomic
    def post(self, request):
        user = request.user
        if hasattr(user, 'requires_email_verification') and user.requires_email_verification():
            return Response(
                {
                    'error': 'يرجى تأكيد حسابك برمز التحقق (OTP) أولاً.',
                    'code': 'EMAIL_VERIFICATION_REQUIRED',
                    'requires_verification': True,
                },
                status=status.HTTP_403_FORBIDDEN,
            )
        full_name = str(request.data.get('full_name', '')).strip()
        national_id = str(request.data.get('national_id', user.national_id or '')).strip()
        phone = str(request.data.get('phone', user.phone or '')).strip()
        password = str(request.data.get('password', '')).strip()

        if not national_id or len(national_id) != 14 or not national_id.isdigit():
            return Response({'error': 'الرقم القومي يجب أن يكون 14 رقماً صحيحاً.'}, status=status.HTTP_400_BAD_REQUEST)

        if User.objects.filter(national_id=national_id).exclude(pk=user.pk).exists():
            return Response({'error': 'الرقم القومي مسجل لمستخدم آخر بالفعل.'}, status=status.HTTP_400_BAD_REQUEST)

        if not phone or not phone.isdigit() or len(phone) < 11:
            return Response({'error': 'رقم الهاتف يجب أن يتكون من 11 رقماً على الأقل.'}, status=status.HTTP_400_BAD_REQUEST)

        if User.objects.filter(phone=phone).exclude(pk=user.pk).exists():
            return Response({'error': 'رقم الهاتف مسجل لمستخدم آخر بالفعل.'}, status=status.HTTP_400_BAD_REQUEST)

        if full_name:
            parts = full_name.split(' ', 1)
            user.first_name = parts[0]
            user.last_name = parts[1] if len(parts) > 1 else ''

        req_role = str(request.data.get('role', '')).strip().lower()
        if req_role in ('student', 'teacher', 'assistant') and not user.custom_id and not user.is_superuser and user.role != 'admin':
            user.role = req_role

        user.national_id = national_id
        user.phone = phone

        if not user.custom_id:
            chars = string.ascii_uppercase + string.digits
            prefix = {'assistant': 'A', 'teacher': 'T', 'student': 'S'}.get(user.role, 'U')
            user.custom_id = prefix + ''.join(random.choices(chars, k=6))

        if password:
            if len(password) < 6:
                return Response({'error': 'كلمة المرور يجب ألا تقل عن 6 أحرف.'}, status=status.HTTP_400_BAD_REQUEST)
            user.set_password(password)

        user.save()

        pending_teacher_review = False
        if user.role == 'student':
            parent_phone = str(request.data.get('parent_phone', '')).strip()
            if not parent_phone or not parent_phone.isdigit() or len(parent_phone) < 11:
                return Response({'error': 'رقم هاتف ولي الأمر مطلوب ويجب أن يتكون من 11 رقماً.'}, status=status.HTTP_400_BAD_REQUEST)
            StudentProfile.objects.update_or_create(
                user=user,
                defaults={'parent_phone': parent_phone},
            )

        elif user.role == 'teacher':
            raw_subject = request.data.get('subject_id')
            if raw_subject in (None, ''):
                raw_subject = request.data.get('subject')
            bio = str(request.data.get('bio', '')).strip()
            if not raw_subject:
                return Response({'error': 'يرجى اختيار المادة التي تدرسها.'}, status=status.HTTP_400_BAD_REQUEST)
            subject = _resolve_subject_input(raw_subject)
            if subject is None:
                return Response({'error': 'المادة المختارة غير موجودة.'}, status=status.HTTP_404_NOT_FOUND)

            # لا يُمنح المعلم باقة أو ظهوراً مباشراً عند التسجيل؛ يظل قيد المراجعة حتى موافقة الإدارة
            tp, created = TeacherProfile.objects.get_or_create(
                user=user,
                defaults={
                    'bio': bio,
                    'subject': subject,
                    'is_approved': False,
                    'subscription_end_date': None,
                    'is_trial_used': False,
                    'current_plan': None,
                },
            )
            if not created:
                tp.bio = bio
                tp.subject = subject
                tp.save(update_fields=['bio', 'subject'])
            if not tp.is_approved:
                pending_teacher_review = True
                _notify_admins_teacher_pending(tp)

        elif user.role == 'assistant':
            AssistantProfile.objects.update_or_create(
                user=user,
                defaults={'phone': phone},
            )

        record_behavioral_activity(
            request=request,
            user=user,
            installation_id=_extract_installation_id(request),
            activity_type='complete_profile',
            metadata={'role': user.role, 'pending_teacher_review': pending_teacher_review},
        )
        msg = (
            'تم إرسال طلب انضمامك كمعلم بنجاح! حسابك الآن قيد المراجعة من قِبل الإدارة وسيتم تفعيله وإشعارك فور الموافقة.'
            if pending_teacher_review
            else f'تم استكمال البيانات بنجاح! أهلاً بك يا {user.first_name}'
        )
        return Response({
            'message': msg,
            'pending_teacher_review': pending_teacher_review,
            'user': UserDetailSerializer(user, context={'request': request}).data,
        }, status=status.HTTP_200_OK)


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
            return Response({'error': 'الحساب محظور.'}, status=status.HTTP_403_FORBIDDEN)

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
        from .video_security import clear_watch_window
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


class MeProfileAPIView(APIView):
    """جلب أو تحديث أو حذف حساب المستخدم الحالي."""
    permission_classes = [IsAuthenticated]

    def get(self, request):
        return Response(UserDetailSerializer(request.user, context={'request': request}).data)

    def post(self, request):
        return self.patch(request)

    @transaction.atomic
    def patch(self, request):
        user = request.user
        if 'first_name' in request.data:
            user.first_name = str(request.data['first_name']).strip()
        if 'last_name' in request.data:
            user.last_name = str(request.data['last_name']).strip()
        if 'phone' in request.data:
            new_phone = str(request.data['phone']).strip()
            if new_phone and User.objects.filter(phone=new_phone).exclude(pk=user.pk).exists():
                return Response({'error': 'رقم الهاتف مستخدم بالفعل.'}, status=status.HTTP_400_BAD_REQUEST)
            user.phone = new_phone
        user.save()

        if user.role == 'teacher' and hasattr(user, 'teacher_profile'):
            tp = user.teacher_profile
            if 'bio' in request.data:
                tp.bio = str(request.data['bio']).strip()
            if 'subject_id' in request.data or 'subject' in request.data:
                sid = request.data.get('subject_id')
                if sid in (None, ''):
                    sid = request.data.get('subject')
                if sid:
                    tp.subject = _resolve_subject_input(sid) or tp.subject
            uploaded_img = request.FILES.get('image') or request.FILES.get('avatar')
            if uploaded_img is not None:
                tp.image = uploaded_img
            elif str(request.data.get('remove_image', '')).lower() in ('1', 'true', 'yes'):
                tp.image = None
            tp.save()
        elif user.role == 'student' and hasattr(user, 'student_profile'):
            sp = user.student_profile
            if 'parent_phone' in request.data:
                sp.parent_phone = str(request.data['parent_phone']).strip()
                sp.save()
        elif user.role == 'assistant' and hasattr(user, 'assistant_profile'):
            ap = user.assistant_profile
            if 'phone' in request.data:
                ap.phone = str(request.data['phone']).strip()
                ap.save()

        record_behavioral_activity(
            request=request,
            user=user,
            installation_id=_extract_installation_id(request),
            activity_type='profile_updated',
            metadata={'role': user.role},
        )
        return Response({
            'message': 'تم تحديث البيانات بنجاح.',
            'user': UserDetailSerializer(user, context={'request': request}).data,
        })

    def delete(self, request):
        user = request.user
        if user.is_superuser:
            return Response({'error': 'لا يمكن حذف حساب المالك.'}, status=status.HTTP_400_BAD_REQUEST)
        record_behavioral_activity(
            request=request,
            user=user,
            installation_id=_extract_installation_id(request),
            activity_type='account_deleted',
            metadata={'email': user.email, 'role': user.role},
        )
        user.delete()
        return Response({'message': 'تم حذف الحساب نهائياً.'}, status=status.HTTP_200_OK)


class ChangePasswordAPIView(APIView):
    """تغيير كلمة المرور للمستخدم المسجل."""
    permission_classes = [IsAuthenticated]

    def post(self, request):
        old_password = request.data.get('old_password', '')
        new_password = request.data.get('new_password', '')
        if not old_password or not new_password:
            return Response({'error': 'يرجى إدخال كلمة المرور الحالية والجديدة.'}, status=status.HTTP_400_BAD_REQUEST)
        if not request.user.check_password(old_password):
            return Response({'error': 'كلمة المرور الحالية غير صحيحة.'}, status=status.HTTP_400_BAD_REQUEST)
        if len(new_password) < 6:
            return Response({'error': 'كلمة المرور الجديدة يجب ألا تقل عن 6 أحرف.'}, status=status.HTTP_400_BAD_REQUEST)
        request.user.set_password(new_password)
        request.user.save(update_fields=['password'])
        record_behavioral_activity(
            request=request,
            user=request.user,
            installation_id=_extract_installation_id(request),
            activity_type='password_changed',
        )
        return Response({'message': 'تم تغيير كلمة المرور بنجاح.'})


class ResetPasswordByNationalIdAPIView(APIView):
    """استعادة كلمة المرور عبر التحقق من رقم الهاتف + الرقم القومي (14 رقماً)."""
    permission_classes = [AllowAny]

    def post(self, request):
        phone = str(request.data.get('phone', '')).strip()
        national_id = re.sub(r'\D', '', str(request.data.get('national_id', '')))
        new_password = str(request.data.get('new_password', ''))

        if not phone or not national_id or not new_password:
            return Response({'error': 'يرجى إدخال رقم الهاتف والرقم القومي وكلمة المرور الجديدة.'}, status=status.HTTP_400_BAD_REQUEST)

        if len(new_password) < 6:
            return Response({'error': 'كلمة المرور الجديدة يجب ألا تقل عن 6 أحرف.'}, status=status.HTTP_400_BAD_REQUEST)

        user = User.objects.filter(phone=phone).first()
        if not user or not user.national_id or str(user.national_id) != national_id:
            return Response({'error': 'بيانات التحقق (رقم الهاتف أو الرقم القومي) غير صحيحة.'}, status=status.HTTP_400_BAD_REQUEST)

        user.set_password(new_password)
        user.save(update_fields=['password'])
        record_behavioral_activity(
            request=request,
            user=user,
            installation_id=_extract_installation_id(request),
            activity_type='password_reset_nid',
        )
        return Response({'message': 'تمت إعادة تعيين كلمة المرور بنجاح. يمكنك تسجيل الدخول الآن.'})


def _verify_google_tokens(id_token: str = '', access_token: str = '') -> dict | None:
    """
    يتحقق من صحة id_token أو access_token مع خوادم Google الرسمية
    ويعيد بيانات الحساب (email, given_name, family_name, sub).
    """
    if id_token:
        try:
            url = f"https://oauth2.googleapis.com/tokeninfo?id_token={urllib.parse.quote(id_token)}"
            req = urllib.request.Request(url, headers={'Accept': 'application/json'})
            with urllib.request.urlopen(req, timeout=8) as resp:
                data = json.loads(resp.read().decode('utf-8'))
                if data.get('email') and data.get('email_verified') in (True, 'true', '1'):
                    return {
                        'email': str(data['email']).strip().lower(),
                        'first_name': str(data.get('given_name') or data.get('name', '').split(' ')[0]).strip(),
                        'last_name': str(data.get('family_name') or '').strip(),
                        'sub': str(data.get('sub') or ''),
                    }
        except Exception:
            pass

    if access_token:
        try:
            url = "https://www.googleapis.com/oauth2/v3/userinfo"
            req = urllib.request.Request(
                url,
                headers={
                    'Authorization': f'Bearer {access_token}',
                    'Accept': 'application/json',
                },
            )
            with urllib.request.urlopen(req, timeout=8) as resp:
                data = json.loads(resp.read().decode('utf-8'))
                if data.get('email'):
                    return {
                        'email': str(data['email']).strip().lower(),
                        'first_name': str(data.get('given_name') or data.get('name', '').split(' ')[0]).strip(),
                        'last_name': str(data.get('family_name') or '').strip(),
                        'sub': str(data.get('sub') or ''),
                    }
        except Exception:
            pass

    return None


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




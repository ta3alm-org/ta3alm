"""
api_v1/views_security.py
نقاط النهاية الكاملة لإدارة الأجهزة، الجلسات، تقارير أحداث الشاشة والعبث،
وإجراءات مسؤولي المنصة (الحظر، فك الحظر، إنهاء الجلسات، سياسات الحدود).
"""
from __future__ import annotations

from django.contrib.auth import get_user_model
from django.db.models import Q
from django.shortcuts import get_object_or_404
from django.utils import timezone
from rest_framework import status
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView

from dashboard_admin.models import AuditLog

from .device_security_service import (
    block_device_admin,
    build_unified_devices_registry,
    extract_network_context,
    get_user_device_limit,
    prune_expired_telemetry,
    record_device_activity,
    record_security_event,
    register_or_update_device,
    revoke_user_device,
    serialize_device_summary,
    unblock_device_admin,
)
from .models import (
    DeviceActivity,
    DeviceBlock,
    DeviceSecurityEvent,
    DeviceSession,
    DeviceTrustStatus,
    PlaybackSession,
    RegisteredDevice,
    SecurityPolicyConfig,
    UserSecurityProfile,
)
from .permissions import IsNotBanned, IsPlatformAdmin
from .security_engine import (
    analyze_user_with_ai,
    compute_behavioral_risk,
    enforce_security_ban,
    get_effective_ai_config,
    record_behavioral_activity,
    run_hourly_ai_behavioral_audit,
    serialize_user_security_profile,
    unban_user_and_devices,
    verify_client_request_signature,
)

User = get_user_model()

ALLOWED_CLIENT_REPORT_EVENTS = {
    'screenshot_attempt': ('medium', 20),
    'screen_recording_detected': ('high', 35),
    'display_capture_detected': ('high', 35),
    'debugger_detected': ('critical', 75),
    'tamper_detected': ('critical', 80),
    'integrity_failure': ('high', 65),
    'unfamiliar_device_report': ('high', 40),
    'proxy_mitm_detected': ('critical', 95),
    'user_ca_mitm_detected': ('critical', 95),
    'request_tamper_detected': ('critical', 95),
    'vpn_detected': ('medium', 25),
}


def _is_platform_admin(user) -> bool:
    if not user or not getattr(user, 'is_authenticated', False):
        return False
    if getattr(user, 'is_superuser', False):
        return True
    profile = getattr(user, 'admin_profile', None)
    return bool(profile and profile.is_active_admin)


def _extract_client_installation_id(request) -> str:
    return str(
        request.data.get('installation_id')
        or request.data.get('device_id')
        or request.META.get('HTTP_X_DEVICE_ID')
        or request.META.get('HTTP_X_INSTALLATION_ID')
        or ''
    ).strip()


def _serialize_event(evt: DeviceSecurityEvent) -> dict:
    return {
        'id': evt.id,
        'event_uuid': str(evt.event_uuid),
        'user_id': evt.user_id,
        'username': evt.user.username if evt.user else None,
        'device_id': evt.device_id,
        'installation_id': evt.installation_id,
        'event_type': evt.event_type,
        'severity': evt.severity,
        'risk_score': evt.risk_score,
        'ip_address': evt.ip_address,
        'country_code': evt.country_code,
        'region_name': evt.region_name,
        'action_taken': evt.action_taken,
        'investigation_status': evt.investigation_status,
        'investigation_notes': evt.investigation_notes,
        'details': evt.details,
        'created_at': evt.created_at.isoformat() if evt.created_at else None,
    }


def _serialize_session(sess: DeviceSession, current_inst_id: str = '') -> dict:
    return {
        'id': sess.id,
        'session_uuid': str(sess.session_uuid),
        'user_id': sess.user_id,
        'device_id': sess.device_id,
        'device_name': sess.device.device_name if sess.device else '',
        'installation_id': sess.installation_id,
        'is_current_device': bool(current_inst_id and sess.installation_id == current_inst_id),
        'status': sess.status,
        'ip_address': sess.ip_address,
        'country_code': sess.country_code,
        'region_name': sess.region_name,
        'isp_name': sess.isp_name,
        'is_vpn_or_proxy': sess.is_vpn_or_proxy,
        'started_at': sess.started_at.isoformat() if sess.started_at else None,
        'last_seen_at': sess.last_seen_at.isoformat() if sess.last_seen_at else None,
        'expires_at': sess.expires_at.isoformat() if sess.expires_at else None,
        'revoked_reason': sess.revoked_reason,
    }


def _serialize_policy(policy: SecurityPolicyConfig) -> dict:
    ai_cfg = get_effective_ai_config(policy)
    return {
        'student_device_limit': policy.student_device_limit,
        'teacher_device_limit': policy.teacher_device_limit,
        'assistant_device_limit': policy.assistant_device_limit,
        'max_concurrent_sessions': policy.max_concurrent_sessions,
        'max_concurrent_playback': policy.max_concurrent_playback,
        'risk_threshold_medium': policy.risk_threshold_medium,
        'risk_threshold_high': policy.risk_threshold_high,
        'risk_threshold_critical': policy.risk_threshold_critical,
        'rapid_login_threshold_5m': policy.rapid_login_threshold_5m,
        'rapid_geo_kmh_threshold': policy.rapid_geo_kmh_threshold,
        'event_retention_days': policy.event_retention_days,
        'enforce_device_limits': policy.enforce_device_limits,
        'enforce_screen_capture_policy': policy.enforce_screen_capture_policy,
        'auto_block_on_proxy_mitm': policy.auto_block_on_proxy_mitm,
        'auto_ban_on_account_sharing': policy.auto_ban_on_account_sharing,
        'auto_ban_on_tamper': policy.auto_ban_on_tamper,
        'auto_enforcement_mode': policy.auto_enforcement_mode,
        'enforce_request_signatures': policy.enforce_request_signatures,
        'request_signature_max_skew_seconds': policy.request_signature_max_skew_seconds,
        'ai_security_enabled': policy.ai_security_enabled,
        'ai_provider': ai_cfg['provider'],
        'ai_provider_setting': policy.ai_provider,
        'ai_model_name': policy.ai_model_name,
        'ai_api_key_configured': ai_cfg['configured'],
        'ai_api_key_masked': ai_cfg['masked_key'],
        'ai_hourly_schedule_enabled': policy.ai_hourly_schedule_enabled,
        'ai_auto_enforce_bans': policy.ai_auto_enforce_bans,
        'block_vpn_connections': policy.block_vpn_connections,
        'block_developer_options': policy.block_developer_options,
        'block_abnormal_dns_or_ports': policy.block_abnormal_dns_or_ports,
        'maintenance_approved_devices': policy.maintenance_approved_devices,
        'last_ai_audit_at': policy.last_ai_audit_at.isoformat() if policy.last_ai_audit_at else None,
        'last_ai_audit_summary': policy.last_ai_audit_summary or {},
        'updated_at': policy.updated_at.isoformat() if policy.updated_at else None,
    }


class SecurityDeviceRegisterAPIView(APIView):
    """تسجيل أو تحديث جهاز المستخدم وتوليد بصمة الخادم وجلسة الجهاز."""
    permission_classes = [IsAuthenticated, IsNotBanned]

    def post(self, request):
        installation_id = _extract_client_installation_id(request)
        raw_info = request.data.get('device_info')
        if not isinstance(raw_info, dict):
            raw_info = {
                k: request.data.get(k)
                for k in (
                    'device_name', 'manufacturer', 'model', 'os_name', 'android_version',
                    'api_level', 'cpu_arch', 'cpu_info', 'gpu_renderer', 'gpu_vendor',
                    'screen_resolution', 'app_version', 'app_build_number', 'package_name',
                    'signing_cert_sha256', 'apk_cert_sha256', 'installer_source',
                    'installer_package', 'integrity_signals',
                )
                if k in request.data
            }

        token_jti = ''
        if isinstance(request.auth, dict):
            token_jti = str(request.auth.get('jti') or '')

        outcome = register_or_update_device(
            request=request,
            user=request.user,
            installation_id=installation_id,
            device_info=raw_info,
            token_jti=token_jti,
        )
        clean_payload = {k: v for k, v in outcome.items() if k not in ('device_obj', 'session_obj')}
        http_status = status.HTTP_200_OK if clean_payload.get('allowed') else status.HTTP_403_FORBIDDEN
        return Response(clean_payload, status=http_status)


class SecurityDeviceListAPIView(APIView):
    """عرض الأجهزة الموثوقة للمستخدم الحالي (أو لمستخدم محدد عند الطلب من مسؤول)."""
    permission_classes = [IsAuthenticated, IsNotBanned]

    def get(self, request):
        target_user = request.user
        req_user_id = request.query_params.get('user_id')
        if req_user_id and str(req_user_id) != str(request.user.id):
            if not _is_platform_admin(request.user):
                return Response({'error': 'غير مصرح لك بعرض أجهزة مستخدم آخر.'}, status=status.HTTP_403_FORBIDDEN)
            target_user = get_object_or_404(User, id=req_user_id)

        current_inst_id = (
            request.META.get('HTTP_X_DEVICE_ID')
            or request.META.get('HTTP_X_INSTALLATION_ID')
            or ''
        ).strip()

        devices_qs = RegisteredDevice.objects.filter(user=target_user).order_by('-is_active', '-last_active_at')
        limit = get_user_device_limit(target_user)
        active_count = devices_qs.filter(is_active=True).exclude(
            trust_status__in=[DeviceTrustStatus.REVOKED, DeviceTrustStatus.BLOCKED]
        ).count()

        return Response({
            'device_limit': limit,
            'active_count': active_count,
            'current_installation_id': current_inst_id,
            'devices': [serialize_device_summary(d, current_inst_id) for d in devices_qs],
        })


class SecurityDeviceRevokeAPIView(APIView):
    """إلغاء جهاز أو تسجيل خروجه أو الإبلاغ عنه كجهاز غير معروف مع فحص صارم للملكية (Anti-IDOR)."""
    permission_classes = [IsAuthenticated, IsNotBanned]

    def post(self, request, device_id):
        device = get_object_or_404(RegisteredDevice, id=device_id)
        is_admin = _is_platform_admin(request.user)

        if device.user_id != request.user.id and not is_admin:
            record_security_event(
                event_type='cross_account_device_idor_attempt',
                severity='high',
                risk_score=80,
                user=request.user,
                device=device,
                installation_id=_extract_client_installation_id(request) or device.installation_id,
                request=request,
                action_taken='denied_idor',
                details={'target_device_id': device.id, 'target_owner_id': device.user_id},
            )
            return Response(
                {'error': 'غير مصرح لك بالتحكم في جهاز تابع لحساب آخر.', 'code': 'FORBIDDEN_DEVICE_OWNER'},
                status=status.HTTP_403_FORBIDDEN,
            )

        action = str(request.data.get('action') or 'revoke').strip().lower()
        if action not in ('revoke', 'logout', 'report_unfamiliar'):
            return Response(
                {'error': 'قيمة action غير صالحة. القيم المسموحة: revoke, logout, report_unfamiliar.'},
                status=status.HTTP_400_BAD_REQUEST,
            )

        reason = str(request.data.get('reason') or '').strip()
        updated = revoke_user_device(
            device=device,
            actor=request.user,
            request=request,
            mode=action,
            reason=reason,
        )
        current_inst_id = (request.META.get('HTTP_X_DEVICE_ID') or '').strip()
        return Response({
            'message': 'تم تنفيذ الإجراء على الجهاز بنجاح.',
            'action': action,
            'device': serialize_device_summary(updated, current_inst_id),
        })


class SecurityDeviceVerifyAPIView(APIView):
    """إعادة التحقق من الجهاز المقيّد/المعلّق واستعادة ثقته بعد تأكيد كلمة المرور أو موافقة المسؤول."""
    permission_classes = [IsAuthenticated, IsNotBanned]

    def post(self, request, device_id):
        device = get_object_or_404(RegisteredDevice, id=device_id)
        is_admin = _is_platform_admin(request.user)

        if device.user_id != request.user.id and not is_admin:
            return Response(
                {'error': 'غير مصرح لك بالتحقق من جهاز تابع لحساب آخر.'},
                status=status.HTTP_403_FORBIDDEN,
            )

        if device.trust_status == DeviceTrustStatus.BLOCKED and not is_admin:
            return Response(
                {'error': 'هذا الجهاز محظور إدارياً ولا يمكن تفعيله ذاتياً.', 'code': 'DEVICE_BLOCKED'},
                status=status.HTTP_403_FORBIDDEN,
            )

        if not is_admin:
            if request.user.has_usable_password():
                password = str(request.data.get('password') or '')
                if not password or not request.user.check_password(password):
                    return Response(
                        {'error': 'كلمة المرور غير صحيحة لإعادة توثيق الجهاز.', 'code': 'INVALID_PASSWORD'},
                        status=status.HTTP_403_FORBIDDEN,
                    )
            else:
                confirm_email = str(request.data.get('email') or '').strip().lower()
                if not confirm_email or confirm_email != (request.user.email or '').strip().lower():
                    return Response(
                        {'error': 'يرجى تأكيد البريد الإلكتروني لإعادة توثيق الجهاز.', 'code': 'EMAIL_CONFIRMATION_REQUIRED'},
                        status=status.HTTP_403_FORBIDDEN,
                    )

        device.trust_status = DeviceTrustStatus.TRUSTED
        device.is_verified = True
        device.is_active = True
        device.requires_reauth = False
        device.risk_score = 0
        device.risk_level = 'low'
        device.save(
            update_fields=['trust_status', 'is_verified', 'is_active', 'requires_reauth', 'risk_score', 'risk_level']
        )

        record_device_activity(
            request=request,
            user=device.user,
            device=device,
            activity_type='device_reverified',
            metadata={'verified_by_admin': is_admin},
        )
        record_security_event(
            event_type='device_reverified',
            severity='low',
            risk_score=0,
            user=device.user,
            device=device,
            request=request,
            action_taken='restored_trusted',
            details={'verified_by_admin': is_admin},
        )
        return Response({
            'message': 'تم التحقق من الجهاز واستعادة ثقته بنجاح.',
            'device': serialize_device_summary(device),
        })


class SecurityEventsListAPIView(APIView):
    """سجل أحداث الأمان والمخاطر للمستخدم الحالي أو لجميع المستخدمين للمسؤولين."""
    permission_classes = [IsAuthenticated, IsNotBanned]

    def get(self, request):
        is_admin = _is_platform_admin(request.user)
        qs = DeviceSecurityEvent.objects.select_related('user', 'device').order_by('-created_at')

        if is_admin:
            user_id = request.query_params.get('user_id')
            if user_id:
                qs = qs.filter(user_id=user_id)
        else:
            qs = qs.filter(user=request.user)

        severity = request.query_params.get('severity')
        if severity:
            qs = qs.filter(severity=severity)
        event_type = request.query_params.get('event_type')
        if event_type:
            qs = qs.filter(event_type=event_type)
        inv_status = request.query_params.get('investigation_status')
        if inv_status:
            qs = qs.filter(investigation_status=inv_status)
        inst_id = request.query_params.get('installation_id')
        if inst_id:
            qs = qs.filter(installation_id=inst_id)

        events = [_serialize_event(e) for e in qs[:100]]
        return Response({'count': len(events), 'events': events})


class SecuritySessionsListAPIView(APIView):
    """استعراض أو إنهاء جلسات الأجهزة (DeviceSession)."""
    permission_classes = [IsAuthenticated, IsNotBanned]

    def get(self, request):
        is_admin = _is_platform_admin(request.user)
        current_inst_id = (request.META.get('HTTP_X_DEVICE_ID') or '').strip()
        qs = DeviceSession.objects.select_related('device', 'user').order_by('-last_seen_at')

        if is_admin:
            req_user_id = request.query_params.get('user_id')
            if req_user_id:
                qs = qs.filter(user_id=req_user_id)
        else:
            qs = qs.filter(user=request.user)

        sess_status = request.query_params.get('status')
        if sess_status:
            qs = qs.filter(status=sess_status)

        return Response({
            'sessions': [_serialize_session(s, current_inst_id) for s in qs[:100]],
        })

    def post(self, request):
        session_uuid = str(request.data.get('session_uuid') or request.data.get('session_id') or '').strip()
        if not session_uuid:
            return Response({'error': 'معرّف الجلسة session_uuid مطلوب.'}, status=status.HTTP_400_BAD_REQUEST)

        sess = get_object_or_404(DeviceSession, session_uuid=session_uuid)
        is_admin = _is_platform_admin(request.user)
        if sess.user_id != request.user.id and not is_admin:
            return Response({'error': 'غير مصرح لك بإنهاء جلسة حساب آخر.'}, status=status.HTTP_403_FORBIDDEN)

        sess.status = 'revoked'
        sess.ended_at = timezone.now()
        sess.revoked_reason = str(request.data.get('reason') or ('revoked_by_admin' if is_admin else 'revoked_by_owner'))[:160]
        sess.save(update_fields=['status', 'ended_at', 'revoked_reason'])

        record_security_event(
            event_type='device_session_revoked',
            severity='medium',
            risk_score=20,
            user=sess.user,
            device=sess.device,
            installation_id=sess.installation_id,
            request=request,
            action_taken='session_revoked',
            details={'session_uuid': str(sess.session_uuid), 'actor_id': request.user.id},
        )
        return Response({'message': 'تم إنهاء الجلسة بنجاح.', 'session': _serialize_session(sess)})


class SecurityEventReportAPIView(APIView):
    """استقبال بلاغات التطبيق (محاولة لقطة شاشة، تسجيل شاشة، عرض خارجي، بروكسي MITM، أداة تصحيح/حقن)."""
    permission_classes = []

    def post(self, request):
        raw_type = str(request.data.get('event_type') or '').strip().lower()
        if raw_type not in ALLOWED_CLIENT_REPORT_EVENTS:
            return Response(
                {
                    'error': 'نوع الحدث غير معروف.',
                    'allowed_types': sorted(ALLOWED_CLIENT_REPORT_EVENTS.keys()),
                },
                status=status.HTTP_400_BAD_REQUEST,
            )

        is_auth = bool(request.user and getattr(request.user, 'is_authenticated', False))
        sig_check = verify_client_request_signature(request)
        if not is_auth and not sig_check.get('present'):
            return Response(
                {'error': 'يتطلب مصادقة أو توقيعاً تشفيرياً موثقاً لتسجيل الحدث الأمني.'},
                status=status.HTTP_401_UNAUTHORIZED,
            )
        if sig_check.get('present') and not sig_check.get('valid'):
            return Response({'error': sig_check.get('reason') or 'توقيع غير صالح.'}, status=status.HTTP_403_FORBIDDEN)

        reporter_user = request.user if is_auth else None
        severity, base_risk = ALLOWED_CLIENT_REPORT_EVENTS[raw_type]
        inst_id = _extract_client_installation_id(request)
        screen_name = str(request.data.get('screen_name') or '').strip()[:120]
        details = request.data.get('details')
        if not isinstance(details, dict):
            details = {}
        details = {**details, 'screen_name': screen_name, 'client_reported': True}

        net_ctx = extract_network_context(request)
        device = (
            RegisteredDevice.objects.filter(user=reporter_user, installation_id=inst_id).first()
            if (reporter_user and inst_id)
            else (RegisteredDevice.objects.filter(installation_id=inst_id).first() if inst_id else None)
        )

        signal_tag = ''
        if raw_type == 'proxy_mitm_detected':
            signal_tag = 'proxy_mitm'
        elif raw_type == 'user_ca_mitm_detected':
            signal_tag = 'user_ca_mitm'
        elif raw_type == 'request_tamper_detected':
            signal_tag = 'request_tamper'
        elif raw_type in ('debugger_detected', 'tamper_detected', 'integrity_failure'):
            signal_tag = 'integrity_tamper'

        behav = record_behavioral_activity(
            request=request,
            user=reporter_user,
            device=device,
            installation_id=inst_id,
            activity_type=raw_type,
            signal_tag=signal_tag,
            risk_delta=base_risk,
            net_ctx=net_ctx,
            metadata=details,
        )

        action_taken = 'logged'
        if device and device.trust_status != DeviceTrustStatus.BLOCKED:
            new_score = min(max(device.risk_score, base_risk) if severity == 'critical' else device.risk_score + (base_risk // 2), 100)
            device.risk_score = new_score
            if new_score >= 85 or severity == 'critical':
                device.risk_level = 'critical'
                device.trust_status = DeviceTrustStatus.RESTRICTED
                device.requires_reauth = True
                action_taken = 'temp_restricted'
            elif new_score >= 60 or raw_type in ('screen_recording_detected', 'display_capture_detected'):
                device.risk_level = 'high'
                if device.trust_status == DeviceTrustStatus.TRUSTED:
                    device.trust_status = DeviceTrustStatus.SUSPICIOUS
                action_taken = 'flagged_suspicious'
            elif new_score >= 30:
                device.risk_level = 'medium'
                action_taken = 'monitored'
            device.save(update_fields=['risk_score', 'risk_level', 'trust_status', 'requires_reauth'])

        # إذا كان المستخدم غير مسجل دخول ولكن التوقيع أكد وجود بروكسي/MITM حقيقي، احظر الجهاز نفسه مؤقتاً
        policy = SecurityPolicyConfig.load()
        if (
            reporter_user is None
            and inst_id
            and signal_tag in ('proxy_mitm', 'user_ca_mitm', 'request_tamper')
            and policy.auto_block_on_proxy_mitm
            and policy.auto_enforcement_mode in ('device_only', 'device_and_user')
        ):
            enforce_security_ban(
                device=device,
                installation_id=inst_id,
                mode='device_only',
                reason=f'حظر تلقائي للجهاز: رصد اعتراض/بروكسي ({raw_type})',
                request=request,
            )
            action_taken = 'device_blocked'

        evt = record_security_event(
            event_type=raw_type,
            severity=severity,
            risk_score=device.risk_score if device else base_risk,
            user=reporter_user,
            device=device,
            installation_id=inst_id,
            request=request,
            net_ctx=net_ctx,
            action_taken=(behav.get('enforcement') or {}).get('mode') or action_taken,
            details=details,
            notify_user=bool(reporter_user and severity in ('medium', 'high', 'critical')),
            notify_title='تنبيه حماية المحتوى',
            notify_message=(
                'تم رصد محاولة اعتراض اتصال أو استخدام شهادة/بروكسي غير مصرح وتم تقييد الوصول لحماية المنصة.'
                if signal_tag in ('proxy_mitm', 'user_ca_mitm', 'request_tamper')
                else (
                    'تم رصد محاولة التقاط لقطة شاشة أو تسجيل محتوى محمي على حسابك.'
                    if raw_type in ('screenshot_attempt', 'screen_recording_detected', 'display_capture_detected')
                    else 'تم رصد نشاط غير معتاد أو محاولة عبث على جهازك أثناء استخدام المنصة.'
                )
            ),
        )

        return Response(
            {
                'recorded': True,
                'event': _serialize_event(evt),
                'action_taken': evt.action_taken,
                'behavioral_risk': {k: v for k, v in behav.items() if k != 'profile'},
                'screen_capture_policy_enforced': policy.enforce_screen_capture_policy,
            },
            status=status.HTTP_201_CREATED,
        )


class SecurityAdminActionAPIView(APIView):
    """إجراءات مسؤولي المنصة لإدارة حظر الأجهزة والجلسات والسياسات وتحليل السلوك والأحداث الأمنية."""
    permission_classes = [IsPlatformAdmin]

    def get(self, request):
        now = timezone.now()
        last_24h = now - timezone.timedelta(hours=24) if hasattr(timezone, 'timedelta') else (now - __import__('datetime').timedelta(hours=24))
        policy = SecurityPolicyConfig.load()

        profiles = (
            UserSecurityProfile.objects
            .select_related('user')
            .order_by('-behavior_risk_score', '-analyzed_at')[:60]
        )
        recent_activities = (
            DeviceActivity.objects
            .select_related('user', 'device')
            .order_by('-created_at')[:60]
        )
        recent_events = (
            DeviceSecurityEvent.objects
            .select_related('user', 'device')
            .order_by('-created_at')[:40]
        )
        active_blocks = (
            DeviceBlock.objects
            .select_related('user', 'device')
            .filter(is_active=True)
            .order_by('-created_at')[:40]
        )

        unified_devices = build_unified_devices_registry(
            search_query=str(request.query_params.get('q') or '').strip(),
            trust_filter=str(request.query_params.get('trust') or '').strip(),
            limit=120,
        )

        return Response({
            'metrics': {
                'total_devices': len(unified_devices),
                'raw_device_records': RegisteredDevice.objects.count(),
                'active_devices': RegisteredDevice.objects.filter(is_active=True).count(),
                'suspicious_devices': RegisteredDevice.objects.filter(
                    trust_status__in=[DeviceTrustStatus.SUSPICIOUS, DeviceTrustStatus.RESTRICTED]
                ).count(),
                'blocked_devices': sum(1 for u in unified_devices if u.get('is_blocked')) or DeviceBlock.objects.filter(is_active=True).count(),
                'active_sessions': DeviceSession.objects.filter(status='active', expires_at__gt=now).count(),
                'open_security_events': DeviceSecurityEvent.objects.filter(investigation_status='open').count(),
                'critical_events': DeviceSecurityEvent.objects.filter(severity='critical', investigation_status='open').count(),
                'high_risk_users_count': UserSecurityProfile.objects.filter(behavior_risk_level__in=('high', 'critical')).count(),
                'total_activities_24h': DeviceActivity.objects.filter(created_at__gte=last_24h).count(),
            },
            'policy': _serialize_policy(policy),
            'unified_devices': unified_devices,
            'risk_profiles': [serialize_user_security_profile(p) for p in profiles],
            'recent_activities': [
                {
                    'id': a.id,
                    'user_id': a.user_id,
                    'username': (a.user.get_full_name() or a.user.email or a.user.username) if a.user else 'زائر',
                    'role': a.user.role if a.user else 'guest',
                    'device_name': a.device.device_name if a.device else '',
                    'installation_id': a.device.installation_id if a.device else (a.metadata.get('installation_id', '') if isinstance(a.metadata, dict) else ''),
                    'activity_type': a.activity_type,
                    'endpoint': a.endpoint,
                    'ip_address': a.ip_address,
                    'country_code': a.country_code,
                    'is_vpn_or_proxy': a.is_vpn_or_proxy,
                    'metadata': a.metadata,
                    'created_at': a.created_at.isoformat() if a.created_at else None,
                }
                for a in recent_activities
            ],
            'recent_events': [_serialize_event(e) for e in recent_events],
            'active_blocks': [
                {
                    'id': b.id,
                    'installation_id': b.installation_id,
                    'hardware_id': b.fingerprint_hash if str(b.fingerprint_hash).startswith('DEV-') else '',
                    'device_name': b.device.device_name if b.device else b.installation_id,
                    'user_id': b.user_id,
                    'username': (b.user.get_full_name() or b.user.email) if b.user else None,
                    'block_type': b.block_type,
                    'reason': b.reason,
                    'expires_at': b.expires_at.isoformat() if b.expires_at else None,
                    'created_at': b.created_at.isoformat() if b.created_at else None,
                }
                for b in active_blocks
            ],
        })

    def post(self, request):
        action = str(request.data.get('action') or '').strip()
        if not action:
            return Response({'error': 'حقل action مطلوب.'}, status=status.HTTP_400_BAD_REQUEST)

        if action == 'block_device':
            device_id = request.data.get('device_id')
            inst_id = str(request.data.get('installation_id') or '').strip()
            hw_id = str(request.data.get('hardware_id') or '').strip()
            ban_linked_users = bool(request.data.get('ban_linked_users'))
            device = RegisteredDevice.objects.filter(id=device_id).first() if device_id else None
            if not device and inst_id:
                device = RegisteredDevice.objects.filter(installation_id=inst_id).first()
            if not device and not inst_id and not hw_id:
                return Response({'error': 'يجب تحديد hardware_id أو device_id أو installation_id.'}, status=status.HTTP_400_BAD_REQUEST)

            block_type = 'temporary' if str(request.data.get('block_type') or 'permanent') == 'temporary' else 'permanent'
            duration_hours = int(request.data.get('duration_hours') or 24)
            reason = str(request.data.get('reason') or 'حظر إداري شامل للجهاز (التطبيق والمتصفح)').strip()

            blk = block_device_admin(
                device=device,
                installation_id=inst_id or (device.installation_id if device else hw_id),
                hardware_id=hw_id,
                admin_user=request.user,
                block_type=block_type,
                reason=reason,
                duration_hours=duration_hours,
                request=request,
            )
            banned_accounts = 0
            if ban_linked_users:
                from .device_security_service import _find_all_devices_for_hardware, get_device_hardware_id
                target_hw = hw_id or (blk.fingerprint_hash if str(blk.fingerprint_hash).startswith('DEV-') else (get_device_hardware_id(device) if device else ''))
                linked = _find_all_devices_for_hardware(hardware_id=target_hw, installation_id=inst_id, primary_device=device)
                seen_uid = set()
                for d in linked:
                    if d.user_id in seen_uid:
                        continue
                    seen_uid.add(d.user_id)
                    if not getattr(d.user, 'is_superuser', False) and getattr(d.user, 'role', '') != 'admin':
                        d.user.is_banned = True
                        d.user.save(update_fields=['is_banned'])
                        banned_accounts += 1
            AuditLog.log(
                request,
                AuditLog.ACTION_BLOCK_DEVICE,
                target_label=hw_id or blk.fingerprint_hash or blk.installation_id,
                target_id=device.id if device else None,
                details={'block_id': blk.id, 'hardware_id': hw_id or blk.fingerprint_hash, 'block_type': block_type, 'reason': reason, 'banned_accounts': banned_accounts},
            )
            return Response({
                'message': f'تم حظر الجهاز ({hw_id or blk.fingerprint_hash or blk.installation_id}) على التطبيق والمتصفح بنجاح.',
                'block': {
                    'id': blk.id,
                    'installation_id': blk.installation_id,
                    'hardware_id': hw_id or blk.fingerprint_hash,
                    'block_type': blk.block_type,
                    'is_active': blk.is_active,
                    'expires_at': blk.expires_at.isoformat() if blk.expires_at else None,
                    'reason': blk.reason,
                },
            })

        if action == 'unblock_device':
            block_id = request.data.get('block_id')
            device_id = request.data.get('device_id')
            inst_id = str(request.data.get('installation_id') or '').strip()
            hw_id = str(request.data.get('hardware_id') or '').strip()
            reason = str(request.data.get('reason') or 'رفع الحظر بواسطة مسؤول المنصة').strip()

            device = RegisteredDevice.objects.filter(id=device_id).first() if device_id else None
            if block_id and not inst_id and not hw_id:
                blk = get_object_or_404(DeviceBlock, id=block_id)
                inst_id = blk.installation_id
                if str(blk.fingerprint_hash or '').startswith('DEV-'):
                    hw_id = blk.fingerprint_hash
                if not device:
                    device = blk.device
            if not device and inst_id:
                device = RegisteredDevice.objects.filter(installation_id=inst_id).first()
            if not inst_id and device:
                inst_id = device.installation_id
            if not inst_id and not hw_id:
                return Response({'error': 'يجب تحديد block_id أو hardware_id أو device_id أو installation_id.'}, status=status.HTTP_400_BAD_REQUEST)

            count = unblock_device_admin(
                device=device,
                installation_id=inst_id,
                hardware_id=hw_id,
                admin_user=request.user,
                reason=reason,
                request=request,
            )
            AuditLog.log(
                request,
                AuditLog.ACTION_UNBLOCK_DEVICE,
                target_label=hw_id or inst_id,
                target_id=device.id if device else None,
                details={'unblocked_count': count, 'hardware_id': hw_id, 'reason': reason},
            )
            return Response({'message': 'تم فك حظر الجهاز (التطبيق والمتصفح) بنجاح.', 'unblocked_count': count})

        if action == 'revoke_session':
            session_uuid = str(request.data.get('session_uuid') or request.data.get('session_id') or '').strip()
            sess = get_object_or_404(DeviceSession, session_uuid=session_uuid)
            sess.status = 'revoked'
            sess.ended_at = timezone.now()
            sess.revoked_reason = str(request.data.get('reason') or 'revoked_by_admin')[:160]
            sess.save(update_fields=['status', 'ended_at', 'revoked_reason'])
            AuditLog.log(
                request,
                AuditLog.ACTION_REVOKE_SESSION,
                target_label=str(sess.session_uuid),
                target_id=sess.user_id,
                details={'installation_id': sess.installation_id, 'reason': sess.revoked_reason},
            )
            return Response({'message': 'تم إنهاء الجلسة بنجاح.', 'session': _serialize_session(sess)})

        if action == 'revoke_all_user_sessions':
            user_id = request.data.get('user_id')
            target_user = get_object_or_404(User, id=user_id)
            now = timezone.now()
            ds_count = DeviceSession.objects.filter(user=target_user, status='active').update(
                status='revoked',
                ended_at=now,
                revoked_reason='revoked_all_by_admin',
            )
            ps_count = PlaybackSession.objects.filter(user=target_user, status='active').update(
                status='revoked',
                revoked_reason='revoked_all_by_admin',
            )
            AuditLog.log(
                request,
                AuditLog.ACTION_REVOKE_SESSION,
                target_label=target_user.username,
                target_id=target_user.id,
                details={'device_sessions_revoked': ds_count, 'playback_sessions_revoked': ps_count},
            )
            return Response({
                'message': 'تم إنهاء كافة جلسات المستخدم.',
                'device_sessions_revoked': ds_count,
                'playback_sessions_revoked': ps_count,
            })

        if action == 'force_reauth':
            device = get_object_or_404(RegisteredDevice, id=request.data.get('device_id'))
            now = timezone.now()
            device.requires_reauth = True
            if device.trust_status != DeviceTrustStatus.BLOCKED:
                device.trust_status = DeviceTrustStatus.PENDING
            device.save(update_fields=['requires_reauth', 'trust_status'])
            DeviceSession.objects.filter(device=device, status='active').update(
                status='revoked',
                ended_at=now,
                revoked_reason='force_reauth_by_admin',
            )
            AuditLog.log(
                request,
                AuditLog.ACTION_REVOKE_SESSION,
                target_label=device.installation_id,
                target_id=device.id,
                details={'action': 'force_reauth'},
            )
            return Response({'message': 'تم فرض إعادة التحقق على الجهاز.', 'device': serialize_device_summary(device)})

        if action in ('mark_false_positive', 'update_event_status'):
            event = get_object_or_404(DeviceSecurityEvent, id=request.data.get('event_id'))
            new_status = (
                'false_positive'
                if action == 'mark_false_positive'
                else str(request.data.get('investigation_status') or 'resolved').strip()
            )
            if new_status not in ('open', 'investigating', 'resolved', 'false_positive'):
                return Response({'error': 'حالة تحقيق غير صالحة.'}, status=status.HTTP_400_BAD_REQUEST)

            notes = str(request.data.get('investigation_notes') or request.data.get('notes') or '').strip()
            event.investigation_status = new_status
            if notes:
                event.investigation_notes = notes
            event.reviewed_by = request.user
            event.reviewed_at = timezone.now()
            event.save(update_fields=['investigation_status', 'investigation_notes', 'reviewed_by', 'reviewed_at'])

            if new_status == 'false_positive' and event.device_id:
                dev = event.device
                if dev and dev.trust_status != DeviceTrustStatus.BLOCKED:
                    dev.trust_status = DeviceTrustStatus.TRUSTED
                    dev.requires_reauth = False
                    dev.risk_score = max(dev.risk_score - 40, 0)
                    dev.risk_level = 'low' if dev.risk_score < 30 else ('medium' if dev.risk_score < 60 else 'high')
                    dev.save(update_fields=['trust_status', 'requires_reauth', 'risk_score', 'risk_level'])

            return Response({'message': 'تم تحديث حالة الحدث الأمني.', 'event': _serialize_event(event)})

        if action == 'update_policy_config':
            policy = SecurityPolicyConfig.load()
            for field in (
                'student_device_limit',
                'teacher_device_limit',
                'assistant_device_limit',
                'max_concurrent_sessions',
                'max_concurrent_playback',
                'risk_threshold_medium',
                'risk_threshold_high',
                'risk_threshold_critical',
                'rapid_login_threshold_5m',
                'rapid_geo_kmh_threshold',
                'event_retention_days',
                'request_signature_max_skew_seconds',
            ):
                if field in request.data and request.data[field] is not None:
                    setattr(policy, field, max(int(request.data[field]), 1))
            for bfield in (
                'enforce_device_limits',
                'enforce_screen_capture_policy',
                'auto_block_on_proxy_mitm',
                'auto_ban_on_account_sharing',
                'auto_ban_on_tamper',
                'enforce_request_signatures',
                'ai_security_enabled',
                'ai_hourly_schedule_enabled',
                'ai_auto_enforce_bans',
            ):
                if bfield in request.data:
                    raw_b = request.data[bfield]
                    setattr(policy, bfield, raw_b if isinstance(raw_b, bool) else str(raw_b).lower() in ('1', 'true', 'yes'))
            if 'auto_enforcement_mode' in request.data and str(request.data['auto_enforcement_mode']).strip() in (
                'warn', 'device_only', 'user_only', 'device_and_user'
            ):
                policy.auto_enforcement_mode = str(request.data['auto_enforcement_mode']).strip()

            def _opt_bool(key: str):
                if key not in request.data:
                    return None
                rb = request.data[key]
                return rb if isinstance(rb, bool) else str(rb).lower() in ('1', 'true', 'yes')

            policy.set_boot_guard_flags(
                block_vpn=_opt_bool('block_vpn_connections'),
                block_dev_options=_opt_bool('block_developer_options'),
                block_abnormal_net=_opt_bool('block_abnormal_dns_or_ports'),
            )
            if 'ai_provider' in request.data and str(request.data['ai_provider']).strip().lower() in (
                'auto', 'gemini', 'openai', 'groq', 'deepseek'
            ):
                policy.ai_provider = str(request.data['ai_provider']).strip().lower()
            if 'ai_model_name' in request.data and str(request.data['ai_model_name']).strip():
                policy.ai_model_name = str(request.data['ai_model_name']).strip()[:64]
            if 'ai_api_key_override' in request.data:
                new_key = str(request.data['ai_api_key_override'] or '').strip()
                if new_key != 'PUT_YOUR_AI_API_KEY_HERE':
                    policy.ai_api_key_override = new_key[:255]
            policy.save()
            AuditLog.log(
                request,
                AuditLog.ACTION_SECURITY_POLICY,
                target_label='SecurityPolicyConfig',
                target_id=policy.id,
                details={k: v for k, v in _serialize_policy(policy).items() if k != 'ai_api_key_override'},
            )
            return Response({'message': 'تم تحديث إعدادات السياسة الأمنية والذكاء الاصطناعي بنجاح.', 'policy': _serialize_policy(policy)})

        if action in ('ban_user_only', 'ban_device_only', 'ban_user_and_device'):
            user_id = request.data.get('user_id')
            device_id = request.data.get('device_id')
            inst_id = str(request.data.get('installation_id') or '').strip()
            hw_id = str(request.data.get('hardware_id') or '').strip()
            target_user = User.objects.filter(id=user_id).first() if user_id else None
            device = RegisteredDevice.objects.filter(id=device_id).first() if device_id else None
            if not device and inst_id:
                device = RegisteredDevice.objects.filter(installation_id=inst_id).first()
            if not inst_id and hw_id and device is None:
                from .device_security_service import _find_all_devices_for_hardware
                matched_hw_devs = _find_all_devices_for_hardware(hardware_id=hw_id)
                if matched_hw_devs:
                    device = matched_hw_devs[0]
                    inst_id = device.installation_id
            mode = (
                'user_only'
                if action == 'ban_user_only'
                else ('device_only' if action == 'ban_device_only' else 'device_and_user')
            )
            reason = str(request.data.get('reason') or f'حظر أمني ({mode}) بواسطة مسؤول المنصة').strip()
            block_type = 'temporary' if str(request.data.get('block_type') or 'permanent') == 'temporary' else 'permanent'
            duration_hours = int(request.data.get('duration_hours') or 24)
            res = enforce_security_ban(
                user=target_user,
                device=device,
                installation_id=inst_id or hw_id,
                mode=mode,
                reason=reason,
                block_type=block_type,
                duration_hours=duration_hours,
                actor=request.user,
                request=request,
            )
            return Response({'message': 'تم تنفيذ إجراء الحظر الأمني بنجاح.', 'result': res})

        if action == 'unban_user_and_devices':
            user_id = request.data.get('user_id')
            inst_id = str(request.data.get('installation_id') or '').strip()
            mode = str(request.data.get('mode') or 'both').strip()
            target_user = User.objects.filter(id=user_id).first() if user_id else None
            res = unban_user_and_devices(
                user=target_user,
                installation_id=inst_id,
                mode=mode,
                actor=request.user,
                reason=str(request.data.get('reason') or 'فك الحظر بواسطة الإدارة').strip(),
                request=request,
            )
            return Response({'message': 'تم رفع الحظر بنجاح.', 'result': res})

        if action == 'analyze_user_behavior':
            user_id = request.data.get('user_id')
            if user_id:
                target_user = get_object_or_404(User, id=user_id)
                res = analyze_user_with_ai(target_user, enforce_if_flagged=True, request=request)
                return Response({
                    'message': f"تم تحليل سلوك المستخدم ({res['verdict'].get('recommended_action', 'none')}) بنجاح.",
                    'profile': serialize_user_security_profile(res['profile']),
                    'verdict': res['verdict'],
                    'enforcement': res['enforcement'],
                })
            # تشغيل دورة التحليل بالذكاء الاصطناعي على جميع المستخدمين النشطين اليوم
            summary = run_hourly_ai_behavioral_audit(force=True, request=request)
            return Response({
                'message': f"تم تحليل سلوك {summary.get('analyzed_users', 0)} مستخدماً نشطاً اليوم (عالي الخطورة: {summary.get('flagged_high_risk', 0)} | حظر آلي: {summary.get('banned_users', 0)} حساب / {summary.get('banned_devices', 0)} جهاز).",
                'summary': summary,
                'analyzed_count': summary.get('analyzed_users', 0),
            })

        if action == 'toggle_maintenance_device':
            hw_id = str(request.data.get('hardware_id') or '').strip()
            inst_id = str(request.data.get('installation_id') or '').strip()
            device_id = request.data.get('device_id')
            if not hw_id and device_id:
                dev = RegisteredDevice.objects.filter(id=device_id).first()
                if dev is not None:
                    from .device_security_service import get_device_hardware_id
                    hw_id = get_device_hardware_id(dev)
            if not hw_id and inst_id:
                dev = RegisteredDevice.objects.filter(installation_id=inst_id).first()
                if dev is not None:
                    from .device_security_service import get_device_hardware_id
                    hw_id = get_device_hardware_id(dev)
            target_ident = hw_id or inst_id
            if not target_ident:
                return Response({'error': 'يجب تحديد معرّف الجهاز المادي DEV-XXXX.'}, status=status.HTTP_400_BAD_REQUEST)

            policy = SecurityPolicyConfig.load()
            if 'approved' in request.data and request.data['approved'] is not None:
                raw_ap = request.data['approved']
                approved = raw_ap if isinstance(raw_ap, bool) else str(raw_ap).lower() in ('1', 'true', 'yes', 'on')
            else:
                approved = not policy.is_device_maintenance_approved(target_ident)

            approved_list = policy.set_device_maintenance_approval(target_ident, approved=approved)
            policy.save()
            AuditLog.log(
                request,
                AuditLog.ACTION_SECURITY_POLICY,
                target_label=target_ident,
                details={'action': 'toggle_maintenance_device', 'approved': approved},
            )
            return Response({
                'message': (
                    f'تم اعتماد الجهاز ({target_ident}) لظهور زر دخول الإدارة أثناء وضع الصيانة.'
                    if approved
                    else f'تم إلغاء اعتماد الجهاز ({target_ident}) لدخول الإدارة أثناء الصيانة.'
                ),
                'approved': approved,
                'hardware_id': target_ident,
                'maintenance_approved_devices': approved_list,
                'policy': _serialize_policy(policy),
            })

        if action == 'prune_telemetry':
            days = request.data.get('retention_days')
            result = prune_expired_telemetry(int(days) if days is not None else None)
            AuditLog.log(
                request,
                AuditLog.ACTION_SECURITY_POLICY,
                target_label='TelemetryPrune',
                details=result,
            )
            return Response({'message': 'تم تنفيذ سياسة الاحتفاظ بالسجلات وتنظيف البيانات المنتهية.', 'result': result})

        return Response({'error': f'إجراء غير معروف: {action}'}, status=status.HTTP_400_BAD_REQUEST)

"""api_v1.views.security.monitoring
Extracted from api_v1/views_security.py.
"""
from __future__ import annotations

from django.shortcuts import get_object_or_404
from django.utils import timezone
from rest_framework import status
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView
from api_v1.device_security_service import (
    extract_network_context,
    record_security_event,
)
from api_v1.models import (
    DeviceSecurityEvent,
    DeviceSession,
    DeviceTrustStatus,
    RegisteredDevice,
    SecurityPolicyConfig,
)
from api_v1.permissions import IsNotBanned
from api_v1.security_engine import (
    enforce_security_ban,
    record_behavioral_activity,
    verify_client_request_signature,
)

from api_v1.views.security.helpers import (
    ALLOWED_CLIENT_REPORT_EVENTS,
    _extract_client_installation_id,
    _is_platform_admin,
    _serialize_event,
    _serialize_session,
)


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

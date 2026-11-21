"""api_v1.views.security.admin_actions
Extracted from api_v1/views_security.py.
"""
from __future__ import annotations

from django.contrib.auth import get_user_model
from django.shortcuts import get_object_or_404
from django.utils import timezone
from rest_framework import status
from rest_framework.response import Response
from rest_framework.views import APIView
from dashboard_admin.models import AuditLog
from api_v1.device_security_service import (
    block_device_admin,
    build_unified_devices_registry,
    prune_expired_telemetry,
    serialize_device_summary,
    unblock_device_admin,
)
from api_v1.models import (
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
from api_v1.permissions import IsPlatformAdmin
from api_v1.security_engine import (
    analyze_user_with_ai,
    enforce_security_ban,
    run_hourly_ai_behavioral_audit,
    serialize_user_security_profile,
    unban_user_and_devices,
)

from api_v1.views.security.helpers import (
    _serialize_event,
    _serialize_policy,
    _serialize_session,
)

User = get_user_model()


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
                from api_v1.device_security_service import _find_all_devices_for_hardware, get_device_hardware_id
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
                from api_v1.device_security_service import _find_all_devices_for_hardware
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
                    from api_v1.device_security_service import get_device_hardware_id
                    hw_id = get_device_hardware_id(dev)
            if not hw_id and inst_id:
                dev = RegisteredDevice.objects.filter(installation_id=inst_id).first()
                if dev is not None:
                    from api_v1.device_security_service import get_device_hardware_id
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

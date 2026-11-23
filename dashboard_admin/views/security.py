"""dashboard_admin.views.security
Extracted from dashboard_admin/views.py.
"""

from django.shortcuts import (
    render,
    redirect,
    get_object_or_404,
)
from django.contrib import messages
from django.contrib.auth import get_user_model
from django.db.models import Q
from django.utils import timezone
from dashboard_admin.models import AuditLog
from dashboard_admin.decorators import moderator_required
from django.urls import reverse

from django.template.loader import render_to_string

from dashboard_admin.views.base import _base_context
from dashboard_admin.views.ajax import (
    ajax_error,
    ajax_success,
    is_ajax_request,
)

User = get_user_model()


def _build_security_dashboard_context(request):
    """تجميع بيانات مركز الأمان للعرض الكامل وتحديثات AJAX الجزئية."""
    import ipaddress
    from api_v1.models import (
        DeviceBlock,
        DeviceSecurityEvent,
        DeviceSession,
        DeviceTrustStatus,
        RegisteredDevice,
        SecurityPolicyConfig,
        UserSecurityProfile,
    )
    from api_v1.security_engine import (
        get_effective_ai_config,
        maybe_trigger_hourly_ai_audit_async,
    )

    ctx = _base_context(request)
    policy = SecurityPolicyConfig.load()
    if getattr(policy, 'ai_security_enabled', True):
        maybe_trigger_hourly_ai_audit_async()
    now = timezone.now()

    q = (request.GET.get('q') or '').strip()
    trust_filter = (request.GET.get('trust') or '').strip()
    severity_filter = (request.GET.get('severity') or '').strip()
    event_status_filter = (request.GET.get('event_status') or '').strip()

    devices_qs = RegisteredDevice.objects.select_related('user').order_by('-risk_score', '-last_active_at')
    if q:
        search_q = (
            Q(user__username__icontains=q)
            | Q(user__email__icontains=q)
            | Q(device_name__icontains=q)
            | Q(model__icontains=q)
            | Q(installation_id__icontains=q)
        )
        try:
            ipaddress.ip_address(q)
            search_q |= Q(last_ip=q)
        except ValueError:
            pass
        devices_qs = devices_qs.filter(search_q)
    if trust_filter:
        devices_qs = devices_qs.filter(trust_status=trust_filter)

    events_qs = DeviceSecurityEvent.objects.select_related('user', 'device').order_by('-created_at')
    if severity_filter:
        events_qs = events_qs.filter(severity=severity_filter)
    if event_status_filter:
        events_qs = events_qs.filter(investigation_status=event_status_filter)

    active_sessions_qs = DeviceSession.objects.select_related('user', 'device').filter(
        status='active',
        expires_at__gt=now,
    ).order_by('-last_seen_at')

    active_blocks_qs = DeviceBlock.objects.select_related('user', 'device', 'blocked_by').filter(
        is_active=True
    ).order_by('-created_at')

    sharing_alerts = DeviceSecurityEvent.objects.select_related('user', 'device').filter(
        event_type__in=(
            'account_sharing_suspected',
            'excessive_simultaneous_sessions',
            'distant_simultaneous_locations',
            'concurrent_playback_multiple_devices',
            'unfamiliar_device_reported',
        )
    ).order_by('-created_at')[:20]

    unified_devices = []
    try:
        from api_v1.device_security_service import build_unified_devices_registry
        unified_devices = build_unified_devices_registry(
            search_query=q,
            trust_filter=trust_filter,
            limit=120,
        )
    except Exception:
        unified_devices = []

    risk_profiles = (
        UserSecurityProfile.objects
        .select_related('user')
        .order_by('-behavior_risk_score', '-ai_risk_score', '-analyzed_at')[:60]
    )
    high_risk_users_count = UserSecurityProfile.objects.filter(
        behavior_risk_level__in=('high', 'critical')
    ).count()

    ctx.update({
        'policy': policy,
        'ai_config': get_effective_ai_config(policy),
        'ai_summary': policy.last_ai_audit_summary if isinstance(policy.last_ai_audit_summary, dict) else {},
        'risk_profiles': risk_profiles,
        'devices': devices_qs[:60],
        'unified_devices': unified_devices,
        'events': events_qs[:60],
        'active_sessions': active_sessions_qs[:40],
        'active_blocks': active_blocks_qs[:40],
        'sharing_alerts': sharing_alerts,
        'q': q,
        'trust_filter': trust_filter,
        'severity_filter': severity_filter,
        'event_status_filter': event_status_filter,
        'trust_choices': DeviceTrustStatus.choices,
        'stats': {
            'total_devices': len(unified_devices) if not (q or trust_filter) else RegisteredDevice.objects.count(),
            'unique_physical_devices': len(unified_devices),
            'active_devices': RegisteredDevice.objects.filter(is_active=True).count(),
            'suspicious_devices': RegisteredDevice.objects.filter(
                trust_status__in=[DeviceTrustStatus.SUSPICIOUS, DeviceTrustStatus.RESTRICTED]
            ).count(),
            'blocked_devices': DeviceBlock.objects.filter(is_active=True).count(),
            'active_sessions': active_sessions_qs.count(),
            'open_events': DeviceSecurityEvent.objects.filter(investigation_status='open').count(),
            'critical_events': DeviceSecurityEvent.objects.filter(
                severity='critical',
                investigation_status='open',
            ).count(),
            'high_risk_users': high_risk_users_count,
        },
    })
    return ctx


# ==========================================================
# 10. مركز أمان الأجهزة ومكافحة الحسابات المشتركة والعبث
# ==========================================================
@moderator_required
def security_dashboard(request):
    """لوحة مراقبة الأجهزة، المخاطر السلوكية، الحظر، والجلسات النشطة."""
    ctx = _build_security_dashboard_context(request)
    if is_ajax_request(request) and request.GET.get('partial') == '1':
        html = render_to_string('admin_panel/partials/_security_panels.html', ctx, request=request)
        return ajax_success(
            data={
                'html': html,
                'stats': ctx['stats'],
                'counts': {
                    'unified_devices': len(ctx['unified_devices']),
                    'events': len(ctx['events']),
                    'active_sessions': len(ctx['active_sessions']),
                    'risk_profiles': len(ctx['risk_profiles']),
                },
            }
        )
    return render(request, 'admin_panel/security_dashboard.html', ctx)


@moderator_required
def security_device_detail(request, device_id):
    """تفاصيل جهاز مسجّل: البصمات، تاريخ IP، الجلسات، النشاط، والأحداث الأمنية."""
    from api_v1.models import DeviceBlock, RegisteredDevice

    ctx = _base_context(request)
    device = get_object_or_404(RegisteredDevice.objects.select_related('user'), id=device_id)
    ctx.update({
        'device': device,
        'fingerprints': device.fingerprints.order_by('-created_at')[:20],
        'sessions': device.sessions.order_by('-last_seen_at')[:30],
        'activities': device.activities.order_by('-created_at')[:40],
        'events': device.security_events.order_by('-created_at')[:40],
        'blocks': DeviceBlock.objects.filter(
            Q(device=device) | Q(installation_id=device.installation_id)
        ).order_by('-created_at')[:15],
        'user_other_devices': RegisteredDevice.objects.filter(user=device.user).exclude(pk=device.pk)[:10],
    })
    return render(request, 'admin_panel/security_device_detail.html', ctx)


@moderator_required
def security_admin_action(request):
    """تنفيذ إجراءات الأمان الإدارية من لوحة التحكم (حظر، فك حظر، إبطال جلسة، سياسات، تحقيق)."""
    if request.method != 'POST':
        if is_ajax_request(request):
            return ajax_error("طريقة الطلب غير مدعومة.", status=405)
        return redirect('admin_panel:security_dashboard')

    from api_v1.device_security_service import (
        block_device_admin,
        prune_expired_telemetry,
        revoke_user_device,
        unblock_device_admin,
    )
    from api_v1.models import (
        DeviceBlock,
        DeviceSecurityEvent,
        DeviceSession,
        DeviceTrustStatus,
        PlaybackSession,
        RegisteredDevice,
        SecurityPolicyConfig,
    )

    from django.utils.http import url_has_allowed_host_and_scheme

    action = (request.POST.get('action') or '').strip()
    raw_next = (request.POST.get('next') or '').strip()
    if raw_next and url_has_allowed_host_and_scheme(
        raw_next,
        allowed_hosts={request.get_host()},
        require_https=request.is_secure(),
    ):
        next_url = raw_next
    else:
        next_url = reverse('admin_panel:security_dashboard')

    def _finish(ok, msg, extra=None, status=200):
        if is_ajax_request(request):
            payload = {'action': action}
            if extra:
                payload.update(extra)
            if ok:
                return ajax_success(msg, data=payload, status=status)
            return ajax_error(msg, status=status or 400, data=payload)
        if ok:
            messages.success(request, msg)
        else:
            messages.error(request, msg)
        return redirect(next_url)

    def _is_checked(field_name):
        return request.POST.get(field_name) in ('on', '1', 'true', 'yes')

    if action == 'block_device':
        device_id = request.POST.get('device_id')
        inst_id = (request.POST.get('installation_id') or '').strip()
        hw_id = (request.POST.get('hardware_id') or '').strip()
        device = RegisteredDevice.objects.filter(id=device_id).first() if device_id else None
        if not device and inst_id:
            device = RegisteredDevice.objects.filter(installation_id=inst_id).first()
        block_type = 'temporary' if request.POST.get('block_type') == 'temporary' else 'permanent'
        try:
            duration_hours = max(int(request.POST.get('duration_hours') or 24), 1)
        except ValueError:
            duration_hours = 24
        reason = (request.POST.get('reason') or 'حظر إداري من لوحة التحكم (تطبيق + متصفح)').strip()
        if device or inst_id or hw_id:
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
            AuditLog.log(
                request,
                AuditLog.ACTION_BLOCK_DEVICE,
                target_label=hw_id or blk.fingerprint_hash or blk.installation_id,
                target_id=device.id if device else None,
                details={'block_type': block_type, 'hardware_id': hw_id or blk.fingerprint_hash, 'reason': reason, 'duration_hours': duration_hours},
            )
            return _finish(
                True,
                f"تم حظر الجهاز ({hw_id or blk.fingerprint_hash or blk.installation_id}) على التطبيق والمتصفح وإبطال جلساته.",
                extra={'is_blocked': True, 'hardware_id': hw_id},
            )
        return _finish(False, "تعذر العثور على الجهاز المطلوب حظره.", status=404)

    elif action == 'unblock_device':
        block_id = request.POST.get('block_id')
        device_id = request.POST.get('device_id')
        inst_id = (request.POST.get('installation_id') or '').strip()
        hw_id = (request.POST.get('hardware_id') or '').strip()
        device = RegisteredDevice.objects.filter(id=device_id).first() if device_id else None
        if block_id and not inst_id and not hw_id:
            blk = get_object_or_404(DeviceBlock, id=block_id)
            inst_id = blk.installation_id
            if str(blk.fingerprint_hash or '').startswith('DEV-'):
                hw_id = blk.fingerprint_hash
            device = device or blk.device
        reason = (request.POST.get('reason') or 'رفع الحظر بواسطة الإدارة').strip()
        if inst_id or device or hw_id:
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
                target_label=hw_id or inst_id or (device.installation_id if device else ''),
                target_id=device.id if device else None,
                details={'unblocked_count': count, 'hardware_id': hw_id, 'reason': reason},
            )
            return _finish(
                True,
                "تم فك حظر الجهاز (التطبيق والمتصفح) بنجاح.",
                extra={'is_blocked': False, 'unblocked_count': count, 'hardware_id': hw_id},
            )
        return _finish(False, "بيانات الجهاز غير كافية لفك الحظر.", status=400)

    elif action == 'revoke_device':
        device = get_object_or_404(RegisteredDevice, id=request.POST.get('device_id'))
        revoke_user_device(
            device=device,
            actor=request.user,
            request=request,
            mode='revoke',
            reason=request.POST.get('reason') or 'revoked_by_admin_panel',
        )
        AuditLog.log(
            request,
            AuditLog.ACTION_REVOKE_SESSION,
            target_label=device.installation_id,
            target_id=device.id,
            details={'action': 'revoke_device'},
        )
        return _finish(True, "تم إلغاء تفويض الجهاز وإنهاء جلساته.", extra={'device_id': device.id})

    elif action == 'force_reauth':
        device = get_object_or_404(RegisteredDevice, id=request.POST.get('device_id'))
        device.requires_reauth = True
        if device.trust_status != DeviceTrustStatus.BLOCKED:
            device.trust_status = DeviceTrustStatus.PENDING
        device.save(update_fields=['requires_reauth', 'trust_status'])
        DeviceSession.objects.filter(device=device, status='active').update(
            status='revoked',
            ended_at=timezone.now(),
            revoked_reason='force_reauth_admin_panel',
        )
        msg = "تم إلزام الجهاز بإعادة التحقق."
        if is_ajax_request(request):
            return ajax_success(msg, data={'action': action, 'device_id': device.id, 'trust_status': device.trust_status})
        messages.info(request, msg)
        return redirect(next_url)

    elif action == 'revoke_session':
        sess = get_object_or_404(DeviceSession, id=request.POST.get('session_id'))
        sess.status = 'revoked'
        sess.ended_at = timezone.now()
        sess.revoked_reason = 'revoked_by_admin_panel'
        sess.save(update_fields=['status', 'ended_at', 'revoked_reason'])
        AuditLog.log(
            request,
            AuditLog.ACTION_REVOKE_SESSION,
            target_label=str(sess.session_uuid),
            target_id=sess.user_id,
            details={'installation_id': sess.installation_id},
        )
        return _finish(True, "تم إنهاء الجلسة بنجاح.", extra={'session_id': sess.id})

    elif action == 'revoke_all_user_sessions':
        target_user = get_object_or_404(User, id=request.POST.get('user_id'))
        now = timezone.now()
        DeviceSession.objects.filter(user=target_user, status='active').update(
            status='revoked',
            ended_at=now,
            revoked_reason='revoked_all_admin_panel',
        )
        PlaybackSession.objects.filter(user=target_user, status='active').update(
            status='revoked',
            revoked_reason='revoked_all_admin_panel',
        )
        return _finish(
            True,
            f"تم إنهاء جميع الجلسات النشطة للمستخدم {target_user.username}.",
            extra={'user_id': target_user.id},
        )

    elif action == 'resolve_event':
        evt = get_object_or_404(DeviceSecurityEvent, id=request.POST.get('event_id'))
        inv_status = (request.POST.get('investigation_status') or 'resolved').strip()
        notes = (request.POST.get('investigation_notes') or '').strip()
        if inv_status in ('open', 'investigating', 'resolved', 'false_positive'):
            evt.investigation_status = inv_status
            if notes:
                evt.investigation_notes = notes
            evt.reviewed_by = request.user
            evt.reviewed_at = timezone.now()
            evt.save(update_fields=['investigation_status', 'investigation_notes', 'reviewed_by', 'reviewed_at'])
            if inv_status == 'false_positive' and evt.device and evt.device.trust_status != DeviceTrustStatus.BLOCKED:
                dev = evt.device
                dev.trust_status = DeviceTrustStatus.TRUSTED
                dev.requires_reauth = False
                dev.risk_score = max(dev.risk_score - 40, 0)
                dev.risk_level = 'low' if dev.risk_score < 30 else 'medium'
                dev.save(update_fields=['trust_status', 'requires_reauth', 'risk_score', 'risk_level'])
            return _finish(
                True,
                "تم تحديث حالة الحدث الأمني.",
                extra={'event_id': evt.id, 'investigation_status': inv_status},
            )
        return _finish(False, "حالة التحقيق غير صالحة.", status=400)

    elif action == 'update_policy':
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
        ):
            raw_v = request.POST.get(field)
            if raw_v is not None and str(raw_v).isdigit():
                setattr(policy, field, max(int(raw_v), 1))
        policy.enforce_device_limits = _is_checked('enforce_device_limits')
        policy.enforce_screen_capture_policy = _is_checked('enforce_screen_capture_policy')
        policy.set_boot_guard_flags(
            block_vpn=_is_checked('block_vpn_connections'),
            block_dev_options=_is_checked('block_developer_options'),
            block_abnormal_net=_is_checked('block_abnormal_dns_or_ports'),
        )
        policy.save()
        AuditLog.log(
            request,
            AuditLog.ACTION_SECURITY_POLICY,
            target_label='SecurityPolicyConfig',
            target_id=policy.id,
            details={'student_device_limit': policy.student_device_limit},
        )
        return _finish(True, "تم حفظ إعدادات سياسة الأمان وحدود الأجهزة.")

    elif action == 'toggle_maintenance_device':
        hw_id = (request.POST.get('hardware_id') or '').strip()
        inst_id = (request.POST.get('installation_id') or '').strip()
        device_id = request.POST.get('device_id')
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
            return _finish(False, "يجب تحديد معرّف الجهاز المادي DEV-XXXX.", status=400)
        policy = SecurityPolicyConfig.load()
        raw_approved = request.POST.get('approved')
        if raw_approved is not None:
            approved = str(raw_approved).lower() in ('1', 'true', 'yes', 'on')
        else:
            approved = not policy.is_device_maintenance_approved(target_ident)
        policy.set_device_maintenance_approval(target_ident, approved=approved)
        policy.save()
        AuditLog.log(
            request,
            AuditLog.ACTION_SECURITY_POLICY,
            target_label=target_ident,
            details={'action': 'toggle_maintenance_device', 'approved': approved},
        )
        return _finish(
            True,
            f"تم {'اعتماد' if approved else 'إلغاء اعتماد'} الجهاز ({target_ident}) لظهور زر دخول الإدارة في وضع الصيانة.",
            extra={'approved': approved, 'hardware_id': target_ident},
        )

    elif action == 'update_ai_config':
        policy = SecurityPolicyConfig.load()
        policy.ai_security_enabled = _is_checked('ai_security_enabled')
        policy.ai_hourly_schedule_enabled = _is_checked('ai_hourly_schedule_enabled')
        policy.ai_auto_enforce_bans = _is_checked('ai_auto_enforce_bans')
        raw_provider = (request.POST.get('ai_provider') or '').strip().lower()
        if raw_provider in ('auto', 'gemini', 'openai', 'groq', 'deepseek'):
            policy.ai_provider = raw_provider
        raw_model = (request.POST.get('ai_model_name') or '').strip()
        if raw_model:
            policy.ai_model_name = raw_model[:64]
        if request.POST.get('clear_ai_key') == '1':
            policy.ai_api_key_override = ''
        else:
            raw_key = (request.POST.get('ai_api_key_override') or '').strip()
            if raw_key and raw_key != 'PUT_YOUR_AI_API_KEY_HERE':
                policy.ai_api_key_override = raw_key[:255]
        policy.save()
        AuditLog.log(
            request,
            AuditLog.ACTION_TOGGLE_AI,
            target_label='AI Security Analyst',
            target_id=policy.id,
            details={
                'ai_security_enabled': policy.ai_security_enabled,
                'ai_hourly_schedule_enabled': policy.ai_hourly_schedule_enabled,
                'ai_auto_enforce_bans': policy.ai_auto_enforce_bans,
                'ai_provider': policy.ai_provider,
                'ai_model_name': policy.ai_model_name,
            },
        )
        return _finish(
            True,
            "تم حفظ إعدادات الذكاء الاصطناعي الأمني بنجاح.",
            extra={
                'ai_security_enabled': policy.ai_security_enabled,
                'ai_provider': policy.ai_provider,
                'ai_model_name': policy.ai_model_name,
            },
        )

    elif action == 'analyze_user_behavior':
        from api_v1.security_engine import (
            analyze_user_with_ai,
            run_hourly_ai_behavioral_audit,
        )
        raw_uid = (request.POST.get('user_id') or '').strip()
        if raw_uid:
            target_user = get_object_or_404(User, id=raw_uid)
            res = analyze_user_with_ai(target_user, enforce_if_flagged=True, request=request)
            verdict = res.get('verdict') or {}
            return _finish(
                True,
                f"تم فحص {target_user.get_full_name() or target_user.email}: الخطورة {verdict.get('risk_score', 0)}% ({verdict.get('recommended_action', 'none')}) — {verdict.get('reason_ar', '')}",
                extra={'user_id': target_user.id, 'verdict': verdict},
            )
        summary = run_hourly_ai_behavioral_audit(force=True, request=request)
        return _finish(
            True,
            f"تم تشغيل فحص الذكاء الاصطناعي لـ {summary.get('analyzed_users', 0)} مستخدماً (خطورة عالية: {summary.get('flagged_high_risk', 0)} | حظر تلقائي: {summary.get('banned_users', 0)} حساب / {summary.get('banned_devices', 0)} جهاز).",
            extra={'summary': summary},
        )

    elif action in ('ban_user_only', 'ban_device_only', 'ban_user_and_device'):
        from api_v1.security_engine import enforce_security_ban
        raw_uid = (request.POST.get('user_id') or '').strip()
        inst_id = (request.POST.get('installation_id') or '').strip()
        target_user = User.objects.filter(id=raw_uid).first() if raw_uid else None
        device = RegisteredDevice.objects.filter(installation_id=inst_id).first() if inst_id else None
        if not device and target_user is not None:
            device = RegisteredDevice.objects.filter(user=target_user).order_by('-last_active_at').first()
            if device and not inst_id:
                inst_id = device.installation_id
        mode = (
            'user_only'
            if action == 'ban_user_only'
            else ('device_only' if action == 'ban_device_only' else 'device_and_user')
        )
        reason = (request.POST.get('reason') or f'حظر أمني ({mode}) من تقارير الذكاء الاصطناعي').strip()
        if target_user is None and not inst_id:
            return _finish(False, "بيانات المستخدم أو الجهاز غير كافية لتنفيذ الحظر.", status=400)
        enforce_security_ban(
            user=target_user,
            device=device,
            installation_id=inst_id,
            mode=mode,
            reason=reason,
            block_type='permanent',
            duration_hours=24,
            actor=request.user,
            request=request,
        )
        return _finish(True, "تم تنفيذ الحظر الأمني بنجاح.", extra={'mode': mode, 'user_id': raw_uid})

    elif action == 'unban_user_and_devices':
        from api_v1.security_engine import unban_user_and_devices
        raw_uid = (request.POST.get('user_id') or '').strip()
        inst_id = (request.POST.get('installation_id') or '').strip()
        target_user = User.objects.filter(id=raw_uid).first() if raw_uid else None
        if target_user is None and not inst_id:
            return _finish(False, "بيانات المستخدم غير كافية لرفع الحظر.", status=400)
        unban_user_and_devices(
            user=target_user,
            installation_id=inst_id,
            mode='both',
            actor=request.user,
            reason=(request.POST.get('reason') or 'فك الحظر من لوحة الأمان').strip(),
            request=request,
        )
        return _finish(True, "تم فك الحظر عن الحساب والأجهزة بنجاح.", extra={'user_id': raw_uid})

    elif action == 'prune_telemetry':
        res = prune_expired_telemetry()
        return _finish(
            True,
            f"تم تنظيف السجلات المنتهية: {res['activities_deleted']} نشاط، {res['events_deleted']} حدث.",
            extra=res,
        )

    return _finish(False, "إجراء أمني غير معروف.", status=400)

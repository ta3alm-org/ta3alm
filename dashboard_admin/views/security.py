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

from dashboard_admin.views.base import _base_context

User = get_user_model()


# ==========================================================
# 10. مركز أمان الأجهزة ومكافحة الحسابات المشتركة والعبث
# ==========================================================
@moderator_required
def security_dashboard(request):
    """لوحة مراقبة الأجهزة، المخاطر السلوكية، الحظر، والجلسات النشطة."""
    import ipaddress
    from api_v1.models import (
        DeviceBlock,
        DeviceSecurityEvent,
        DeviceSession,
        DeviceTrustStatus,
        RegisteredDevice,
        SecurityPolicyConfig,
    )

    ctx = _base_context(request)
    policy = SecurityPolicyConfig.load()
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

    ctx.update({
        'policy': policy,
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
        },
    })
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
            messages.success(request, f"تم حظر الجهاز ({hw_id or blk.fingerprint_hash or blk.installation_id}) على التطبيق والمتصفح وإبطال جلساته.")
        else:
            messages.error(request, "تعذر العثور على الجهاز المطلوب حظره.")

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
            messages.success(request, "تم فك حظر الجهاز (التطبيق والمتصفح) بنجاح.")
        else:
            messages.error(request, "بيانات الجهاز غير كافية لفك الحظر.")

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
        messages.success(request, "تم إلغاء تفويض الجهاز وإنهاء جلساته.")

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
        messages.info(request, "تم إلزام الجهاز بإعادة التحقق.")

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
        messages.success(request, "تم إنهاء الجلسة بنجاح.")

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
        messages.success(request, f"تم إنهاء جميع الجلسات النشطة للمستخدم {target_user.username}.")

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
            messages.success(request, "تم تحديث حالة الحدث الأمني.")

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
        policy.enforce_device_limits = request.POST.get('enforce_device_limits') == 'on'
        policy.enforce_screen_capture_policy = request.POST.get('enforce_screen_capture_policy') == 'on'
        policy.set_boot_guard_flags(
            block_vpn=request.POST.get('block_vpn_connections') == 'on',
            block_dev_options=request.POST.get('block_developer_options') == 'on',
            block_abnormal_net=request.POST.get('block_abnormal_dns_or_ports') == 'on',
        )
        policy.save()
        AuditLog.log(
            request,
            AuditLog.ACTION_SECURITY_POLICY,
            target_label='SecurityPolicyConfig',
            target_id=policy.id,
            details={'student_device_limit': policy.student_device_limit},
        )
        messages.success(request, "تم حفظ إعدادات سياسة الأمان وحدود الأجهزة.")

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
            messages.error(request, "يجب تحديد معرّف الجهاز المادي DEV-XXXX.")
        else:
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
            messages.success(
                request,
                f"تم {'اعتماد' if approved else 'إلغاء اعتماد'} الجهاز ({target_ident}) لظهور زر دخول الإدارة في وضع الصيانة.",
            )

    elif action == 'prune_telemetry':
        res = prune_expired_telemetry()
        messages.success(
            request,
            f"تم تنظيف السجلات المنتهية: {res['activities_deleted']} نشاط، {res['events_deleted']} حدث.",
        )

    return redirect(next_url)

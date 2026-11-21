"""api_v1.services.device_security.events
Extracted from api_v1/device_security_service.py.
"""
from __future__ import annotations

from datetime import timedelta
from typing import Any
from django.utils import timezone
from core.models import Notification
from api_v1.models import (
    DeviceActivity,
    DeviceSecurityEvent,
    DeviceSession,
    RegisteredDevice,
    SecurityPolicyConfig,
    VideoSecurityAuditLog,
)

from api_v1.services.device_security.network import extract_network_context


def record_device_activity(
    *,
    request=None,
    user=None,
    device: RegisteredDevice | None = None,
    session: DeviceSession | None = None,
    activity_type: str,
    endpoint: str = '',
    metadata: dict[str, Any] | None = None,
    net_ctx: dict[str, Any] | None = None,
) -> DeviceActivity:
    ctx = net_ctx or extract_network_context(request)
    return DeviceActivity.objects.create(
        user=user if getattr(user, 'is_authenticated', False) else (user if getattr(user, 'pk', None) else None),
        device=device,
        session=session,
        activity_type=activity_type[:64],
        ip_address=ctx.get('ip_address'),
        country_code=ctx.get('country_code', '')[:16],
        region_name=ctx.get('region_name', '')[:128],
        isp_name=ctx.get('isp_name', '')[:128],
        is_vpn_or_proxy=bool(ctx.get('is_vpn_or_proxy')),
        endpoint=(endpoint or (getattr(request, 'path', '') if request is not None else ''))[:255],
        metadata=metadata or {},
    )


def record_security_event(
    *,
    event_type: str,
    severity: str = 'low',
    risk_score: int = 0,
    user=None,
    device: RegisteredDevice | None = None,
    installation_id: str = '',
    request=None,
    action_taken: str = 'logged',
    details: dict[str, Any] | None = None,
    net_ctx: dict[str, Any] | None = None,
    notify_user: bool = False,
    notify_title: str = '',
    notify_message: str = '',
) -> DeviceSecurityEvent:
    ctx = net_ctx or extract_network_context(request)
    resolved_user = user if (user is not None and getattr(user, 'pk', None)) else (device.user if device else None)
    resolved_inst = installation_id or (device.installation_id if device else '')

    evt = DeviceSecurityEvent.objects.create(
        user=resolved_user,
        device=device,
        installation_id=resolved_inst[:128],
        event_type=event_type[:64],
        severity=severity,
        risk_score=min(max(int(risk_score), 0), 100),
        ip_address=ctx.get('ip_address'),
        country_code=ctx.get('country_code', '')[:16],
        region_name=ctx.get('region_name', '')[:128],
        action_taken=action_taken[:64],
        details=details or {},
    )

    if resolved_user and notify_user and notify_message:
        try:
            Notification.objects.create(
                recipient=resolved_user,
                title=notify_title or 'تنبيه أمني لحسابك',
                message=notify_message,
                link='/devices/',
            )
        except Exception:
            pass

    return evt


def prune_expired_telemetry(retention_days: int | None = None) -> dict[str, int]:
    """ينفّذ سياسة الاحتفاظ بالبيانات وحذف سجلات النشاط والأحداث المغلقة القديمة."""
    days = retention_days if retention_days is not None else SecurityPolicyConfig.load().event_retention_days
    cutoff = timezone.now() - timedelta(days=max(int(days), 7))
    act_deleted, _ = DeviceActivity.objects.filter(created_at__lt=cutoff).delete()
    evt_deleted, _ = DeviceSecurityEvent.objects.filter(
        created_at__lt=cutoff,
        investigation_status__in=('resolved', 'false_positive'),
    ).delete()
    audit_deleted, _ = VideoSecurityAuditLog.objects.filter(created_at__lt=cutoff).delete()
    return {
        'activities_deleted': act_deleted,
        'events_deleted': evt_deleted,
        'video_logs_deleted': audit_deleted,
    }

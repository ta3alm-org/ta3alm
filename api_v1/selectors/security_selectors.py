"""api_v1.selectors.security_selectors
Extracted from api_v1/security_engine.py.
"""
from __future__ import annotations

from datetime import timedelta
from typing import Any
from django.utils import timezone
from api_v1.models import (
    DeviceActivity,
    DeviceSecurityEvent,
    RegisteredDevice,
    UserSecurityProfile,
)


def collect_user_today_telemetry(user, *, since=None) -> dict[str, Any]:
    """تجميع بصمة سلوك المستخدم وحركاته وأجهزته اليوم لإرسالها لمحلل الذكاء الاصطناعي."""
    from django.db.models import Count

    now = timezone.now()
    today_start = since or timezone.localtime(now).replace(hour=0, minute=0, second=0, microsecond=0)

    today_activities = DeviceActivity.objects.filter(user=user, created_at__gte=today_start)
    action_breakdown = {
        row['activity_type']: row['c']
        for row in today_activities.values('activity_type').annotate(c=Count('id'))
    }
    distinct_ips = list(
        today_activities.filter(ip_address__isnull=False)
        .values_list('ip_address', flat=True)
        .distinct()[:12]
    )
    distinct_countries = list(
        today_activities.exclude(country_code='')
        .values_list('country_code', flat=True)
        .distinct()[:8]
    )
    vpn_hits = today_activities.filter(is_vpn_or_proxy=True).count()

    devices_data = []
    for d in RegisteredDevice.objects.filter(user=user).order_by('-last_active_at')[:10]:
        sig = d.integrity_signals if isinstance(d.integrity_signals, dict) else {}
        devices_data.append({
            'installation_id': d.installation_id,
            'device_name': d.device_name,
            'os': d.os_name,
            'trust_status': d.trust_status,
            'is_active': d.is_active,
            'risk_score': d.risk_score,
            'last_ip': d.last_ip,
            'proxy_detected': bool(sig.get('proxy_detected')),
            'user_ca_detected': bool(sig.get('user_ca_detected')),
            'mitm_ca_detected': bool(sig.get('mitm_ca_detected')),
            'frida_detected': bool(sig.get('frida_detected')),
            'hooking_detected': bool(sig.get('hooking_detected')),
            'root_detected': bool(sig.get('root_detected')),
        })

    recent_events = [
        {
            'event_type': e.event_type,
            'severity': e.severity,
            'risk_score': e.risk_score,
            'installation_id': e.installation_id,
            'action_taken': e.action_taken,
            'created_at': e.created_at.isoformat() if e.created_at else None,
        }
        for e in DeviceSecurityEvent.objects.filter(user=user, created_at__gte=today_start - timedelta(days=2)).order_by('-created_at')[:15]
    ]

    sec_prof, _ = UserSecurityProfile.objects.get_or_create(user=user)
    return {
        'user_id': user.id,
        'role': user.role,
        'is_banned': user.is_banned,
        'today_total_actions': today_activities.count(),
        'today_action_breakdown': action_breakdown,
        'today_distinct_ips': [str(ip) for ip in distinct_ips],
        'today_distinct_countries': distinct_countries,
        'today_vpn_hits': vpn_hits,
        'lifetime_failed_logins': sec_prof.total_failed_logins,
        'proxy_tamper_strikes': sec_prof.proxy_tamper_strikes,
        'sharing_strikes': sec_prof.sharing_strikes,
        'heuristic_score': sec_prof.behavior_risk_score,
        'devices': devices_data,
        'recent_security_events': recent_events,
    }

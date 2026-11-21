"""api_v1.services.security_engine.behavioral
Extracted from api_v1/security_engine.py.
"""
from __future__ import annotations

from datetime import timedelta
from typing import Any
from django.core.cache import cache
from django.db.models import Q
from django.utils import timezone
from api_v1.device_security_service import (
    extract_network_context,
    record_device_activity,
)
from api_v1.models import (
    DeviceActivity,
    DeviceBlock,
    DeviceSecurityEvent,
    DeviceTrustStatus,
    RegisteredDevice,
    SecurityPolicyConfig,
    UserSecurityProfile,
)

from api_v1.services.security_engine.constants import _HIGH_VALUE_SIGNAL_TAGS


def is_protected_admin_user(user) -> bool:
    if not user or not getattr(user, 'pk', None):
        return False
    return bool(getattr(user, 'is_superuser', False) or getattr(user, 'role', '') == 'admin')


def compute_behavioral_risk(user, *, recent_signal_tag: str = '', risk_delta: int = 0) -> dict[str, Any]:
    """
    نموذج التحليل السلوكي للمستخدم عبر تجميع الإشارات التاريخية واللحظية من السجلات والأجهزة والأحداث.
    """
    now = timezone.now()
    last_15m = now - timedelta(minutes=15)
    last_1h = now - timedelta(hours=1)
    last_7d = now - timedelta(days=7)

    profile, _ = UserSecurityProfile.objects.get_or_create(user=user)
    policy = SecurityPolicyConfig.load()

    failed_15m = DeviceActivity.objects.filter(
        user=user,
        activity_type='login_failed',
        created_at__gte=last_15m,
    ).count()

    burst_1m = DeviceActivity.objects.filter(
        user=user,
        created_at__gte=now - timedelta(minutes=1),
    ).count()

    distinct_ips_1h = (
        DeviceActivity.objects.filter(user=user, created_at__gte=last_1h, ip_address__isnull=False)
        .values('ip_address')
        .distinct()
        .count()
    )

    open_high_events = DeviceSecurityEvent.objects.filter(
        user=user,
        investigation_status__in=('open', 'investigating'),
        severity__in=('high', 'critical'),
        created_at__gte=last_7d,
    ).count()

    blocked_devices_count = DeviceBlock.objects.filter(
        user=user,
        is_active=True,
    ).count()

    active_devices_count = (
        RegisteredDevice.objects.filter(user=user, is_active=True)
        .exclude(trust_status__in=[DeviceTrustStatus.REVOKED, DeviceTrustStatus.BLOCKED])
        .count()
    )

    reasons: list[str] = []
    score = 0

    if failed_15m >= max(policy.rapid_login_threshold_5m, 4):
        score += min(failed_15m * 6, 30)
        reasons.append(f'repeated_failed_logins:{failed_15m}')

    if burst_1m >= 65:
        score += 20
        reasons.append(f'abnormal_request_burst:{burst_1m}')

    if distinct_ips_1h >= 4:
        score += 20
        reasons.append(f'multiple_ips_1h:{distinct_ips_1h}')

    if profile.proxy_tamper_strikes > 0:
        score += min(profile.proxy_tamper_strikes * 45, 95)
        reasons.append(f'proxy_or_tamper_strikes:{profile.proxy_tamper_strikes}')

    if profile.sharing_strikes > 0:
        score += min(profile.sharing_strikes * 25, 65)
        reasons.append(f'account_sharing_strikes:{profile.sharing_strikes}')

    if open_high_events > 0:
        score += min(open_high_events * 20, 60)
        reasons.append(f'open_high_security_events:{open_high_events}')

    if blocked_devices_count > 0:
        score += 30
        reasons.append(f'active_blocked_devices:{blocked_devices_count}')

    if getattr(user, 'role', '') == 'student' and active_devices_count > policy.student_device_limit:
        score += 25
        reasons.append('device_limit_exceeded')

    if risk_delta > 0:
        score = max(score, min(profile.behavior_risk_score + risk_delta, 100))

    if recent_signal_tag:
        reasons.append(recent_signal_tag)

    score = min(max(int(score), 0), 100)
    if score >= policy.risk_threshold_critical:
        level = 'critical'
    elif score >= policy.risk_threshold_high:
        level = 'high'
    elif score >= policy.risk_threshold_medium:
        level = 'medium'
    else:
        level = 'low'

    profile.behavior_risk_score = score
    profile.behavior_risk_level = level
    profile.last_signals = {
        'reasons': reasons,
        'failed_15m': failed_15m,
        'burst_1m': burst_1m,
        'distinct_ips_1h': distinct_ips_1h,
        'open_high_events': open_high_events,
        'blocked_devices': blocked_devices_count,
    }
    profile.save(update_fields=['behavior_risk_score', 'behavior_risk_level', 'last_signals', 'analyzed_at'])

    return {
        'score': score,
        'level': level,
        'reasons': reasons,
        'profile': profile,
    }


def record_behavioral_activity(
    *,
    request=None,
    user=None,
    activity_type: str,
    endpoint: str = '',
    device: RegisteredDevice | None = None,
    installation_id: str = '',
    signal_tag: str = '',
    risk_delta: int = 0,
    metadata: dict[str, Any] | None = None,
    net_ctx: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """
    يسجّل النشاط الفردي في DeviceActivity ويحدّث ملف UserSecurityProfile السلوكي،
    وينفّذ الحظر التلقائي إذا رُصدت محاولة MITM / Proxy / تلاعب وفق سياسة الإدارة.
    """
    from api_v1.services.security_engine.enforcement import enforce_security_ban
    ctx = net_ctx or (extract_network_context(request) if request is not None else {})
    clean_inst = str(installation_id or (device.installation_id if device else '') or '').strip()
    is_auth_user = bool(user is not None and getattr(user, 'pk', None) and getattr(user, 'is_authenticated', True))

    if device is None and is_auth_user and clean_inst:
        device = RegisteredDevice.objects.filter(user=user, installation_id=clean_inst).first()

    meta = dict(metadata or {})
    if clean_inst and 'installation_id' not in meta:
        meta['installation_id'] = clean_inst
    if signal_tag and 'signal_tag' not in meta:
        meta['signal_tag'] = signal_tag

    record_device_activity(
        request=request,
        user=user if is_auth_user else None,
        device=device,
        activity_type=activity_type,
        endpoint=endpoint or (getattr(request, 'path', '') if request is not None else ''),
        metadata=meta,
        net_ctx=ctx,
    )

    if not is_auth_user:
        return {'analyzed': False, 'enforcement': None}

    now = timezone.now()
    profile, _ = UserSecurityProfile.objects.get_or_create(user=user)
    profile.total_actions_count += 1
    if activity_type == 'login_failed':
        profile.total_failed_logins += 1
    if signal_tag in _HIGH_VALUE_SIGNAL_TAGS:
        profile.proxy_tamper_strikes += 1
    if signal_tag == 'account_sharing':
        profile.sharing_strikes += 1

    profile.last_action_type = activity_type[:64]
    profile.last_action_endpoint = (endpoint or (getattr(request, 'path', '') if request is not None else ''))[:255]
    profile.last_action_at = now
    if ctx.get('ip_address'):
        profile.last_ip = ctx['ip_address']
    if ctx.get('country_code'):
        profile.last_country = ctx['country_code'][:16]
    profile.save(
        update_fields=[
            'total_actions_count',
            'total_failed_logins',
            'proxy_tamper_strikes',
            'sharing_strikes',
            'last_action_type',
            'last_action_endpoint',
            'last_action_at',
            'last_ip',
            'last_country',
            'analyzed_at',
        ]
    )

    should_recompute_risk = bool(
        signal_tag
        or risk_delta > 0
        or activity_type == 'login_failed'
        or profile.analyzed_at is None
        or not cache.get(f'ta3alm:behav_risk_fresh:{user.id}')
    )
    if should_recompute_risk:
        risk_info = compute_behavioral_risk(user, recent_signal_tag=signal_tag, risk_delta=risk_delta)
        cache.set(f'ta3alm:behav_risk_fresh:{user.id}', 1, timeout=60)
    else:
        reasons = (
            profile.last_signals.get('reasons', [])
            if isinstance(profile.last_signals, dict)
            else []
        )
        risk_info = {
            'score': profile.behavior_risk_score,
            'level': profile.behavior_risk_level,
            'reasons': reasons,
            'profile': profile,
        }

    policy = SecurityPolicyConfig.load()
    enforcement_result = None
    should_auto_ban = False
    ban_reason = ''

    if policy.auto_enforcement_mode != 'warn' and not is_protected_admin_user(user):
        if signal_tag in ('proxy_mitm', 'user_ca_mitm', 'request_tamper', 'replay_attack') and policy.auto_block_on_proxy_mitm:
            should_auto_ban = True
            ban_reason = f'حظر أمني تلقائي: رصد اعتراض أو بروكسي/MITM ({signal_tag})'
        elif signal_tag in ('frida', 'hooking', 'integrity_tamper') and policy.auto_ban_on_tamper:
            should_auto_ban = True
            ban_reason = f'حظر أمني تلقائي: رصد أداة عبث أو حقن ({signal_tag})'
        elif signal_tag == 'account_sharing' and policy.auto_ban_on_account_sharing and risk_info['score'] >= policy.risk_threshold_critical:
            should_auto_ban = True
            ban_reason = 'حظر تلقائي بسبب تكرار مشاركة الحساب بشكل حرج.'

    if should_auto_ban:
        enforcement_result = enforce_security_ban(
            user=user,
            device=device,
            installation_id=clean_inst,
            mode=policy.auto_enforcement_mode or 'device_and_user',
            reason=ban_reason,
            block_type='permanent',
            actor=None,
            request=request,
        )

    return {
        'analyzed': True,
        'risk_score': risk_info['score'],
        'risk_level': risk_info['level'],
        'reasons': risk_info['reasons'],
        'enforcement': enforcement_result,
    }


def serialize_user_security_profile(profile: UserSecurityProfile) -> dict[str, Any]:
    u = profile.user
    active_blocks = DeviceBlock.objects.filter(
        Q(user=u) | Q(device__user=u),
        is_active=True,
    ).distinct().count()
    devices_count = RegisteredDevice.objects.filter(user=u, is_active=True).count()
    return {
        'id': profile.id,
        'user_id': u.id,
        'full_name': f"{u.first_name} {u.last_name}".strip() or u.username,
        'email': u.email,
        'phone': u.phone,
        'custom_id': u.custom_id,
        'role': u.role,
        'is_banned': u.is_banned,
        'behavior_risk_score': profile.behavior_risk_score,
        'behavior_risk_level': profile.behavior_risk_level,
        'total_actions_count': profile.total_actions_count,
        'total_failed_logins': profile.total_failed_logins,
        'proxy_tamper_strikes': profile.proxy_tamper_strikes,
        'sharing_strikes': profile.sharing_strikes,
        'last_action_type': profile.last_action_type,
        'last_action_endpoint': profile.last_action_endpoint,
        'last_action_at': profile.last_action_at.isoformat() if profile.last_action_at else None,
        'last_ip': profile.last_ip,
        'last_country': profile.last_country,
        'last_signals': profile.last_signals,
        'auto_ban_mode': profile.auto_ban_mode,
        'ban_reason': profile.ban_reason,
        'ai_risk_score': profile.ai_risk_score,
        'ai_recommended_action': profile.ai_recommended_action,
        'ai_analysis_summary': profile.ai_analysis_summary,
        'ai_last_analyzed_at': profile.ai_last_analyzed_at.isoformat() if profile.ai_last_analyzed_at else None,
        'active_device_blocks': active_blocks,
        'devices_count': devices_count,
        'analyzed_at': profile.analyzed_at.isoformat() if profile.analyzed_at else None,
    }

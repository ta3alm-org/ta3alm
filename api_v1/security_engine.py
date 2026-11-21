"""
api_v1/security_engine.py
محرك التحليل السلوكي، التحقق التشفيري من توقيع الطلبات (Anti-MITM/Replay)، وتنفيذ الحظر الانتقائي أو المشترك (جهاز فقط / حساب فقط / كلاهما).
"""
from __future__ import annotations

import hashlib
import hmac
import time
from datetime import timedelta
from typing import Any

from django.conf import settings
from django.core.cache import cache
from django.db import transaction
from django.db.models import Q
from django.utils import timezone
from rest_framework.authtoken.models import Token

from dashboard_admin.models import AuditLog

from .device_security_service import (
    block_device_admin,
    extract_network_context,
    record_device_activity,
    record_security_event,
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

# أجزاء مقسمة ومقنّعة متطابقة رياضياً مع تطبيق Flutter (RequestSigner) لتجنب تخزين المفتاح كنص صريح واحد
_SHARD_A = (0x53, 0x62, 0x2F, 0x7A, 0x41, 0x19, 0x6E, 0x33)
_SHARD_B = (0x74, 0x31, 0x6D, 0x40, 0x5F, 0x24, 0x61, 0x38)
_SHARD_C = (0x6B, 0x39, 0x50, 0x72, 0x21, 0x64, 0x48, 0x57)
_SHARD_D = (0x66, 0x33, 0x45, 0x6C, 0x2D, 0x79, 0x37, 0x4D)
_MASK_SEQ = (0x27, 0x1B, 0x4C, 0x39, 0x12, 0x55, 0x0E, 0x61)

# أرقام البناء (Build Number) بدايةً من الإصدار المزود بتوقيع الطلبات وحماية MITM الإلزامية
MIN_SIGNED_NATIVE_BUILD = 6

_HIGH_VALUE_SIGNAL_TAGS = {
    'proxy_mitm',
    'user_ca_mitm',
    'request_tamper',
    'replay_attack',
    'frida',
    'hooking',
    'integrity_tamper',
}


def _derive_client_signing_key() -> bytes:
    """إعادة تجميع مفتاح HMAC-SHA256 المشتق من الشظايا المقنّعة مع دعم المتغير البيئي الاختياري."""
    import os

    override = os.environ.get('TA3ALM_CLIENT_SIGNING_SECRET', '').strip()
    if override:
        return hashlib.sha256(override.encode('utf-8')).digest()

    raw_bytes = bytearray()
    for shard_idx, shard in enumerate((_SHARD_A, _SHARD_B, _SHARD_C, _SHARD_D)):
        for i, val in enumerate(shard):
            raw_bytes.append((val ^ _MASK_SEQ[i] ^ ((shard_idx * 19 + i * 7) & 0xFF)) & 0xFF)
    salt = b'ta3alm.edge.hmac.v2'
    return hashlib.sha256(bytes(raw_bytes) + salt).digest()


def _empty_body_sha256() -> str:
    return hashlib.sha256(b'').hexdigest()


def _extract_raw_body_sha256(request) -> str:
    content_type = str(getattr(request, 'content_type', '') or request.META.get('CONTENT_TYPE', '') or '').lower()
    if 'multipart/form-data' in content_type:
        return _empty_body_sha256()
    try:
        raw = request.body or b''
    except Exception:
        raw = b''
    return hashlib.sha256(raw).hexdigest()


def verify_client_request_signature(request) -> dict[str, Any]:
    """
    يتحقق من صحة التوقيع التشفيري للطلب (HMAC-SHA256 + Anti-Replay Nonce + Timestamp Window).
    يُرجع قاموساً: {'valid': bool, 'present': bool, 'code': str, 'reason': str, 'tampered': bool}.
    """
    meta = getattr(request, 'META', {}) or {}
    sig = str(meta.get('HTTP_X_TA3ALM_SIG') or '').strip().lower()
    ts_raw = str(meta.get('HTTP_X_TA3ALM_TS') or '').strip()
    nonce = str(meta.get('HTTP_X_TA3ALM_NONCE') or '').strip()
    device_id = str(meta.get('HTTP_X_DEVICE_ID') or meta.get('HTTP_X_INSTALLATION_ID') or '').strip()
    platform = str(meta.get('HTTP_X_CLIENT_PLATFORM') or '').strip().lower()
    build_raw = str(meta.get('HTTP_X_APP_BUILD') or '').strip()

    present = bool(sig or ts_raw or nonce)
    policy = SecurityPolicyConfig.load()

    if not present:
        # إذا كان العميل يدّعي أنه إصدار التطبيق الجديد (build >= 6) ولكنه حذف ترويسات التوقيع عبر Proxy
        try:
            build_num = int(build_raw) if build_raw else 0
        except (TypeError, ValueError):
            build_num = 0
        must_sign = (
            policy.enforce_request_signatures
            and platform in ('android', 'ios')
            and build_num >= MIN_SIGNED_NATIVE_BUILD
        )
        if must_sign:
            return {
                'valid': False,
                'present': False,
                'tampered': True,
                'code': 'MISSING_REQUEST_SIGNATURE',
                'reason': 'تم حذف توقيع الأمان من الطلب أو اعتراضه عبر وسيط غير مصرح.',
            }
        return {'valid': True, 'present': False, 'tampered': False, 'code': 'NOT_REQUIRED', 'reason': ''}

    if not sig or not ts_raw or not nonce or len(nonce) < 12 or len(nonce) > 96:
        return {
            'valid': False,
            'present': True,
            'tampered': True,
            'code': 'MALFORMED_REQUEST_SIGNATURE',
            'reason': 'ترويسات التوقيع الأمني غير مكتملة أو تم العبث بها.',
        }

    try:
        req_ts = int(ts_raw)
    except (TypeError, ValueError):
        return {
            'valid': False,
            'present': True,
            'tampered': True,
            'code': 'INVALID_SIGNATURE_TIMESTAMP',
            'reason': 'طابع الوقت الأمني غير صالح.',
        }

    now_ts = int(time.time())
    max_skew = max(int(policy.request_signature_max_skew_seconds or 300), 60)
    if abs(now_ts - req_ts) > max_skew:
        return {
            'valid': False,
            'present': True,
            'tampered': True,
            'code': 'EXPIRED_REQUEST_SIGNATURE',
            'reason': 'انتهت صلاحية توقيع الطلب أو هناك فرق غير مقبول في التوقيت.',
        }

    body_hash = _extract_raw_body_sha256(request)
    canonical = f"{request.method.upper()}|{request.path}|{req_ts}|{nonce}|{body_hash}|{device_id}"
    expected_sig = hmac.new(
        _derive_client_signing_key(),
        canonical.encode('utf-8'),
        hashlib.sha256,
    ).hexdigest().lower()

    if not hmac.compare_digest(expected_sig, sig):
        return {
            'valid': False,
            'present': True,
            'tampered': True,
            'code': 'INVALID_REQUEST_SIGNATURE',
            'reason': 'فشل التحقق التشفيري من سلامة الطلب (محاولة تعديل أو MITM).',
        }

    nonce_cache_key = f"ta3alm:sig_nonce:{hashlib.sha256(f'{device_id}:{nonce}'.encode('utf-8')).hexdigest()}"
    added = cache.add(nonce_cache_key, 1, timeout=max_skew + 30)
    if not added:
        return {
            'valid': False,
            'present': True,
            'tampered': True,
            'code': 'REPLAY_ATTACK_DETECTED',
            'reason': 'تم رصد إعادة إرسال طلب مكرر (Replay Attack).',
        }

    return {'valid': True, 'present': True, 'tampered': False, 'code': 'OK', 'reason': ''}


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


@transaction.atomic
def enforce_security_ban(
    *,
    user=None,
    device: RegisteredDevice | None = None,
    installation_id: str = '',
    mode: str = 'device_and_user',
    reason: str = 'تم فرض حظر أمني تلقائي/إداري لحماية المنصة.',
    block_type: str = 'permanent',
    duration_hours: int = 24,
    actor=None,
    request=None,
) -> dict[str, Any]:
    """
    ينفّذ الحظر على:
    - device_only: حظر الجهاز المحدد (أو أجهزة المستخدم المرتبطة) وإبطال جلساته دون حظر الحساب.
    - user_only: حظر الحساب وإبطال جلساته دون وضع DeviceBlock دائم على الجهاز.
    - device_and_user: حظر الحساب والجهاز معاً وإلغاء كافة التوكنات وجلسات التشغيل.
    """
    clean_mode = mode if mode in ('device_only', 'user_only', 'device_and_user') else 'device_and_user'
    clean_inst = str(installation_id or (device.installation_id if device else '') or '').strip()
    now = timezone.now()

    if user is None and device is not None:
        user = device.user

    if is_protected_admin_user(user) and clean_mode in ('user_only', 'device_and_user'):
        # حماية حسابات الإدارة العليا من الحظر الآلي العرضي
        return {
            'enforced': False,
            'mode': 'protected_admin_skip',
            'blocked_devices': 0,
            'user_banned': False,
        }

    blocked_devices = 0
    if clean_mode in ('device_only', 'device_and_user'):
        target_devices: list[RegisteredDevice] = []
        if device is not None:
            target_devices.append(device)
        elif clean_inst:
            matched = RegisteredDevice.objects.filter(installation_id=clean_inst).first()
            if matched:
                target_devices.append(matched)
            else:
                block_device_admin(
                    device=None,
                    installation_id=clean_inst,
                    admin_user=actor,
                    block_type=block_type,
                    reason=reason,
                    duration_hours=duration_hours,
                    request=request,
                )
                blocked_devices += 1
        elif user is not None:
            target_devices.extend(list(RegisteredDevice.objects.filter(user=user)))

        seen_insts: set[str] = set()
        for dev in target_devices:
            if dev.installation_id in seen_insts:
                continue
            seen_insts.add(dev.installation_id)
            block_device_admin(
                device=dev,
                installation_id=dev.installation_id,
                admin_user=actor,
                block_type=block_type,
                reason=reason,
                duration_hours=duration_hours,
                request=request,
            )
            blocked_devices += 1

    user_banned = False
    if clean_mode in ('user_only', 'device_and_user') and user is not None and not is_protected_admin_user(user):
        user.is_banned = True
        user.save(update_fields=['is_banned'])
        user_banned = True

        DeviceSession.objects.filter(user=user, status='active').update(
            status='revoked',
            ended_at=now,
            revoked_reason=f'security_ban:{clean_mode}',
        )
        PlaybackSession.objects.filter(user=user, status='active').update(
            status='revoked',
            revoked_reason=f'security_ban:{clean_mode}',
            view_window_expires_at=now,
        )
        Token.objects.filter(user=user).delete()

    if user is not None:
        sec_prof, _ = UserSecurityProfile.objects.get_or_create(user=user)
        sec_prof.auto_ban_mode = clean_mode
        sec_prof.ban_reason = reason[:255]
        sec_prof.behavior_risk_score = max(sec_prof.behavior_risk_score, 90)
        sec_prof.behavior_risk_level = 'critical'
        sec_prof.save(
            update_fields=[
                'auto_ban_mode',
                'ban_reason',
                'behavior_risk_score',
                'behavior_risk_level',
                'analyzed_at',
            ]
        )

    record_security_event(
        event_type=f'security_ban_{clean_mode}',
        severity='critical',
        risk_score=95,
        user=user,
        device=device,
        installation_id=clean_inst,
        request=request,
        action_taken=clean_mode,
        details={
            'mode': clean_mode,
            'reason': reason,
            'blocked_devices': blocked_devices,
            'user_banned': user_banned,
            'actor_id': getattr(actor, 'id', None),
        },
    )

    if request is not None:
        AuditLog.log(
            request,
            AuditLog.ACTION_BAN if user_banned else AuditLog.ACTION_BLOCK_DEVICE,
            target_label=(
                (user.email or user.username) if user else clean_inst or 'unknown'
            ),
            target_id=getattr(user, 'id', None),
            details={'mode': clean_mode, 'installation_id': clean_inst, 'reason': reason},
        )

    return {
        'enforced': True,
        'mode': clean_mode,
        'blocked_devices': blocked_devices,
        'user_banned': user_banned,
    }


@transaction.atomic
def unban_user_and_devices(
    *,
    user=None,
    installation_id: str = '',
    mode: str = 'both',
    actor=None,
    reason: str = 'رفع الحظر بواسطة مسؤول المنصة',
    request=None,
) -> dict[str, Any]:
    """فك الحظر عن الحساب، الجهاز، أو كليهما مع إعادة ضبط مؤشرات التصعيد."""
    clean_mode = mode if mode in ('user_only', 'device_only', 'both') else 'both'
    user_unbanned = False
    devices_unblocked = 0

    if clean_mode in ('user_only', 'both') and user is not None:
        if user.is_banned:
            user.is_banned = False
            user.save(update_fields=['is_banned'])
        user_unbanned = True
        sec_prof, _ = UserSecurityProfile.objects.get_or_create(user=user)
        sec_prof.auto_ban_mode = 'none'
        sec_prof.ban_reason = ''
        sec_prof.proxy_tamper_strikes = 0
        sec_prof.total_failed_logins = 0
        sec_prof.behavior_risk_score = min(sec_prof.behavior_risk_score, 20)
        sec_prof.behavior_risk_level = 'low'
        sec_prof.save(
            update_fields=[
                'auto_ban_mode',
                'ban_reason',
                'proxy_tamper_strikes',
                'total_failed_logins',
                'behavior_risk_score',
                'behavior_risk_level',
                'analyzed_at',
            ]
        )

    if clean_mode in ('device_only', 'both'):
        if installation_id:
            dev = RegisteredDevice.objects.filter(installation_id=installation_id).first()
            devices_unblocked += unblock_device_admin(
                device=dev,
                installation_id=installation_id,
                admin_user=actor,
                reason=reason,
                request=request,
            )
        elif user is not None:
            for dev in RegisteredDevice.objects.filter(user=user):
                if dev.trust_status == DeviceTrustStatus.BLOCKED or DeviceBlock.objects.filter(
                    installation_id=dev.installation_id, is_active=True
                ).exists():
                    devices_unblocked += unblock_device_admin(
                        device=dev,
                        installation_id=dev.installation_id,
                        admin_user=actor,
                        reason=reason,
                        request=request,
                    )

    if request is not None:
        AuditLog.log(
            request,
            AuditLog.ACTION_UNBAN,
            target_label=(user.email or user.username) if user else installation_id,
            target_id=getattr(user, 'id', None),
            details={'mode': clean_mode, 'devices_unblocked': devices_unblocked, 'reason': reason},
        )

    return {
        'user_unbanned': user_unbanned,
        'devices_unblocked': devices_unblocked,
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

    risk_info = compute_behavioral_risk(user, recent_signal_tag=signal_tag, risk_delta=risk_delta)

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
        'active_device_blocks': active_blocks,
        'devices_count': devices_count,
        'analyzed_at': profile.analyzed_at.isoformat() if profile.analyzed_at else None,
    }

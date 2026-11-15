"""
api_v1/device_security_service.py
المحرك المركزي لهوية الأجهزة، البصمة متعددة الطبقات (Versioned Fingerprinting)،
تحليل الشبكة والـ IP، حدود الأجهزة، التحليل السلوكي، كشف مشاركة الحسابات، وحظر الأجهزة.
"""
from __future__ import annotations

import hashlib
import hmac
import ipaddress
import os
import re
import uuid
from datetime import timedelta
from typing import Any

from django.conf import settings
from django.contrib.auth import get_user_model
from django.core import signing
from django.core.cache import cache
from django.db import transaction
from django.db.models import Count, Q
from django.utils import timezone

from core.models import Notification

from .models import (
    DeviceActivity,
    DeviceBlock,
    DeviceFingerprint,
    DeviceIntegrityRecord,
    DeviceSecurityEvent,
    DeviceSession,
    DeviceTrustStatus,
    PlaybackSession,
    RegisteredDevice,
    SecurityPolicyConfig,
    VideoSecurityAuditLog,
)

User = get_user_model()

FINGERPRINT_ALGORITHM_VERSION = 'fp_v1'
MAX_IP_HISTORY_ENTRIES = 20
WEB_PACKAGE_NAME = 'web.ta3alm.online'
WEB_COOKIE_NAME = 'ta3alm_web_inst_id'
WEB_COOKIE_SALT = 'ta3alm-web-device-v1'

CORE_FINGERPRINT_FIELDS = ('manufacturer', 'model', 'cpu_arch', 'package_name')
SUPPORTING_FINGERPRINT_FIELDS = (
    'android_version',
    'api_level',
    'cpu_info',
    'gpu_renderer',
    'gpu_vendor',
    'screen_resolution',
    'app_version',
    'app_build_number',
    'signing_cert_sha256',
    'installer_source',
)
BENIGN_DRIFT_FIELDS = {
    'android_version',
    'api_level',
    'app_version',
    'app_build_number',
    'screen_resolution',
    'installer_source',
    'gpu_renderer',
    'gpu_vendor',
    'cpu_info',
}


def _fingerprint_secret() -> bytes:
    raw = os.environ.get('DEVICE_FINGERPRINT_SECRET', '').strip() or settings.SECRET_KEY
    return hashlib.sha256(f"ta3alm-device-fp-key:{raw}".encode('utf-8')).digest()


def validate_installation_id(raw_id: Any, user=None) -> tuple[bool, str, str | None]:
    """
    يتحقق من أن معرّف التثبيت عشوائي وقوي وليس بريداً إلكترونياً أو اسم مستخدم.
    يُرجع (is_valid, cleaned_id, error_message).
    """
    cleaned = str(raw_id or '').strip()
    if not cleaned:
        return False, '', 'معرّف التثبيت (installation_id) مطلوب.'
    if len(cleaned) < 8 or len(cleaned) > 128:
        return False, '', 'صيغة معرّف التثبيت غير صالحة.'
    if '@' in cleaned:
        return False, '', 'لا يُسمح باستخدام البريد الإلكتروني كمعرّف للجهاز.'
    if not re.match(r'^[A-Za-z0-9._:-]+$', cleaned):
        return False, '', 'يحتوي معرّف التثبيت على رموز غير مسموح بها.'
    if user is not None:
        disallowed = {
            str(getattr(user, 'username', '') or '').strip().lower(),
            str(getattr(user, 'email', '') or '').strip().lower(),
        }
        if cleaned.lower() in disallowed:
            return False, '', 'لا يُسمح باستخدام اسم المستخدم أو البريد كمعرّف للجهاز.'
    return True, cleaned[:128], None


def normalize_device_info(raw: dict[str, Any] | None) -> dict[str, Any]:
    """يطبع الخصائص الـ 15 المسموح بها لجمع بصمة الجهاز بشكل متسق."""
    src = raw if isinstance(raw, dict) else {}

    def _s(key: str, max_len: int = 128, lower: bool = False) -> str:
        val = str(src.get(key) or '').strip()
        val = re.sub(r'\s+', ' ', val)[:max_len]
        return val.lower() if lower else val

    try:
        api_level = max(int(src.get('api_level') or src.get('sdk_int') or 0), 0)
    except (TypeError, ValueError):
        api_level = 0

    cert = re.sub(r'[^0-9a-fA-F]', '', str(src.get('signing_cert_sha256') or src.get('apk_cert_sha256') or '')).lower()
    raw_signals = src.get('integrity_signals')
    if not isinstance(raw_signals, dict):
        raw_signals = {}

    return {
        'device_name': _s('device_name', 150) or f"{_s('manufacturer', 60)} {_s('model', 80)}".strip() or 'Android Device',
        'manufacturer': _s('manufacturer', 100),
        'model': _s('model', 100),
        'os_name': _s('os_name', 32) or 'Android',
        'android_version': _s('android_version', 32),
        'api_level': api_level,
        'cpu_arch': _s('cpu_arch', 64, lower=True),
        'cpu_info': _s('cpu_info', 255),
        'gpu_renderer': _s('gpu_renderer', 255),
        'gpu_vendor': _s('gpu_vendor', 255),
        'screen_resolution': _s('screen_resolution', 64, lower=True),
        'app_version': _s('app_version', 32),
        'app_build_number': _s('app_build_number', 32),
        'package_name': _s('package_name', 128),
        'signing_cert_sha256': cert[:128],
        'installer_source': _s('installer_source', 128) or _s('installer_package', 128),
        'integrity_signals': dict(raw_signals),
    }


def generate_versioned_fingerprint(
    installation_id: str,
    traits: dict[str, Any],
    previous_fingerprint: DeviceFingerprint | None = None,
    algorithm_version: str = FINGERPRINT_ALGORITHM_VERSION,
) -> dict[str, Any]:
    """
    ينشئ بصمة خادم مُشفّرة ومُرقّمة الإصدار (HMAC-SHA256)، ويحسب درجة الانحراف (Drift)
    مع التمييز بين التحديثات الطبيعية (OS / App update) وتبدل خصائص العتاد الأساسية.
    """
    secret = _fingerprint_secret()
    core_payload = '|'.join(
        [
            algorithm_version,
            installation_id,
            str(traits.get('manufacturer', '')).lower(),
            str(traits.get('model', '')).lower(),
            str(traits.get('cpu_arch', '')).lower(),
            str(traits.get('package_name', '')).lower(),
        ]
    )
    supporting_payload = '|'.join(
        [
            str(traits.get('android_version', '')).lower(),
            str(traits.get('api_level', 0)),
            str(traits.get('cpu_info', '')).lower(),
            str(traits.get('gpu_renderer', '')).lower(),
            str(traits.get('gpu_vendor', '')).lower(),
            str(traits.get('screen_resolution', '')).lower(),
            str(traits.get('app_version', '')).lower(),
            str(traits.get('app_build_number', '')).lower(),
            str(traits.get('signing_cert_sha256', '')).lower(),
            str(traits.get('installer_source', '')).lower(),
        ]
    )
    core_hash = hmac.new(secret, core_payload.encode('utf-8'), hashlib.sha256).hexdigest()
    supporting_hash = hmac.new(secret, supporting_payload.encode('utf-8'), hashlib.sha256).hexdigest()
    combined_hash = hmac.new(
        secret,
        f"{algorithm_version}:{core_hash}:{supporting_hash}".encode('utf-8'),
        hashlib.sha256,
    ).hexdigest()
    versioned_hash = f"{algorithm_version}:{combined_hash}"

    changed_fields: list[str] = []
    drift_score = 0
    core_mismatch = False

    if previous_fingerprint and isinstance(previous_fingerprint.normalized_traits, dict):
        prev = previous_fingerprint.normalized_traits
        for field in (*CORE_FINGERPRINT_FIELDS, *SUPPORTING_FINGERPRINT_FIELDS):
            old_val = str(prev.get(field, '') or '').strip().lower()
            new_val = str(traits.get(field, '') or '').strip().lower()
            if old_val and new_val and old_val != new_val:
                changed_fields.append(field)

        core_changed = [f for f in changed_fields if f in ('manufacturer', 'model', 'cpu_arch')]
        if core_changed:
            core_mismatch = True
            drift_score += 55
        if 'package_name' in changed_fields:
            drift_score += 40
        if 'signing_cert_sha256' in changed_fields:
            drift_score += 45
        benign_changed = [f for f in changed_fields if f in BENIGN_DRIFT_FIELDS]
        if benign_changed and not core_changed:
            drift_score += min(len(benign_changed) * 3, 10)

    return {
        'fingerprint_hash': versioned_hash,
        'algorithm_version': algorithm_version,
        'core_hash': core_hash,
        'supporting_hash': supporting_hash,
        'drift_score': min(drift_score, 100),
        'changed_fields': changed_fields,
        'core_mismatch': core_mismatch,
    }


def get_server_observed_ip(request) -> str | None:
    """
    يستخرج عنوان IP الحقيقي المرصود على مستوى الخادم فقط،
    ولا يثق أبداً بأي عنوان IP يرسله العميل داخل جسم الطلب.
    """
    if request is None:
        return None
    for header in ('HTTP_CF_CONNECTING_IP', 'HTTP_X_REAL_IP', 'HTTP_X_FORWARDED_FOR', 'REMOTE_ADDR'):
        raw = (request.META.get(header) or '').strip()
        if not raw:
            continue
        candidate = raw.split(',')[0].strip()
        try:
            ipaddress.ip_address(candidate)
            return candidate
        except ValueError:
            continue
    return None


def extract_network_context(request, integrity_signals: dict[str, Any] | None = None) -> dict[str, Any]:
    """يستخلص سياق الشبكة والموقع التقريبي وإشارات الـ VPN من ترويسات البروكسي والخادم."""
    ip_addr = get_server_observed_ip(request)
    meta = getattr(request, 'META', {}) if request is not None else {}

    country = (
        meta.get('HTTP_CF_IPCOUNTRY')
        or meta.get('HTTP_X_VERCEL_IP_COUNTRY')
        or meta.get('HTTP_X_GEO_COUNTRY')
        or ''
    ).strip().upper()[:16]
    region = (
        meta.get('HTTP_X_VERCEL_IP_COUNTRY_REGION')
        or meta.get('HTTP_X_GEO_REGION')
        or ''
    ).strip()[:128]
    isp = (
        meta.get('HTTP_X_ISP')
        or meta.get('HTTP_X_ISP_NAME')
        or meta.get('HTTP_X_ASN')
        or ''
    ).strip()[:128]

    header_vpn = str(meta.get('HTTP_X_VPN_SUSPECTED') or '').strip().lower() in ('1', 'true', 'yes')
    client_vpn = bool((integrity_signals or {}).get('vpn_interface_active'))

    is_private_ip = False
    if ip_addr:
        try:
            ip_obj = ipaddress.ip_address(ip_addr)
            is_private_ip = ip_obj.is_private or ip_obj.is_loopback
        except ValueError:
            pass

    return {
        'ip_address': ip_addr,
        'country_code': country,
        'region_name': region,
        'isp_name': isp,
        'is_vpn_or_proxy': header_vpn or client_vpn,
        'is_private_ip': is_private_ip,
        'user_agent': str(meta.get('HTTP_USER_AGENT') or '')[:255],
    }


def analyze_ip_transition(device: RegisteredDevice, net_ctx: dict[str, Any]) -> dict[str, Any]:
    """
    يحلّل تغير الـ IP والموقع الجغرافي مع دعم IP المتغير لشبكات المحمول و CGNAT،
    دون حظر تلقائي عند استخدام VPN أو تبدّل الـ IP داخل نفس الدولة.
    """
    ip_addr = net_ctx.get('ip_address')
    country = net_ctx.get('country_code', '')
    region = net_ctx.get('region_name', '')
    now = timezone.now()

    prev_ip = device.last_ip
    prev_country = (device.last_country or '').upper()
    prev_active = device.last_active_at

    ip_changed = bool(ip_addr and prev_ip and ip_addr != prev_ip)
    rapid_geo_transition = False
    same_country_dynamic_ip = False

    if ip_changed:
        if country and prev_country and country != prev_country:
            if prev_active and (now - prev_active) <= timedelta(minutes=60):
                rapid_geo_transition = True
        else:
            same_country_dynamic_ip = True

    history = list(device.ip_history or [])
    if ip_addr:
        last_entry = history[0] if history and isinstance(history[0], dict) else None
        if not last_entry or last_entry.get('ip') != ip_addr or last_entry.get('country') != country:
            history.insert(
                0,
                {
                    'ip': ip_addr,
                    'country': country,
                    'region': region,
                    'isp': net_ctx.get('isp_name', ''),
                    'vpn': bool(net_ctx.get('is_vpn_or_proxy')),
                    'seen_at': now.isoformat(),
                },
            )
            history = history[:MAX_IP_HISTORY_ENTRIES]

    return {
        'ip_changed': ip_changed,
        'same_country_dynamic_ip': same_country_dynamic_ip,
        'rapid_geo_transition': rapid_geo_transition,
        'vpn_signal': bool(net_ctx.get('is_vpn_or_proxy')),
        'updated_ip_history': history,
    }


def get_user_device_limit(user) -> int:
    """يُرجع الحد الأقصى للأجهزة المسموح بها حسب الدور وإعدادات Django/الإدارة."""
    role = getattr(user, 'role', 'student')
    if getattr(user, 'is_superuser', False) or role == 'admin':
        return 25
    policy = SecurityPolicyConfig.load()
    if role == 'student':
        override = getattr(settings, 'STUDENT_DEVICE_LIMIT', None)
        if override is not None:
            return max(int(override), 1)
        return max(int(policy.student_device_limit), 1)
    if role == 'teacher':
        override = getattr(settings, 'TEACHER_DEVICE_LIMIT', None)
        if override is not None:
            return max(int(override), 1)
        return max(int(policy.teacher_device_limit), 1)
    override = getattr(settings, 'ASSISTANT_DEVICE_LIMIT', None)
    if override is not None:
        return max(int(override), 1)
    return max(int(policy.assistant_device_limit), 1)


def get_active_device_block(installation_id: str) -> DeviceBlock | None:
    """يتحقق من وجود حظر نشط للجهاز ويفكّ الحظر المؤقت المنتهي تلقائياً."""
    if not installation_id:
        return None
    now = timezone.now()
    active_blocks = DeviceBlock.objects.filter(
        installation_id=installation_id,
        is_active=True,
    ).order_by('-created_at')
    for blk in active_blocks:
        if blk.block_type == 'temporary' and blk.expires_at and blk.expires_at <= now:
            blk.is_active = False
            blk.unblocked_at = now
            blk.unblock_reason = 'auto_expired'
            blk.save(update_fields=['is_active', 'unblocked_at', 'unblock_reason'])
            if blk.device_id and blk.device.trust_status == DeviceTrustStatus.BLOCKED:
                blk.device.trust_status = DeviceTrustStatus.TRUSTED
                blk.device.is_active = True
                blk.device.save(update_fields=['trust_status', 'is_active'])
            continue
        return blk
    return None


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
            )
        except Exception:
            pass

    return evt


def _verify_app_identity_signals(traits: dict[str, Any], tamper_signals: dict[str, Any]) -> dict[str, Any]:
    """
    يتحقق على مستوى الخادم من حزمة التطبيق وشهادة التوقيع ووضع الـ Debug ومؤشرات العبث،
    مع دعم معرّف أجهزة متصفح الويب (web.ta3alm.online) دون معاقبته على شهادة توقيع APK.
    """
    is_debug_build = bool(tamper_signals.get('is_debug_build'))
    expected_pkg = os.environ.get('PLAY_INTEGRITY_PACKAGE_NAME', 'online.ta3alm.ta3alm_flutter').strip()
    allowed_pkgs = {expected_pkg, WEB_PACKAGE_NAME}
    if settings.DEBUG or is_debug_build:
        allowed_pkgs.add(f"{expected_pkg}.debug")

    pkg = (traits.get('package_name') or tamper_signals.get('package_name') or '').strip()
    is_web_browser = pkg == WEB_PACKAGE_NAME
    package_mismatch = bool(pkg and expected_pkg and pkg not in allowed_pkgs)

    raw_expected_certs = (
        os.environ.get('ANDROID_RELEASE_CERT_SHA256', '').strip()
        or os.environ.get('ANDROID_ASSETLINKS_SHA256', '').strip()
    )
    expected_certs = {
        re.sub(r'[^0-9a-fA-F]', '', c).lower()
        for c in raw_expected_certs.split(',')
        if re.sub(r'[^0-9a-fA-F]', '', c)
    }
    client_cert = re.sub(
        r'[^0-9a-fA-F]',
        '',
        str(traits.get('signing_cert_sha256') or tamper_signals.get('apk_cert_sha256') or ''),
    ).lower()

    cert_mismatch = bool(
        not is_web_browser
        and expected_certs
        and client_cert
        and client_cert not in expected_certs
        and not (settings.DEBUG and is_debug_build)
    )
    if not is_web_browser and tamper_signals.get('signature_mismatch'):
        cert_mismatch = True

    frida = bool(tamper_signals.get('frida_detected'))
    hooking = bool(tamper_signals.get('hooking_detected'))
    debugger = bool(tamper_signals.get('debugger_attached'))
    rooted = bool(tamper_signals.get('root_detected'))
    emulator = bool(tamper_signals.get('emulator_detected'))
    webdriver_detected = bool(tamper_signals.get('webdriver_detected'))

    debug_in_prod = bool(not is_web_browser and is_debug_build and not settings.DEBUG)
    debugger_in_release = bool(not is_web_browser and debugger and not is_debug_build)

    return {
        'is_web_browser': is_web_browser,
        'package_mismatch': package_mismatch,
        'cert_mismatch': cert_mismatch,
        'frida': frida,
        'hooking': hooking,
        'debugger_in_release': debugger_in_release,
        'debug_in_prod': debug_in_prod,
        'rooted': rooted,
        'emulator': emulator,
        'webdriver_detected': webdriver_detected,
        'signing_cert_verified': (not is_web_browser) and (not cert_mismatch) and (not package_mismatch),
    }


def evaluate_and_apply_risk(
    *,
    request=None,
    user,
    device: RegisteredDevice,
    fp_info: dict[str, Any],
    ip_info: dict[str, Any],
    tamper_signals: dict[str, Any],
    net_ctx: dict[str, Any],
) -> dict[str, Any]:
    """
    محرك تقييم المخاطر السلوكية (LOW / MEDIUM / HIGH / CRITICAL) القائم على تجميع عدة إشارات
    وعدم الاعتماد على إشارة واحدة ضعيفة (مثل تغير الـ IP أو VPN منفرداً).
    """
    policy = SecurityPolicyConfig.load()
    now = timezone.now()
    indicators: list[str] = []
    score = 0

    app_checks = _verify_app_identity_signals(
        {
            'package_name': device.package_name,
            'signing_cert_sha256': device.signing_cert_sha256,
        },
        tamper_signals,
    )

    # 1. مؤشرات عبث التطبيق والحقن والتوقيع
    if app_checks['frida'] or app_checks['hooking']:
        score += 90
        indicators.append('runtime_hooking_or_frida')
    if app_checks['package_mismatch']:
        score += 85
        indicators.append('unexpected_package_name')
    if app_checks['cert_mismatch']:
        score += 85
        indicators.append('unexpected_signing_certificate')
    if app_checks['debugger_in_release']:
        score += 65
        indicators.append('debugger_attached_in_release')
    if app_checks['debug_in_prod']:
        score += 35
        indicators.append('debug_build_in_production')
    if app_checks['rooted']:
        score += 20
        indicators.append('root_indicators')
    if app_checks['emulator']:
        score += 15
        indicators.append('emulator_environment')
    if app_checks.get('webdriver_detected'):
        score += 20
        indicators.append('automated_browser_webdriver')

    # 2. تغير البصمة (تمييز التحديث الطبيعي عن تغير العتاد الجوهري)
    if fp_info.get('core_mismatch'):
        score += 45
        indicators.append('core_hardware_fingerprint_mismatch')

    # 3. الشبكة والتحركات الجغرافية السريعة
    if ip_info.get('rapid_geo_transition'):
        score += 35
        indicators.append('rapid_geo_transition')
    if ip_info.get('vpn_signal'):
        score += 10
        indicators.append('vpn_or_proxy_signal')

    # 4. السلوك التاريخي: فشل دخول متكرر، تبديل حسابات على نفس الجهاز، دورات تسجيل/إلغاء
    failed_15m = DeviceActivity.objects.filter(
        Q(user=user) | Q(ip_address=net_ctx.get('ip_address')) if net_ctx.get('ip_address') else Q(user=user),
        activity_type='login_failed',
        created_at__gte=now - timedelta(minutes=15),
    ).count()
    if failed_15m >= max(policy.rapid_login_threshold_5m, 3):
        score += 30
        indicators.append('repeated_failed_logins')

    distinct_accounts_on_device = (
        RegisteredDevice.objects.filter(installation_id=device.installation_id)
        .values('user_id')
        .distinct()
        .count()
    )
    if distinct_accounts_on_device >= 3:
        score += 35
        indicators.append('frequent_account_switching_on_device')

    revocations_7d = DeviceSecurityEvent.objects.filter(
        user=user,
        event_type__in=('device_revoked', 'device_limit_reached'),
        created_at__gte=now - timedelta(days=7),
    ).count()
    if revocations_7d >= 3:
        score += 25
        indicators.append('repeated_registration_revocation_cycle')

    # 5. الجلسات المتزامنة من أجهزة أو دول مختلفة
    active_sessions = DeviceSession.objects.filter(
        user=user,
        status='active',
        expires_at__gt=now,
    ).select_related('device')
    distinct_active_devices = {s.installation_id for s in active_sessions if s.installation_id}
    distinct_active_countries = {s.country_code for s in active_sessions if s.country_code}
    if len(distinct_active_devices) > policy.max_concurrent_sessions:
        score += 30
        indicators.append('excessive_simultaneous_sessions')
    if len(distinct_active_countries) > 1:
        score += 30
        indicators.append('simultaneous_distant_locations')

    # 6. فحص أحدث سجل Play Integrity للجهاز
    latest_integrity = (
        DeviceIntegrityRecord.objects.filter(device_id=device.installation_id)
        .order_by('-verified_at')
        .first()
    )
    if latest_integrity and latest_integrity.policy_decision == 'block':
        score += 75
        indicators.append('play_integrity_blocked')

    score = min(score, 100)

    if score >= policy.risk_threshold_critical:
        risk_level = 'critical'
    elif score >= policy.risk_threshold_high:
        risk_level = 'high'
    elif score >= policy.risk_threshold_medium:
        risk_level = 'medium'
    else:
        risk_level = 'low'

    action_taken = 'logged'
    if device.trust_status != DeviceTrustStatus.BLOCKED:
        if risk_level == 'critical':
            device.trust_status = DeviceTrustStatus.RESTRICTED
            device.requires_reauth = True
            action_taken = 'temp_restricted'
        elif risk_level == 'high':
            device.trust_status = DeviceTrustStatus.SUSPICIOUS
            device.requires_reauth = True
            action_taken = 'reauth_required'
        elif risk_level == 'medium':
            if device.trust_status == DeviceTrustStatus.TRUSTED:
                device.trust_status = DeviceTrustStatus.SUSPICIOUS
            action_taken = 'monitored'
        else:
            if device.trust_status in (DeviceTrustStatus.PENDING, DeviceTrustStatus.SUSPICIOUS):
                device.trust_status = DeviceTrustStatus.TRUSTED
            device.requires_reauth = False

    device.risk_score = score
    device.risk_level = risk_level
    device.signing_cert_verified = app_checks['signing_cert_verified']
    device.save(
        update_fields=[
            'trust_status',
            'requires_reauth',
            'risk_score',
            'risk_level',
            'signing_cert_verified',
        ]
    )

    if score >= policy.risk_threshold_medium or indicators:
        sev = risk_level
        record_security_event(
            event_type=indicators[0] if indicators else 'risk_assessment',
            severity=sev,
            risk_score=score,
            user=user,
            device=device,
            request=request,
            net_ctx=net_ctx,
            action_taken=action_taken,
            details={'indicators': indicators, 'app_checks': app_checks},
            notify_user=risk_level in ('high', 'critical'),
            notify_title='تنبيه أمني حول نشاط جهازك',
            notify_message='تم رصد نشاط غير معتاد على أحد الأجهزة المرتبطة بحسابك. راجع قائمة الأجهزة الموثوقة في الإعدادات.',
        )

    return {
        'risk_score': score,
        'risk_level': risk_level,
        'trust_status': device.trust_status,
        'indicators': indicators,
        'action_taken': action_taken,
        'app_checks': app_checks,
    }


def detect_account_sharing(
    request,
    user,
    *,
    lecture=None,
    installation_id: str = '',
) -> dict[str, Any]:
    """
    يكشف مؤشرات مشاركة الحساب (جلسات متزامنة مفرطة، تشغيل متزامن من أجهزة مختلفة،
    انتقالات جغرافية متباعدة أثناء جلسات نشطة) دون حظر عشوائي على دليل ضعيف.
    """
    policy = SecurityPolicyConfig.load()
    now = timezone.now()
    net_ctx = extract_network_context(request)

    active_dev_sessions = list(
        DeviceSession.objects.filter(
            user=user,
            status='active',
            expires_at__gt=now,
        )
    )
    active_installations = {s.installation_id for s in active_dev_sessions if s.installation_id}
    if installation_id:
        active_installations.add(installation_id)

    active_countries = {s.country_code for s in active_dev_sessions if s.country_code}
    if net_ctx.get('country_code'):
        active_countries.add(net_ctx['country_code'])

    concurrent_playback = list(
        PlaybackSession.objects.filter(
            user=user,
            status='active',
            expires_at__gt=now,
            last_heartbeat_at__gte=now - timedelta(minutes=2),
        )
    )
    playback_devices = {p.device_id for p in concurrent_playback if p.device_id}
    if installation_id:
        playback_devices.add(installation_id)

    signals: list[str] = []
    if len(active_installations) > policy.max_concurrent_sessions:
        signals.append('excessive_simultaneous_sessions')
    if len(active_countries) > 1:
        signals.append('distant_simultaneous_locations')
    if len(playback_devices) > max(policy.max_concurrent_playback, 1):
        signals.append('concurrent_playback_multiple_devices')

    if signals:
        device = RegisteredDevice.objects.filter(user=user, installation_id=installation_id).first() if installation_id else None
        risk_score = min(35 * len(signals), 95)
        severity = 'high' if len(signals) >= 2 else 'medium'
        record_security_event(
            event_type='account_sharing_suspected',
            severity=severity,
            risk_score=risk_score,
            user=user,
            device=device,
            installation_id=installation_id,
            request=request,
            net_ctx=net_ctx,
            action_taken='session_monitored_and_notified',
            details={
                'signals': signals,
                'lecture_id': getattr(lecture, 'id', None),
                'active_devices_count': len(active_installations),
                'active_countries': sorted(active_countries),
                'playback_devices_count': len(playback_devices),
            },
            notify_user=True,
            notify_title='تنبيه: نشاط متزامن على حسابك',
            notify_message='لاحظنا أكثر من جلسة نشطة أو محاولة تشغيل متزامنة. يرجى التأكد من عدم مشاركة بيانات حسابك.',
        )
        return {'suspected': True, 'signals': signals, 'risk_score': risk_score}

    return {'suspected': False, 'signals': [], 'risk_score': 0}


def serialize_device_summary(device: RegisteredDevice, current_installation_id: str = '') -> dict[str, Any]:
    active_sess = device.sessions.filter(status='active', expires_at__gt=timezone.now()).exists()
    return {
        'id': device.id,
        'device_uuid': str(device.device_uuid),
        'installation_id': device.installation_id,
        'is_current_device': bool(current_installation_id and device.installation_id == current_installation_id),
        'device_name': device.device_name or f"{device.manufacturer} {device.model}".strip() or 'Android Device',
        'manufacturer': device.manufacturer,
        'model': device.model,
        'os_name': device.os_name,
        'android_version': device.android_version,
        'api_level': device.api_level,
        'cpu_arch': device.cpu_arch,
        'gpu_renderer': device.gpu_renderer,
        'gpu_vendor': device.gpu_vendor,
        'screen_resolution': device.screen_resolution,
        'app_version': device.app_version,
        'app_build_number': device.app_build_number,
        'package_name': device.package_name,
        'signing_cert_verified': device.signing_cert_verified,
        'fingerprint_version': device.fingerprint_version,
        'trust_status': device.trust_status,
        'is_active': device.is_active,
        'is_verified': device.is_verified,
        'requires_reauth': device.requires_reauth,
        'risk_score': device.risk_score,
        'risk_level': device.risk_level,
        'current_session_active': active_sess,
        'last_ip': device.last_ip,
        'last_country': device.last_country,
        'last_region': device.last_region,
        'first_registered_at': device.first_registered_at.isoformat() if device.first_registered_at else None,
        'last_active_at': device.last_active_at.isoformat() if device.last_active_at else None,
        'unfamiliar_reported': device.unfamiliar_reported,
    }


@transaction.atomic
def register_or_update_device(
    *,
    request,
    user,
    installation_id: str,
    device_info: dict[str, Any] | None = None,
    token_jti: str = '',
    refresh_jti: str = '',
) -> dict[str, Any]:
    """
    التدفق الكامل لتسجيل أو تحديث الجهاز:
    1) التحقق من صحة installation_id.
    2) التحقق من عدم وجود حظر إداري DeviceBlock.
    3) التحقق من حد الأجهزة المسموح (دون استبدال صامت).
    4) إنشاء/تحديث بصمة fp_v1 وسجل الانحراف وسجل IP.
    5) إنشاء أو تحديث DeviceSession وتقييم المخاطر.
    """
    valid, clean_id, err = validate_installation_id(installation_id, user=user)
    if not valid:
        return {'allowed': False, 'code': 'INVALID_INSTALLATION_ID', 'error': err}

    traits = normalize_device_info(device_info)
    tamper_signals = traits.get('integrity_signals') or {}
    net_ctx = extract_network_context(request, integrity_signals=tamper_signals)

    active_block = get_active_device_block(clean_id)
    if active_block:
        record_security_event(
            event_type='blocked_device_attempt',
            severity='high',
            risk_score=90,
            user=user,
            device=active_block.device,
            installation_id=clean_id,
            request=request,
            net_ctx=net_ctx,
            action_taken='denied_registration',
            details={'block_id': active_block.id, 'reason': active_block.reason},
        )
        return {
            'allowed': False,
            'code': 'DEVICE_BLOCKED',
            'error': f'هذا الجهاز محظور من استخدام المنصة: {active_block.reason}',
            'block_type': active_block.block_type,
            'expires_at': active_block.expires_at.isoformat() if active_block.expires_at else None,
        }

    existing = (
        RegisteredDevice.objects.select_for_update()
        .filter(user=user, installation_id=clean_id)
        .first()
    )

    if existing and existing.trust_status == DeviceTrustStatus.BLOCKED:
        return {
            'allowed': False,
            'code': 'DEVICE_BLOCKED',
            'error': 'تم حظر هذا الجهاز من قِبل إدارة المنصة.',
        }

    policy = SecurityPolicyConfig.load()
    limit = get_user_device_limit(user)
    needs_slot = existing is None or (not existing.is_active) or existing.trust_status == DeviceTrustStatus.REVOKED

    if needs_slot and policy.enforce_device_limits:
        active_devices_qs = (
            RegisteredDevice.objects.select_for_update()
            .filter(user=user, is_active=True)
            .exclude(trust_status__in=[DeviceTrustStatus.REVOKED, DeviceTrustStatus.BLOCKED])
        )
        if existing:
            active_devices_qs = active_devices_qs.exclude(pk=existing.pk)
        active_devices = list(active_devices_qs)
        if len(active_devices) >= limit:
            record_security_event(
                event_type='device_limit_reached',
                severity='medium',
                risk_score=40,
                user=user,
                installation_id=clean_id,
                request=request,
                net_ctx=net_ctx,
                action_taken='denied_new_device',
                details={
                    'limit': limit,
                    'active_count': len(active_devices),
                    'attempted_device': traits.get('device_name'),
                },
                notify_user=True,
                notify_title='تنبيه: تم بلوغ الحد الأقصى للأجهزة',
                notify_message=f'حسابك وصل للحد الأقصى المسموح به ({limit} أجهزة). قم بإلغاء أحد الأجهزة القديمة قبل إضافة جهاز جديد.',
            )
            return {
                'allowed': False,
                'code': 'DEVICE_LIMIT_REACHED',
                'error': f'لقد وصلت للحد الأقصى المسموح به من الأجهزة ({limit}). يرجى إزالة جهاز قديم أولاً من شاشة الأجهزة الموثوقة.',
                'device_limit': limit,
                'active_devices_count': len(active_devices),
                'devices': [serialize_device_summary(d) for d in active_devices],
            }

    now = timezone.now()
    if existing is None:
        device = RegisteredDevice.objects.create(
            user=user,
            installation_id=clean_id,
            device_name=traits['device_name'],
            manufacturer=traits['manufacturer'],
            model=traits['model'],
            os_name=traits['os_name'],
            android_version=traits['android_version'],
            api_level=traits['api_level'],
            cpu_arch=traits['cpu_arch'],
            cpu_info=traits['cpu_info'],
            gpu_renderer=traits['gpu_renderer'],
            gpu_vendor=traits['gpu_vendor'],
            screen_resolution=traits['screen_resolution'],
            app_version=traits['app_version'],
            app_build_number=traits['app_build_number'],
            package_name=traits['package_name'],
            signing_cert_sha256=traits['signing_cert_sha256'],
            installer_source=traits['installer_source'],
            trust_status=DeviceTrustStatus.TRUSTED,
            is_active=True,
            is_verified=True,
            last_ip=net_ctx.get('ip_address'),
            last_country=net_ctx.get('country_code', ''),
            last_region=net_ctx.get('region_name', ''),
            last_isp=net_ctx.get('isp_name', ''),
            integrity_signals=tamper_signals,
            last_active_at=now,
        )
        is_new_device = True
    else:
        device = existing
        is_new_device = False

    prev_fp = device.fingerprints.order_by('-created_at').first()
    fp_info = generate_versioned_fingerprint(clean_id, traits, previous_fingerprint=prev_fp)
    ip_info = analyze_ip_transition(device, net_ctx)

    for field in (
        'device_name',
        'manufacturer',
        'model',
        'os_name',
        'android_version',
        'api_level',
        'cpu_arch',
        'cpu_info',
        'gpu_renderer',
        'gpu_vendor',
        'screen_resolution',
        'app_version',
        'app_build_number',
        'package_name',
        'signing_cert_sha256',
        'installer_source',
    ):
        val = traits.get(field)
        if val not in ('', None, 0):
            setattr(device, field, val)

    device.current_fingerprint = fp_info['fingerprint_hash']
    device.fingerprint_version = fp_info['algorithm_version']
    device.last_ip = net_ctx.get('ip_address') or device.last_ip
    device.last_country = net_ctx.get('country_code') or device.last_country
    device.last_region = net_ctx.get('region_name') or device.last_region
    device.last_isp = net_ctx.get('isp_name') or device.last_isp
    device.ip_history = ip_info['updated_ip_history']
    if tamper_signals:
        device.integrity_signals = tamper_signals
    device.is_active = True
    if device.trust_status == DeviceTrustStatus.REVOKED:
        device.trust_status = DeviceTrustStatus.TRUSTED
        device.revoked_at = None
        device.revoked_reason = ''
    device.last_active_at = now
    device.save()

    if prev_fp is None or prev_fp.fingerprint_hash != fp_info['fingerprint_hash']:
        DeviceFingerprint.objects.create(
            device=device,
            fingerprint_hash=fp_info['fingerprint_hash'],
            algorithm_version=fp_info['algorithm_version'],
            core_hash=fp_info['core_hash'],
            supporting_hash=fp_info['supporting_hash'],
            normalized_traits={k: v for k, v in traits.items() if k != 'integrity_signals'},
            drift_score=fp_info['drift_score'],
            changed_fields=fp_info['changed_fields'],
        )

    # إنشاء أو تدوير جلسة الجهاز
    session = DeviceSession.objects.create(
        user=user,
        device=device,
        installation_id=clean_id,
        token_jti=token_jti[:64],
        refresh_jti=refresh_jti[:64],
        status='active',
        ip_address=net_ctx.get('ip_address'),
        country_code=net_ctx.get('country_code', '')[:16],
        region_name=net_ctx.get('region_name', '')[:128],
        isp_name=net_ctx.get('isp_name', '')[:128],
        is_vpn_or_proxy=bool(net_ctx.get('is_vpn_or_proxy')),
        user_agent=net_ctx.get('user_agent', '')[:255],
        last_seen_at=now,
        expires_at=now + timedelta(days=30),
    )

    # ضبط حد الجلسات المتزامنة بلطف (تعطيل أقدم جلسة زائدة على نفس الجهاز أو عند تجاوز الحد)
    same_dev_other_sessions = (
        DeviceSession.objects.filter(user=user, device=device, status='active')
        .exclude(pk=session.pk)
    )
    same_dev_other_sessions.update(
        status='ended',
        ended_at=now,
        revoked_reason='rotated_on_same_device',
    )

    risk_result = evaluate_and_apply_risk(
        request=request,
        user=user,
        device=device,
        fp_info=fp_info,
        ip_info=ip_info,
        tamper_signals=tamper_signals,
        net_ctx=net_ctx,
    )

    record_device_activity(
        request=request,
        user=user,
        device=device,
        session=session,
        activity_type='device_registered' if is_new_device else 'device_login',
        net_ctx=net_ctx,
        metadata={
            'is_new_device': is_new_device,
            'fingerprint_version': fp_info['algorithm_version'],
            'drift_score': fp_info['drift_score'],
            'risk_level': risk_result['risk_level'],
        },
    )

    if is_new_device:
        record_security_event(
            event_type='new_device_registered',
            severity='low',
            risk_score=risk_result['risk_score'],
            user=user,
            device=device,
            request=request,
            net_ctx=net_ctx,
            action_taken='registered',
            details={'device_name': device.device_name, 'model': device.model},
        )

    if risk_result['risk_level'] == 'critical' and (
        risk_result['app_checks']['frida']
        or risk_result['app_checks']['hooking']
        or risk_result['app_checks']['package_mismatch']
        or risk_result['app_checks']['cert_mismatch']
    ):
        session.status = 'revoked'
        session.ended_at = now
        session.revoked_reason = 'critical_integrity_tamper'
        session.save(update_fields=['status', 'ended_at', 'revoked_reason'])
        return {
            'allowed': False,
            'code': 'APP_INTEGRITY_FAILED',
            'error': 'تم رفض تشغيل هذه النسخة لعدم اجتياز التحقق من سلامة التطبيق أو التوقيع الرسمي.',
            'device': serialize_device_summary(device, clean_id),
            'risk': risk_result,
        }

    return {
        'allowed': True,
        'is_new_device': is_new_device,
        'device_limit': limit,
        'device': serialize_device_summary(device, clean_id),
        'device_obj': device,
        'session_obj': session,
        'session_uuid': str(session.session_uuid),
        'fingerprint': fp_info,
        'risk': risk_result,
    }


def check_device_allowed(user, installation_id: str) -> tuple[bool, str | None, str | None]:
    """
    فحص صارم قبل منح تصريح التشغيل المحمي أو الموارد الحساسة:
    يتحقق من الحظر الإداري، إلغاء تفويض الجهاز، أو التقييد المؤقت، وحد الأجهزة.
    """
    clean_id = str(installation_id or '').strip()
    if not clean_id:
        return True, None, None

    block = get_active_device_block(clean_id)
    if block:
        return False, 'DEVICE_BLOCKED', f'هذا الجهاز محظور: {block.reason}'

    device = RegisteredDevice.objects.filter(user=user, installation_id=clean_id).first()
    if device:
        if device.trust_status == DeviceTrustStatus.BLOCKED:
            return False, 'DEVICE_BLOCKED', 'تم حظر هذا الجهاز من قِبل الإدارة.'
        if device.trust_status == DeviceTrustStatus.REVOKED or not device.is_active:
            return False, 'DEVICE_REVOKED', 'تم إلغاء تفويض هذا الجهاز. يرجى إعادة تسجيل الدخول.'
        if device.trust_status == DeviceTrustStatus.RESTRICTED:
            return False, 'DEVICE_RESTRICTED', 'هذا الجهاز مقيّد مؤقتاً بسبب نشاط غير معتاد أو فشل التحقق الأمني.'
        if device.requires_reauth:
            return False, 'REAUTH_REQUIRED', 'يرجى إعادة التحقق من هويتك لتشغيل المحتوى المحمي على هذا الجهاز.'
        return True, None, None

    # إذا لم يكن هذا الـ installation_id مسجلاً وكان الطالب قد استهلك حده بالفعل
    policy = SecurityPolicyConfig.load()
    if (
        policy.enforce_device_limits
        and getattr(user, 'role', '') == 'student'
        and not clean_id.startswith(f'user-{user.id}')
    ):
        limit = get_user_device_limit(user)
        active_count = (
            RegisteredDevice.objects.filter(user=user, is_active=True)
            .exclude(trust_status__in=[DeviceTrustStatus.REVOKED, DeviceTrustStatus.BLOCKED])
            .count()
        )
        if active_count >= limit:
            return (
                False,
                'DEVICE_LIMIT_REACHED',
                f'لقد وصلت للحد الأقصى للأجهزة ({limit}). يرجى إزالة أحد الأجهزة المسجّلة أولاً.',
            )

    return True, None, None


@transaction.atomic
def revoke_user_device(
    *,
    device: RegisteredDevice,
    actor,
    request=None,
    mode: str = 'revoke',
    reason: str = '',
) -> RegisteredDevice:
    """ينفّذ إلغاء تفويض الجهاز أو تسجيل خروجه أو الإبلاغ عنه كجهاز غير معروف."""
    now = timezone.now()
    net_ctx = extract_network_context(request)

    if mode == 'logout':
        DeviceSession.objects.filter(device=device, status='active').update(
            status='logged_out',
            ended_at=now,
            revoked_reason=reason or 'user_logout_device',
        )
        PlaybackSession.objects.filter(
            user=device.user,
            device_id=device.installation_id,
            status='active',
        ).update(status='revoked', revoked_reason='device_logged_out')
        event_type = 'device_session_logged_out'
        severity = 'low'
    elif mode == 'report_unfamiliar':
        device.unfamiliar_reported = True
        device.trust_status = DeviceTrustStatus.REVOKED
        device.is_active = False
        device.requires_reauth = True
        device.revoked_at = now
        device.revoked_reason = reason or 'reported_unfamiliar_by_user'
        device.save()
        DeviceSession.objects.filter(device=device, status='active').update(
            status='revoked',
            ended_at=now,
            revoked_reason='unfamiliar_device_reported',
        )
        PlaybackSession.objects.filter(
            user=device.user,
            device_id=device.installation_id,
            status='active',
        ).update(status='revoked', revoked_reason='unfamiliar_device_reported')
        event_type = 'unfamiliar_device_reported'
        severity = 'high'
    else:
        device.trust_status = DeviceTrustStatus.REVOKED
        device.is_active = False
        device.revoked_at = now
        device.revoked_reason = reason or 'revoked_by_owner_or_admin'
        device.save()
        DeviceSession.objects.filter(device=device, status='active').update(
            status='revoked',
            ended_at=now,
            revoked_reason=device.revoked_reason,
        )
        PlaybackSession.objects.filter(
            user=device.user,
            device_id=device.installation_id,
            status='active',
        ).update(status='revoked', revoked_reason='device_revoked')
        event_type = 'device_revoked'
        severity = 'medium'

    record_security_event(
        event_type=event_type,
        severity=severity,
        risk_score=65 if mode == 'report_unfamiliar' else 25,
        user=device.user,
        device=device,
        request=request,
        net_ctx=net_ctx,
        action_taken=mode,
        details={'actor_id': getattr(actor, 'id', None), 'reason': reason},
    )
    return device


@transaction.atomic
def block_device_admin(
    *,
    device: RegisteredDevice | None = None,
    installation_id: str = '',
    admin_user,
    block_type: str = 'permanent',
    reason: str = 'Administrative security block',
    duration_hours: int = 24,
    request=None,
) -> DeviceBlock:
    """حظر جهاز إدارياً (مؤقتاً أو دائماً) مع إبطال كافة جلساته فوراً."""
    now = timezone.now()
    clean_inst = installation_id or (device.installation_id if device else '')
    target_user = device.user if device else None
    expires_at = now + timedelta(hours=max(int(duration_hours), 1)) if block_type == 'temporary' else None

    block = DeviceBlock.objects.create(
        device=device,
        user=target_user,
        installation_id=clean_inst,
        fingerprint_hash=device.current_fingerprint if device else '',
        block_type='temporary' if block_type == 'temporary' else 'permanent',
        reason=reason[:255],
        is_active=True,
        blocked_by=admin_user,
        expires_at=expires_at,
    )

    RegisteredDevice.objects.filter(installation_id=clean_inst).update(
        trust_status=DeviceTrustStatus.BLOCKED,
        is_active=False,
        revoked_at=now,
        revoked_reason=reason[:255],
    )
    DeviceSession.objects.filter(installation_id=clean_inst, status='active').update(
        status='revoked',
        ended_at=now,
        revoked_reason='device_blocked_by_admin',
    )
    PlaybackSession.objects.filter(device_id=clean_inst, status='active').update(
        status='revoked',
        revoked_reason='device_blocked_by_admin',
    )

    record_security_event(
        event_type='device_blocked_by_admin',
        severity='high',
        risk_score=90,
        user=target_user,
        device=device,
        installation_id=clean_inst,
        request=request,
        action_taken=f'{block_type}_block',
        details={'block_id': block.id, 'reason': reason, 'admin_id': getattr(admin_user, 'id', None)},
    )
    return block


@transaction.atomic
def unblock_device_admin(
    *,
    device: RegisteredDevice | None = None,
    installation_id: str = '',
    admin_user,
    reason: str = 'Unblocked by administrator',
    request=None,
) -> int:
    """فك الحظر الإداري عن الجهاز واستعادة إمكانية استخدامه."""
    now = timezone.now()
    clean_inst = installation_id or (device.installation_id if device else '')
    qs = DeviceBlock.objects.filter(installation_id=clean_inst, is_active=True)
    updated = qs.update(
        is_active=False,
        unblocked_at=now,
        unblocked_by=admin_user,
        unblock_reason=reason[:255],
    )
    RegisteredDevice.objects.filter(
        installation_id=clean_inst,
        trust_status=DeviceTrustStatus.BLOCKED,
    ).update(
        trust_status=DeviceTrustStatus.TRUSTED,
        is_active=True,
        requires_reauth=False,
        revoked_at=None,
        revoked_reason='',
    )
    record_security_event(
        event_type='device_unblocked_by_admin',
        severity='low',
        risk_score=0,
        user=device.user if device else None,
        device=device,
        installation_id=clean_inst,
        request=request,
        action_taken='unblocked',
        details={'unblocked_records': updated, 'reason': reason, 'admin_id': getattr(admin_user, 'id', None)},
    )
    return updated


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


def parse_web_user_agent(user_agent: str) -> dict[str, str]:
    """يحلّل سلسلة User-Agent لاستخلاص اسم وإصدار المتصفح ونظام التشغيل بشكل مقروء."""
    ua = str(user_agent or '')
    browser_name = 'Web Browser'
    browser_vendor = 'Web Browser'
    browser_version = ''

    if 'Edg/' in ua or 'Edge/' in ua:
        browser_name = 'Microsoft Edge'
        browser_vendor = 'Microsoft Edge'
        m = re.search(r'Edg(?:e)?/([\d.]+)', ua)
        browser_version = m.group(1) if m else ''
    elif 'OPR/' in ua or 'Opera/' in ua:
        browser_name = 'Opera'
        browser_vendor = 'Opera'
        m = re.search(r'(?:OPR|Opera)/([\d.]+)', ua)
        browser_version = m.group(1) if m else ''
    elif 'Chrome/' in ua and 'Chromium/' not in ua:
        browser_name = 'Google Chrome'
        browser_vendor = 'Google Chrome'
        m = re.search(r'Chrome/([\d.]+)', ua)
        browser_version = m.group(1) if m else ''
    elif 'Firefox/' in ua:
        browser_name = 'Mozilla Firefox'
        browser_vendor = 'Mozilla Firefox'
        m = re.search(r'Firefox/([\d.]+)', ua)
        browser_version = m.group(1) if m else ''
    elif 'Safari/' in ua and 'Chrome/' not in ua:
        browser_name = 'Apple Safari'
        browser_vendor = 'Apple Safari'
        m = re.search(r'Version/([\d.]+)', ua)
        browser_version = m.group(1) if m else ''

    os_label = 'Desktop/Web'
    if 'Windows' in ua:
        os_label = 'Windows'
    elif 'iPhone' in ua or 'iPad' in ua or 'iPod' in ua:
        os_label = 'iOS'
    elif 'Android' in ua:
        os_label = 'Android'
    elif 'Macintosh' in ua or 'Mac OS X' in ua:
        os_label = 'macOS'
    elif 'Linux' in ua:
        os_label = 'Linux'

    return {
        'browser_name': browser_name,
        'browser_vendor': browser_vendor,
        'browser_version': browser_version[:32],
        'os_label': os_label,
    }


def build_web_device_info(request, client_traits: dict[str, Any] | None = None) -> dict[str, Any]:
    """
    يبني قاموس خصائص متصفح الويب (Device Info) عبر الدمج بين الترويسات التي يلاحظها الخادم
    والخصائص المسموح بها التي يرسلها المتصفح لتوليد بصمة fp_v1 موثوقة.
    """
    meta = getattr(request, 'META', {}) if request is not None else {}
    ua = str(meta.get('HTTP_USER_AGENT') or '')
    parsed = parse_web_user_agent(ua)
    src = client_traits if isinstance(client_traits, dict) else {}

    sec_platform = str(meta.get('HTTP_SEC_CH_UA_PLATFORM') or '').strip().strip('"')
    os_label = sec_platform or parsed['os_label']
    accept_lang = str(meta.get('HTTP_ACCEPT_LANGUAGE') or '').split(',')[0].strip()[:32]

    browser_name = parsed['browser_name']
    browser_vendor = parsed['browser_vendor']

    def _clean(val: Any, max_len: int = 128) -> str:
        return re.sub(r'\s+', ' ', str(val or '').strip())[:max_len]

    return {
        'device_name': f"متصفح {browser_name} ({os_label})",
        'manufacturer': browser_vendor,
        'model': f"{browser_name} on {os_label}",
        'os_name': f"Web ({os_label})",
        'android_version': parsed['browser_version'],
        'api_level': 0,
        'cpu_arch': _clean(os_label.lower(), 64).lower(),
        'cpu_info': _clean(
            ' | '.join(filter(None, [_clean(src.get('cpu_arch'), 64), _clean(src.get('cpu_info'), 180)])),
            255,
        ),
        'gpu_renderer': _clean(src.get('gpu_renderer'), 255),
        'gpu_vendor': _clean(src.get('gpu_vendor'), 255),
        'screen_resolution': _clean(src.get('screen_resolution'), 64).lower(),
        'app_version': parsed['browser_version'] or 'web-1.0',
        'app_build_number': 'web',
        'package_name': WEB_PACKAGE_NAME,
        'signing_cert_sha256': '',
        'installer_source': 'web_browser',
        'integrity_signals': {
            'is_web_browser': True,
            'webdriver_detected': bool(src.get('webdriver_detected')),
            'timezone': _clean(src.get('timezone'), 64),
            'accept_language': accept_lang,
            'sec_ch_ua': _clean(meta.get('HTTP_SEC_CH_UA'), 255),
            'sec_ch_platform': sec_platform[:64],
        },
    }


def get_or_create_web_installation_id(request) -> str:
    """
    يسترجع معرّف تثبيت المتصفح الموقّع من الكوكي أو الجلسة، أو يولّد معرّفًا عشوائيًا قويًا جديدًا
    ويحفظه لكي تثبّته طبقة Middleware في كوكي HttpOnly موقّع.
    """
    cached = getattr(request, '_web_installation_id', None)
    if cached:
        return cached

    candidate = ''
    has_valid_cookie = False
    if hasattr(request, 'get_signed_cookie'):
        try:
            loaded = request.get_signed_cookie(WEB_COOKIE_NAME, default='', salt=WEB_COOKIE_SALT)
            if loaded:
                ok, cleaned, _ = validate_installation_id(loaded)
                if ok and cleaned.startswith('web-'):
                    candidate = cleaned
                    has_valid_cookie = True
        except Exception:
            candidate = ''
    elif hasattr(request, 'COOKIES'):
        cookie_val = (request.COOKIES.get(WEB_COOKIE_NAME) or '').strip()
        if cookie_val:
            try:
                loaded = signing.loads(cookie_val, salt=WEB_COOKIE_SALT)
                ok, cleaned, _ = validate_installation_id(loaded)
                if ok and cleaned.startswith('web-'):
                    candidate = cleaned
                    has_valid_cookie = True
            except Exception:
                candidate = ''

    if not candidate and hasattr(request, 'session'):
        sess_val = (request.session.get('web_installation_id') or '').strip()
        ok, cleaned, _ = validate_installation_id(sess_val)
        if ok and cleaned.startswith('web-'):
            candidate = cleaned

    if not candidate:
        candidate = f"web-{uuid.uuid4().hex}"

    if hasattr(request, 'session') and request.session.get('web_installation_id') != candidate:
        request.session['web_installation_id'] = candidate

    if not has_valid_cookie:
        request._web_set_cookie_id = candidate

    request._web_installation_id = candidate
    return candidate


def enforce_web_lecture_playback(request, user, lecture, *, course_package=None) -> dict[str, Any]:
    """
    يفحص صلاحية جهاز الويب وحد الأجهزة ومشاركة الحساب والتشغيل المتزامن قبل عرض مشغّل الفيديو
    على الموقع، وينشئ أو يدوّر جلسة PlaybackSession نشطة لهذا المتصفح.
    """
    from .video_security import build_watermark_payload, create_or_rotate_playback_session

    installation_id = get_or_create_web_installation_id(request)
    allowed, code, err = check_device_allowed(user, installation_id)
    if not allowed:
        return {
            'allowed': False,
            'code': code or 'DEVICE_NOT_ALLOWED',
            'error': err or 'هذا المتصفح غير مخوّل لتشغيل المحاضرات حاليًا.',
            'installation_id': installation_id,
        }

    device = RegisteredDevice.objects.filter(
        user=user,
        installation_id=installation_id,
        is_active=True,
    ).exclude(trust_status__in=[DeviceTrustStatus.REVOKED, DeviceTrustStatus.BLOCKED]).first()

    if device is None:
        reg = register_or_update_device(
            request=request,
            user=user,
            installation_id=installation_id,
            device_info=build_web_device_info(request),
            token_jti=f"web:{getattr(getattr(request, 'session', None), 'session_key', '') or 'sess'}",
        )
        if not reg.get('allowed'):
            return {
                'allowed': False,
                'code': reg.get('code') or 'DEVICE_LIMIT_REACHED',
                'error': reg.get('error') or 'تعذر تسجيل هذا المتصفح لتشغيل الفيديو.',
                'installation_id': installation_id,
            }
        device = reg.get('device_obj')

    sharing = detect_account_sharing(request, user, lecture=lecture, installation_id=installation_id)
    session, revoked_count = create_or_rotate_playback_session(
        request=request,
        user=user,
        lecture=lecture,
        package=course_package,
        device_id=installation_id,
        device_fingerprint=device.current_fingerprint if device else '',
        client_platform='web',
        app_version=device.app_version if device else 'web-1.0',
        integrity_verdict='web_browser',
    )
    watermark = build_watermark_payload(user, session)

    record_device_activity(
        request=request,
        user=user,
        device=device,
        activity_type='web_lecture_playback',
        metadata={
            'lecture_id': lecture.id,
            'package_id': getattr(course_package, 'id', None),
            'revoked_concurrent_sessions': revoked_count,
            'sharing_suspected': bool(sharing.get('suspected')),
        },
    )

    return {
        'allowed': True,
        'installation_id': installation_id,
        'playback_session': session,
        'playback_session_uuid': str(session.session_id),
        'revoked_concurrent_sessions': revoked_count,
        'sharing': sharing,
        'watermark': watermark,
    }


"""api_v1.services.device_security.risk
Extracted from api_v1/device_security_service.py.
"""
from __future__ import annotations

import os
import re
from datetime import timedelta
from typing import Any
from django.conf import settings
from django.db.models import Q
from django.utils import timezone
from api_v1.models import (
    DeviceActivity,
    DeviceIntegrityRecord,
    DeviceSecurityEvent,
    DeviceSession,
    DeviceTrustStatus,
    PlaybackSession,
    RegisteredDevice,
    SecurityPolicyConfig,
)

from api_v1.services.device_security.constants import WEB_PACKAGE_NAME
from api_v1.services.device_security.events import record_security_event
from api_v1.services.device_security.network import extract_network_context


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
    if tamper_signals.get('web_spoof_reasons'):
        score += 95
        indicators.append('web_fingerprint_spoof_detected')

    # 2. تغير البصمة (تمييز التحديث الطبيعي عن تغير العتاد الجوهري)
    if fp_info.get('core_mismatch'):
        if device.package_name == WEB_PACKAGE_NAME:
            score += 90
            indicators.append('web_core_hardware_fingerprint_mismatch')
        else:
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

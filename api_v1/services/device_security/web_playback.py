"""api_v1.services.device_security.web_playback
Extracted from api_v1/device_security_service.py.
"""
from __future__ import annotations

from typing import Any
from django.utils import timezone
from api_v1.models import (
    DeviceSession,
    DeviceTrustStatus,
    PlaybackSession,
    RegisteredDevice,
)

from api_v1.services.device_security.constants import (
    WEB_IOS_ONLY_ERROR,
    WEB_PACKAGE_NAME,
)
from api_v1.services.device_security.events import (
    record_device_activity,
    record_security_event,
)
from api_v1.services.device_security.registration import (
    check_device_allowed,
    register_or_update_device,
)
from api_v1.services.device_security.risk import detect_account_sharing
from api_v1.services.device_security.web import (
    _extract_web_or_device_id_from_request,
    _has_desktop_or_emulated_gpu,
    build_web_device_info,
    detect_web_fingerprint_spoofing,
    get_or_create_web_installation_id,
    is_web_client_request,
    parse_web_user_agent,
)


def check_web_ios_only_lecture_access(
    request,
    user=None,
    *,
    client_traits: dict[str, Any] | None = None,
    force_web: bool = False,
) -> dict[str, Any]:
    """
    يتحقق من قاعدة الويب الصارمة: قسم وتشغيل المحاضرات عبر المتصفح مسموح فقط على iPhone و iPad الحقيقيين،
    وممنوع منعاً باتاً على أجهزة Mac و Windows و Linux وأندرويد ومحاكيات F12 و WebDriver.
    """
    if not force_web and not is_web_client_request(request):
        return {'allowed': True, 'is_web': False, 'device_kind': 'native_app', 'needs_ipad_probe': False}

    meta = getattr(request, 'META', {}) if request is not None else {}
    ua = str(meta.get('HTTP_USER_AGENT') or '')
    ua_low = ua.lower()
    sec_platform = str(meta.get('HTTP_SEC_CH_UA_PLATFORM') or '').strip().strip('"').lower()
    sec_ch_ua = str(meta.get('HTTP_SEC_CH_UA') or '').lower()

    # حظر فوري لأدوات الأتمتة والأنظمة غير المسموح بها
    blocked_ua_tokens = (
        'windows',
        'win32',
        'win64',
        'android',
        'linux',
        'x11',
        'cros',
        'ubuntu',
        'headlesschrome',
        'phantomjs',
        'selenium',
        'playwright',
        'puppeteer',
    )
    if any(tok in ua_low for tok in blocked_ua_tokens):
        return {
            'allowed': False,
            'is_web': True,
            'code': 'WEB_IOS_ONLY_REQUIRED',
            'error': WEB_IOS_ONLY_ERROR,
            'device_kind': 'blocked_web_os',
            'needs_ipad_probe': False,
        }

    if sec_platform and sec_platform not in ('ios', 'iphoneos', 'ipados'):
        return {
            'allowed': False,
            'is_web': True,
            'code': 'WEB_IOS_ONLY_REQUIRED',
            'error': WEB_IOS_ONLY_ERROR,
            'device_kind': 'blocked_sec_platform',
            'needs_ipad_probe': False,
        }

    merged_traits: dict[str, Any] = {}
    device = None
    if user is not None and getattr(user, 'is_authenticated', False):
        inst_id = _extract_web_or_device_id_from_request(request)
        if inst_id:
            device = RegisteredDevice.objects.filter(user=user, installation_id=inst_id).first()
            if device and isinstance(device.integrity_signals, dict):
                stored_wt = device.integrity_signals.get('web_traits')
                if isinstance(stored_wt, dict):
                    merged_traits.update(stored_wt)
                if device.integrity_signals.get('webdriver_detected'):
                    merged_traits['webdriver_detected'] = True
    if isinstance(client_traits, dict):
        merged_traits.update({k: v for k, v in client_traits.items() if v is not None})

    if merged_traits.get('webdriver_detected'):
        return {
            'allowed': False,
            'is_web': True,
            'code': 'WEB_AUTOMATION_BLOCKED',
            'error': 'تم حظر تشغيل المحاضرات عبر المتصفحات الآلية أو أدوات الفحص.',
            'device_kind': 'webdriver',
            'needs_ipad_probe': False,
        }

    spoof_reasons = detect_web_fingerprint_spoofing(request, client_traits=merged_traits)
    if spoof_reasons:
        return {
            'allowed': False,
            'is_web': True,
            'code': 'WEB_FINGERPRINT_MISMATCH',
            'error': 'تم رصد تلاعب في بصمة المتصفح أو محاولة انتحال هوية iPhone/iPad عبر F12.',
            'device_kind': 'spoofed_web',
            'needs_ipad_probe': False,
            'spoof_reasons': spoof_reasons,
        }

    if any(tok in ua_low for tok in ('iphone', 'ipad', 'ipod')) and 'applewebkit' in ua_low:
        if sec_ch_ua and any(b in sec_ch_ua for b in ('chromium', 'google chrome', 'microsoft edge')):
            return {
                'allowed': False,
                'is_web': True,
                'code': 'WEB_IOS_ONLY_REQUIRED',
                'error': WEB_IOS_ONLY_ERROR,
                'device_kind': 'spoofed_ch_ios',
                'needs_ipad_probe': False,
            }
        return {
            'allowed': True,
            'is_web': True,
            'code': None,
            'error': '',
            'device_kind': 'iphone_or_ipad',
            'needs_ipad_probe': False,
        }

    # وضع سطح المكتب في iPadOS Safari يرسل Macintosh + Safari/ فقط دون Chrome/Firefox/Edge
    is_mac_safari_candidate = (
        ('macintosh' in ua_low or 'mac os x' in ua_low)
        and 'safari/' in ua_low
        and 'chrome/' not in ua_low
        and 'chromium/' not in ua_low
        and 'firefox/' not in ua_low
        and 'edg/' not in ua_low
        and 'opr/' not in ua_low
    )
    if is_mac_safari_candidate:
        raw_touch = merged_traits.get('max_touch_points')
        try:
            touch_points = int(raw_touch) if raw_touch is not None and str(raw_touch).strip() != '' else None
        except (TypeError, ValueError):
            touch_points = None
        touch_support = merged_traits.get('touch_support')
        gpu_ok = not _has_desktop_or_emulated_gpu(
            str(merged_traits.get('gpu_vendor') or ''),
            str(merged_traits.get('gpu_renderer') or ''),
        )
        if touch_points is not None and touch_points >= 2 and touch_support is True and gpu_ok:
            return {
                'allowed': True,
                'is_web': True,
                'code': None,
                'error': '',
                'device_kind': 'ipados_desktop_safari',
                'needs_ipad_probe': False,
            }
        has_touch_probe = touch_points is not None
        return {
            'allowed': False,
            'is_web': True,
            'code': 'WEB_IOS_ONLY_REQUIRED',
            'error': WEB_IOS_ONLY_ERROR,
            'device_kind': 'mac_or_unverified_safari',
            'needs_ipad_probe': not has_touch_probe,
        }

    return {
        'allowed': False,
        'is_web': True,
        'code': 'WEB_IOS_ONLY_REQUIRED',
        'error': WEB_IOS_ONLY_ERROR,
        'device_kind': 'blocked_web_browser',
        'needs_ipad_probe': False,
    }


def verify_web_device_live_consistency(request, user, installation_id: str) -> tuple[bool, str | None, str | None]:
    """
    يفحص تطابق الترويسات الحية للطلب مع بصمة المتصفح المسجّلة في كل طلب لاحق
    لكشف سرقة الكوكي أو تشغيل نفس الجلسة من متصفح أو جهاز مختلف فوراً.
    """
    if request is None or not user or not getattr(user, 'is_authenticated', False) or not installation_id:
        return True, None, None

    device = RegisteredDevice.objects.filter(
        user=user,
        installation_id=installation_id,
        package_name=WEB_PACKAGE_NAME,
    ).first()
    if device is None:
        return True, None, None

    meta = getattr(request, 'META', {}) or {}
    ua = str(meta.get('HTTP_USER_AGENT') or '')
    if not ua:
        return True, None, None

    parsed = parse_web_user_agent(ua)
    sec_platform = str(meta.get('HTTP_SEC_CH_UA_PLATFORM') or '').strip().strip('"')
    live_os = (sec_platform or parsed['os_label']).lower()
    live_browser = parsed['browser_name'].lower()

    existing_traits = {}
    if isinstance(device.integrity_signals, dict) and isinstance(device.integrity_signals.get('web_traits'), dict):
        existing_traits = device.integrity_signals.get('web_traits') or {}
    spoof_reasons = detect_web_fingerprint_spoofing(request, client_traits=existing_traits)

    stored_browser = str(device.manufacturer or '').strip().lower()
    stored_os = str(device.cpu_arch or '').strip().lower()

    ipad_compatible = (
        stored_os == 'ipados'
        and live_os == 'macos'
        and not sec_platform
        and parsed['browser_name'] == 'Apple Safari'
    )
    browser_mismatch = bool(stored_browser and live_browser and stored_browser != live_browser)
    os_mismatch = bool(stored_os and live_os and stored_os != live_os and not ipad_compatible)

    if spoof_reasons or browser_mismatch or os_mismatch:
        now = timezone.now()
        if device.trust_status != DeviceTrustStatus.BLOCKED:
            device.trust_status = DeviceTrustStatus.RESTRICTED
        device.requires_reauth = True
        device.risk_score = 95
        device.risk_level = 'critical'
        device.save(update_fields=['trust_status', 'requires_reauth', 'risk_score', 'risk_level'])

        DeviceSession.objects.filter(device=device, status='active').update(
            status='revoked',
            ended_at=now,
            revoked_reason='web_cookie_hijack_mismatch',
        )
        PlaybackSession.objects.filter(
            user=user,
            device_id=installation_id,
            status='active',
        ).update(status='revoked', revoked_reason='web_cookie_hijack_mismatch', view_window_expires_at=now)
        from api_v1.video_security import clear_watch_window
        clear_watch_window(user, now=now)

        record_security_event(
            event_type='web_cookie_hijack_mismatch' if (browser_mismatch or os_mismatch) else 'web_fingerprint_spoof_detected',
            severity='critical',
            risk_score=95,
            user=user,
            device=device,
            installation_id=installation_id,
            request=request,
            action_taken='session_revoked_and_restricted',
            details={
                'stored_browser': stored_browser,
                'live_browser': live_browser,
                'stored_os': stored_os,
                'live_os': live_os,
                'spoof_reasons': spoof_reasons,
            },
            notify_user=True,
            notify_title='تنبيه أمني: محاولة استخدام جلستك من متصفح مختلف',
            notify_message='تم إيقاف جلسة التصفح فوراً لاكتشاف تغير صارم في بصمة المتصفح أو نظام التشغيل.',
        )
        return (
            False,
            'WEB_FINGERPRINT_MISMATCH',
            'تم إيقاف الجلسة لاكتشاف تغير في بصمة المتصفح أو محاولة نسخ الجلسة.',
        )

    return True, None, None


def enforce_web_lecture_playback(request, user, lecture, *, course_package=None) -> dict[str, Any]:
    """
    يفحص صلاحية جهاز الويب (iPhone/iPad فقط وبصمة مطابقة) وحد الأجهزة ومشاركة الحساب والتشغيل المتزامن
    قبل عرض مشغّل الفيديو على الموقع، وينشئ أو يدوّر جلسة PlaybackSession نشطة لهذا المتصفح.
    """
    from api_v1.video_security import build_watermark_payload, create_or_rotate_playback_session

    installation_id = get_or_create_web_installation_id(request)
    ios_check = check_web_ios_only_lecture_access(request, user, force_web=True)
    if not ios_check.get('allowed'):
        record_security_event(
            event_type='web_non_ios_lecture_blocked',
            severity='medium',
            risk_score=40,
            user=user,
            installation_id=installation_id,
            request=request,
            action_taken='blocked_web_lecture_non_ios',
            details={
                'lecture_id': getattr(lecture, 'id', None),
                'device_kind': ios_check.get('device_kind'),
                'code': ios_check.get('code'),
                'spoof_reasons': ios_check.get('spoof_reasons', []),
            },
        )
        return {
            'allowed': False,
            'code': ios_check.get('code') or 'WEB_IOS_ONLY_REQUIRED',
            'error': ios_check.get('error') or WEB_IOS_ONLY_ERROR,
            'installation_id': installation_id,
            'needs_ipad_probe': bool(ios_check.get('needs_ipad_probe')),
        }

    live_ok, live_code, live_err = verify_web_device_live_consistency(request, user, installation_id)
    if not live_ok:
        return {
            'allowed': False,
            'code': live_code or 'WEB_FINGERPRINT_MISMATCH',
            'error': live_err or 'تم إيقاف الجلسة بسبب اختلاف بصمة المتصفح.',
            'installation_id': installation_id,
        }

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

    if device and isinstance(device.integrity_signals, dict) and device.integrity_signals.get('webdriver_detected'):
        return {
            'allowed': False,
            'code': 'WEB_AUTOMATION_BLOCKED',
            'error': 'تم حظر تشغيل المحاضرات عبر المتصفحات الآلية أو أدوات الفحص.',
            'installation_id': installation_id,
        }

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

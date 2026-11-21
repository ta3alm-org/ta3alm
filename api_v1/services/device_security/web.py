"""api_v1.services.device_security.web
Extracted from api_v1/device_security_service.py.
"""
from __future__ import annotations

import hashlib
import re
import uuid
from typing import Any
from django.core import signing

from api_v1.services.device_security.constants import (
    WEB_COOKIE_NAME,
    WEB_COOKIE_SALT,
    WEB_PACKAGE_NAME,
    _BROWSER_UA_MARKERS,
    _DESKTOP_OR_EMULATED_GPU_TOKENS,
)
from api_v1.services.device_security.fingerprint import validate_installation_id


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


def _has_desktop_or_emulated_gpu(gpu_vendor: str, gpu_renderer: str) -> bool:
    combined = f"{gpu_vendor or ''} {gpu_renderer or ''}".lower()
    if not combined.strip():
        return False
    return any(tok in combined for tok in _DESKTOP_OR_EMULATED_GPU_TOKENS)


def is_web_client_request(request) -> bool:
    """يميز طلبات المتصفح (الويب) عن طلبات تطبيق الأندرويد الأصلي وعملاء الاختبار المجردين."""
    if request is None:
        return False
    meta = getattr(request, 'META', {}) or {}
    ua = str(meta.get('HTTP_USER_AGENT') or '')
    ua_low = ua.lower()

    if 'dart/' in ua_low:
        return False

    explicit_platform = str(meta.get('HTTP_X_CLIENT_PLATFORM') or '').strip().lower()
    if not explicit_platform and hasattr(request, 'GET'):
        explicit_platform = str(request.GET.get('platform') or '').strip().lower()
    if explicit_platform == 'web':
        return True

    raw_dev = str(meta.get('HTTP_X_DEVICE_ID') or '').strip().lower()
    if raw_dev.startswith('web-'):
        return True

    cookies = getattr(request, 'COOKIES', None) or {}
    if cookies.get(WEB_COOKIE_NAME):
        return True

    if meta.get('HTTP_ORIGIN') or meta.get('HTTP_SEC_FETCH_MODE') or meta.get('HTTP_SEC_FETCH_SITE'):
        return True

    return any(marker in ua_low for marker in _BROWSER_UA_MARKERS)


def _extract_web_or_device_id_from_request(request) -> str:
    if request is None:
        return ''
    meta = getattr(request, 'META', {}) or {}
    raw_dev = str(meta.get('HTTP_X_DEVICE_ID') or '').strip()
    if raw_dev:
        return raw_dev[:128]
    if hasattr(request, 'get_signed_cookie'):
        try:
            loaded = request.get_signed_cookie(WEB_COOKIE_NAME, default='', salt=WEB_COOKIE_SALT)
            if loaded:
                return str(loaded).strip()[:128]
        except Exception:
            pass
    if hasattr(request, 'session'):
        sess_val = str(request.session.get('web_installation_id') or '').strip()
        if sess_val:
            return sess_val[:128]
    return ''


def detect_web_fingerprint_spoofing(request, client_traits: dict[str, Any] | None = None) -> list[str]:
    """يكشف التناقضات الصريحة بين ترويسات المتصفح وخصائص JavaScript/WebGL/اللمس (تزييف F12 أو نسخ الجلسة)."""
    meta = getattr(request, 'META', {}) if request is not None else {}
    ua = str(meta.get('HTTP_USER_AGENT') or '')
    ua_low = ua.lower()
    parsed = parse_web_user_agent(ua)
    src = client_traits if isinstance(client_traits, dict) else {}

    sec_platform = str(meta.get('HTTP_SEC_CH_UA_PLATFORM') or '').strip().strip('"').lower()
    sec_ch_ua = str(meta.get('HTTP_SEC_CH_UA') or '').lower()
    is_ios_ua = parsed['os_label'] == 'iOS'
    is_mac_safari_ua = (
        ('macintosh' in ua_low or 'mac os x' in ua_low)
        and 'safari/' in ua_low
        and 'chrome/' not in ua_low
        and 'chromium/' not in ua_low
        and 'firefox/' not in ua_low
        and 'edg/' not in ua_low
        and 'opr/' not in ua_low
    )

    reasons: list[str] = []
    if is_ios_ua:
        if sec_platform and sec_platform not in ('ios', 'iphoneos', 'ipados'):
            reasons.append('sec_ch_platform_mismatch')
        if sec_ch_ua and any(b in sec_ch_ua for b in ('chromium', 'google chrome', 'microsoft edge', 'opera')):
            reasons.append('sec_ch_browser_spoof')
    elif parsed['os_label'] == 'Windows' and sec_platform and sec_platform != 'windows':
        reasons.append('sec_ch_platform_mismatch')
    elif parsed['os_label'] == 'macOS' and sec_platform and sec_platform not in ('macos', 'mac os x'):
        reasons.append('sec_ch_platform_mismatch')

    nav_platform = str(src.get('navigator_platform') or '').strip().lower()
    gpu_renderer = str(src.get('gpu_renderer') or '').strip()
    gpu_vendor = str(src.get('gpu_vendor') or '').strip()
    touch_raw = src.get('max_touch_points')
    touch_support = src.get('touch_support')

    if is_ios_ua:
        if nav_platform and any(
            nav_platform.startswith(p) for p in ('win', 'linux', 'mac', 'x11', 'cros', 'freebsd')
        ):
            reasons.append('navigator_platform_mismatch')
        if _has_desktop_or_emulated_gpu(gpu_vendor, gpu_renderer):
            reasons.append('desktop_or_emulated_gpu_on_ios')
        if touch_raw is not None and str(touch_raw).strip() != '':
            try:
                if int(touch_raw) <= 0:
                    reasons.append('no_touch_hardware_on_ios_ua')
            except (TypeError, ValueError):
                pass
        if touch_support is False:
            reasons.append('no_touch_hardware_on_ios_ua')
    elif is_mac_safari_ua:
        if nav_platform and any(nav_platform.startswith(p) for p in ('win', 'linux', 'x11', 'cros')):
            reasons.append('navigator_platform_mismatch')
    else:
        if nav_platform.startswith('win') and parsed['os_label'] in ('Linux', 'macOS', 'Android'):
            reasons.append('navigator_platform_mismatch')
        elif nav_platform.startswith('mac') and parsed['os_label'] in ('Windows', 'Linux', 'Android'):
            reasons.append('navigator_platform_mismatch')

    return reasons


def build_web_device_info(request, client_traits: dict[str, Any] | None = None) -> dict[str, Any]:
    """
    يبني قاموس خصائص متصفح الويب (Device Info) عبر الدمج بين الترويسات التي يلاحظها الخادم
    والخصائص الصارمة التي يرسلها المتصفح لتوليد بصمة fp_v1 موثوقة ومقاومة للتزييف.
    """
    meta = getattr(request, 'META', {}) if request is not None else {}
    ua = str(meta.get('HTTP_USER_AGENT') or '')
    parsed = parse_web_user_agent(ua)
    src = client_traits if isinstance(client_traits, dict) else {}

    def _clean(val: Any, max_len: int = 128) -> str:
        return re.sub(r'\s+', ' ', str(val or '').strip())[:max_len]

    sec_platform = str(meta.get('HTTP_SEC_CH_UA_PLATFORM') or '').strip().strip('"')
    gpu_renderer = _clean(src.get('gpu_renderer'), 255)
    gpu_vendor = _clean(src.get('gpu_vendor'), 255)
    canvas_hash = _clean(src.get('canvas_hash'), 128).lower()
    webgl_hash = _clean(src.get('webgl_hash'), 128).lower()
    audio_hash = _clean(src.get('audio_hash'), 128).lower()
    nav_platform = _clean(src.get('navigator_platform'), 64)
    color_depth = _clean(src.get('color_depth'), 16)
    timezone_str = _clean(src.get('timezone'), 64)
    languages = _clean(src.get('languages'), 128)
    raw_touch = src.get('max_touch_points')
    touch_points_int = None
    if raw_touch is not None and str(raw_touch).strip() != '':
        try:
            touch_points_int = max(int(raw_touch), 0)
        except (TypeError, ValueError):
            touch_points_int = None
    touch_support = src.get('touch_support')
    if touch_support is not None:
        touch_support = bool(touch_support)

    # التمييز الصارم بين Mac و iPad في وضع سطح المكتب (Desktop Safari): كلاهما يرسل Macintosh لكن iPad متعدد اللمس
    os_label = sec_platform or parsed['os_label']
    is_ipad_desktop_mode = False
    if (
        parsed['os_label'] == 'macOS'
        and parsed['browser_name'] == 'Apple Safari'
        and not sec_platform
        and touch_points_int is not None
        and touch_points_int >= 2
        and touch_support is True
        and not _has_desktop_or_emulated_gpu(gpu_vendor, gpu_renderer)
        and not bool(src.get('webdriver_detected'))
    ):
        os_label = 'iPadOS'
        is_ipad_desktop_mode = True

    accept_lang = str(meta.get('HTTP_ACCEPT_LANGUAGE') or '').split(',')[0].strip()[:32]
    browser_name = parsed['browser_name']
    browser_vendor = parsed['browser_vendor']
    spoof_reasons = detect_web_fingerprint_spoofing(request, client_traits=src)

    hw_sig_parts = [
        canvas_hash,
        webgl_hash,
        audio_hash,
        gpu_renderer.lower(),
        gpu_vendor.lower(),
        nav_platform.lower(),
        color_depth,
        str(touch_points_int) if touch_points_int is not None else '',
    ]
    web_hw_sig = (
        hashlib.sha256('|'.join(hw_sig_parts).encode('utf-8')).hexdigest()
        if any([canvas_hash, webgl_hash, audio_hash, gpu_renderer])
        else ''
    )

    web_traits_snapshot = {
        'canvas_hash': canvas_hash,
        'webgl_hash': webgl_hash,
        'audio_hash': audio_hash,
        'gpu_renderer': gpu_renderer,
        'gpu_vendor': gpu_vendor,
        'cpu_arch': _clean(src.get('cpu_arch'), 64),
        'cpu_info': _clean(src.get('cpu_info'), 180),
        'navigator_platform': nav_platform,
        'max_touch_points': touch_points_int,
        'touch_support': touch_support,
        'color_depth': color_depth,
        'timezone': timezone_str,
        'languages': languages,
        'screen_resolution': _clean(src.get('screen_resolution'), 64),
        'webdriver_detected': bool(src.get('webdriver_detected')),
        'is_ipad_desktop_mode': is_ipad_desktop_mode,
        'web_hw_sig': web_hw_sig,
    }
    web_traits_snapshot = {k: v for k, v in web_traits_snapshot.items() if v not in ('', None)}

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
        'gpu_renderer': gpu_renderer,
        'gpu_vendor': gpu_vendor,
        'screen_resolution': _clean(src.get('screen_resolution'), 64).lower(),
        'app_version': parsed['browser_version'] or 'web-1.0',
        'app_build_number': 'web',
        'package_name': WEB_PACKAGE_NAME,
        'signing_cert_sha256': '',
        'installer_source': 'web_browser',
        'web_canvas_hash': canvas_hash,
        'web_webgl_hash': webgl_hash,
        'web_audio_hash': audio_hash,
        'web_hw_sig': web_hw_sig,
        'web_max_touch_points': str(touch_points_int) if touch_points_int is not None else '',
        'web_color_depth': color_depth,
        'web_navigator_platform': nav_platform.lower(),
        'integrity_signals': {
            'is_web_browser': True,
            'webdriver_detected': bool(src.get('webdriver_detected')),
            'timezone': timezone_str,
            'accept_language': accept_lang,
            'sec_ch_ua': _clean(meta.get('HTTP_SEC_CH_UA'), 255),
            'sec_ch_platform': sec_platform[:64],
            'web_spoof_reasons': spoof_reasons,
            'web_traits': web_traits_snapshot,
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

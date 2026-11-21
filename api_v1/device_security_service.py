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
WEB_STRICT_CORE_FIELDS = (
    'manufacturer',
    'model',
    'cpu_arch',
    'cpu_info',
    'gpu_renderer',
    'gpu_vendor',
    'web_canvas_hash',
    'web_webgl_hash',
    'web_audio_hash',
    'web_hw_sig',
    'web_max_touch_points',
    'web_color_depth',
    'web_navigator_platform',
)


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
        'web_canvas_hash': _s('web_canvas_hash', 128, lower=True),
        'web_webgl_hash': _s('web_webgl_hash', 128, lower=True),
        'web_audio_hash': _s('web_audio_hash', 128, lower=True),
        'web_hw_sig': _s('web_hw_sig', 128, lower=True),
        'web_max_touch_points': _s('web_max_touch_points', 16, lower=True),
        'web_color_depth': _s('web_color_depth', 16, lower=True),
        'web_navigator_platform': _s('web_navigator_platform', 64, lower=True),
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
    is_web_device = str(traits.get('package_name') or '').strip() == WEB_PACKAGE_NAME
    core_payload = '|'.join(
        [
            algorithm_version,
            installation_id,
            str(traits.get('manufacturer', '')).lower(),
            str(traits.get('model', '')).lower(),
            str(traits.get('cpu_arch', '')).lower(),
            str(traits.get('package_name', '')).lower(),
            str(traits.get('web_hw_sig', '')).lower() if is_web_device else '',
            str(traits.get('web_canvas_hash', '')).lower() if is_web_device else '',
            str(traits.get('web_webgl_hash', '')).lower() if is_web_device else '',
            str(traits.get('web_audio_hash', '')).lower() if is_web_device else '',
            str(traits.get('web_navigator_platform', '')).lower() if is_web_device else '',
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
            str(traits.get('web_max_touch_points', '')).lower() if is_web_device else '',
            str(traits.get('web_color_depth', '')).lower() if is_web_device else '',
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
        fields_to_check = list(dict.fromkeys((*CORE_FINGERPRINT_FIELDS, *SUPPORTING_FINGERPRINT_FIELDS, *(WEB_STRICT_CORE_FIELDS if is_web_device else ()))))
        for field in fields_to_check:
            old_val = str(prev.get(field, '') or '').strip().lower()
            new_val = str(traits.get(field, '') or '').strip().lower()
            if old_val and new_val and old_val != new_val:
                changed_fields.append(field)

        # الترقية الأولى من macOS Safari (قبل مزامنة سمات اللمس) إلى iPadOS عند إثبات تعدد اللمس مسموحة لمرة واحدة
        prev_had_web_hw = bool(str(prev.get('web_hw_sig', '') or '').strip() or str(prev.get('gpu_renderer', '') or '').strip())
        ipad_mode_promotion = (
            is_web_device
            and not prev_had_web_hw
            and str(prev.get('cpu_arch', '') or '').lower() == 'macos'
            and str(traits.get('cpu_arch', '') or '').lower() == 'ipados'
            and 'manufacturer' not in changed_fields
        )
        effective_changed = [
            f for f in changed_fields
            if not (ipad_mode_promotion and f in ('cpu_arch', 'model'))
        ]

        if is_web_device:
            strict_changed = [f for f in effective_changed if f in WEB_STRICT_CORE_FIELDS]
            if strict_changed:
                core_mismatch = True
                drift_score += 90
        else:
            core_changed = [f for f in effective_changed if f in ('manufacturer', 'model', 'cpu_arch')]
            if core_changed:
                core_mismatch = True
                drift_score += 55
        if 'package_name' in effective_changed:
            drift_score += 40
        if 'signing_cert_sha256' in effective_changed:
            drift_score += 45
        benign_changed = [
            f for f in effective_changed
            if f in BENIGN_DRIFT_FIELDS and (not is_web_device or f not in WEB_STRICT_CORE_FIELDS)
        ]
        if benign_changed and not core_mismatch:
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


_VPN_ISP_KEYWORDS = (
    'cloudflare warp',
    'm247',
    'nordvpn',
    'expressvpn',
    'protonvpn',
    'proton ag',
    'mullvad',
    'surfshark',
    'windscribe',
    'psiphon',
    'privatelayer',
    'tzulo',
    'datacamp',
    'packethub',
    'choopa',
    'vultr',
    'hetzner',
    'ovh',
    'linode',
    'digitalocean',
    'tor exit',
    'wireguard',
)


def extract_network_context(request, integrity_signals: dict[str, Any] | None = None) -> dict[str, Any]:
    """يستخلص سياق الشبكة والموقع التقريبي وإشارات الـ VPN/Proxy والـ DNS من ترويسات الخادم والعميل."""
    ip_addr = get_server_observed_ip(request)
    meta = getattr(request, 'META', {}) if request is not None else {}
    sig = integrity_signals if isinstance(integrity_signals, dict) else {}

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

    isp_low = isp.lower()
    cf_warp = str(meta.get('HTTP_CF_WARP') or '').strip().lower() in ('1', 'true', 'yes', 'on')
    header_vpn = str(meta.get('HTTP_X_VPN_SUSPECTED') or meta.get('HTTP_X_VPN_ACTIVE') or '').strip().lower() in ('1', 'true', 'yes', 'on')
    proxy_via = bool((meta.get('HTTP_VIA') or meta.get('HTTP_X_PROXY_ID') or '').strip())
    isp_vpn = any(tok in isp_low for tok in _VPN_ISP_KEYWORDS) if isp_low else False
    client_vpn = bool(sig.get('vpn_interface_active'))

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
        'is_vpn_or_proxy': header_vpn or cf_warp or proxy_via or isp_vpn or client_vpn,
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


def _clean_hw_token(val: Any) -> str:
    return re.sub(r'[^a-z0-9]', '', str(val or '').lower())


def _normalize_gpu_core(gpu_renderer: Any) -> str:
    """يطبع اسم معالج الرسوميات للمقارنة بين تطبيق الأندرويد ومتصفح الويب على نفس الهاتف."""
    raw = str(gpu_renderer or '').strip().lower()
    if not raw:
        return ''
    # إزالة أغلفة Chrome ANGLE ونسخة OpenGL حتى يتطابق ANGLE (ARM, Mali-G68, OpenGL ES...) مع Mali-G68
    raw = re.sub(r'^angle\s*\(', '', raw)
    raw = re.sub(r'\)\s*$', '', raw)
    raw = re.sub(r'opengl\s*es.*$', '', raw)
    raw = re.sub(r'vulkan.*$', '', raw)
    raw = re.sub(r'\(tm\)|\(r\)', '', raw)
    parts = [p.strip() for p in raw.split(',') if p.strip()]
    if len(parts) >= 2 and parts[0] in ('arm', 'qualcomm', 'imagination technologies', 'google', 'samsung'):
        raw = parts[1]
    elif parts:
        raw = parts[0]
    return re.sub(r'[^a-z0-9]', '', raw)[:48]


def extract_android_model_from_ua(user_agent: str, sec_model: str = '') -> str:
    """يستخرج موديل هاتف الأندرويد من User-Agent أو Sec-CH-UA-Model (متجاهلاً الرمز العام K)."""
    candidate = str(sec_model or '').strip().strip('"')
    if not candidate and user_agent:
        m = re.search(r'Android\s+[^;)]+;\s*([^;)]+?)(?:\s+Build/|;|\))', user_agent, re.IGNORECASE)
        if m:
            candidate = m.group(1).strip()
    tok = _clean_hw_token(candidate)
    if tok in ('', 'k', 'mobile', 'android', 'wv', 'linux'):
        return ''
    return tok


def _resolve_os_family(os_name: str, cpu_arch: str = '', user_agent: str = '') -> str:
    combined = f"{os_name or ''} {cpu_arch or ''} {user_agent or ''}".lower()
    if 'ipados' in combined or 'ipad' in combined:
        return 'ipados'
    if 'iphone' in combined or 'ios' in combined:
        return 'ios'
    if 'android' in combined:
        return 'android'
    if 'windows' in combined:
        return 'windows'
    if 'mac' in combined or 'darwin' in combined:
        return 'macos'
    if 'linux' in combined or 'x11' in combined:
        return 'linux'
    return _clean_hw_token(os_name) or 'unknown'


def _extract_device_hw_profile(
    traits: dict[str, Any] | None = None,
    *,
    device: RegisteredDevice | None = None,
    request=None,
) -> dict[str, str]:
    src = traits if isinstance(traits, dict) else {}
    meta = getattr(request, 'META', {}) if request is not None else {}
    ua = str(meta.get('HTTP_USER_AGENT') or '')

    if device is not None:
        os_name = str(src.get('os_name') or device.os_name or '')
        cpu_arch = str(src.get('cpu_arch') or device.cpu_arch or '')
        raw_model = str(src.get('model') or device.model or '')
        manufacturer = str(src.get('manufacturer') or device.manufacturer or '')
        gpu_renderer = str(src.get('gpu_renderer') or device.gpu_renderer or '')
        pkg = str(src.get('package_name') or device.package_name or '')
        web_hw_sig = str(src.get('web_hw_sig') or '')
        if not web_hw_sig and isinstance(device.integrity_signals, dict):
            wt = device.integrity_signals.get('web_traits')
            if isinstance(wt, dict):
                web_hw_sig = str(wt.get('web_hw_sig') or '')
        ip_addr = str(device.last_ip or '')
    else:
        os_name = str(src.get('os_name') or '')
        cpu_arch = str(src.get('cpu_arch') or '')
        raw_model = str(src.get('model') or meta.get('HTTP_X_DEVICE_MODEL') or '')
        manufacturer = str(src.get('manufacturer') or '')
        gpu_renderer = str(src.get('gpu_renderer') or meta.get('HTTP_X_DEVICE_GPU') or '')
        pkg = str(src.get('package_name') or '')
        web_hw_sig = str(src.get('web_hw_sig') or '')
        ip_addr = get_server_observed_ip(request) or ''

    os_family = _resolve_os_family(os_name, cpu_arch, ua)
    is_web = pkg == WEB_PACKAGE_NAME or os_name.lower().startswith('web')
    sec_model = str(meta.get('HTTP_SEC_CH_UA_MODEL') or meta.get('HTTP_X_DEVICE_MODEL') or '').strip().strip('"')

    model_tok = ''
    if not is_web:
        model_tok = _clean_hw_token(raw_model)
    elif os_family == 'android':
        model_tok = extract_android_model_from_ua(ua, sec_model)
        if not model_tok and raw_model and ' on ' not in raw_model.lower():
            model_tok = _clean_hw_token(raw_model)

    return {
        'os_family': os_family,
        'model_token': model_tok,
        'manufacturer_token': _clean_hw_token(manufacturer) if not is_web else '',
        'gpu_core': _normalize_gpu_core(gpu_renderer),
        'web_hw_sig': web_hw_sig.strip().lower(),
        'ip_address': ip_addr.strip(),
        'is_web': '1' if is_web else '0',
    }


def _find_matching_canonical_hardware_id(
    profile: dict[str, str],
    *,
    installation_id: str = '',
    exclude_pk: int | None = None,
) -> str | None:
    """
    يبحث عن جهاز مادي مسجّل مسبقاً يطابق نفس الهاتف/الجهاز (سواء تطبيق أندرويد أو متصفح ويب أو حساب آخر)
    حتى يوحّد التطبيق والمتصفح والحسابات المتعددة تحت معرف DEV-XXXXXXXX واحد.
    """
    clean_inst = str(installation_id or '').strip()
    os_fam = profile.get('os_family', '')
    model_tok = profile.get('model_token', '')
    gpu_core = profile.get('gpu_core', '')
    web_hw_sig = profile.get('web_hw_sig', '')
    ip_addr = profile.get('ip_address', '')

    candidates = RegisteredDevice.objects.only(
        'id',
        'installation_id',
        'os_name',
        'cpu_arch',
        'model',
        'manufacturer',
        'gpu_renderer',
        'package_name',
        'last_ip',
        'last_active_at',
        'integrity_signals',
    ).order_by('-last_active_at')[:350]

    recent_cutoff = timezone.now() - timedelta(days=30)
    for dev in candidates:
        if exclude_pk and dev.pk == exclude_pk:
            continue
        sigs = dev.integrity_signals if isinstance(dev.integrity_signals, dict) else {}
        cand_hw_id = str(sigs.get('hardware_id') or '').strip()
        if not cand_hw_id.startswith('DEV-'):
            continue

        # 1) نفس installation_id على أي حساب
        if clean_inst and dev.installation_id == clean_inst:
            return cand_hw_id

        cand_prof = _extract_device_hw_profile(device=dev)
        if cand_prof['os_family'] != os_fam:
            continue

        # 2) تطابق Web hardware signature الصارم لنفس المتصفح أو التصفح الخفي
        if web_hw_sig and cand_prof['web_hw_sig'] and web_hw_sig == cand_prof['web_hw_sig']:
            return cand_hw_id

        # 3) الربط العابر للمنصات على الأندرويد (تطبيق أندرويد <-> متصفح أندرويد على نفس الهاتف)
        if os_fam == 'android':
            same_model = bool(model_tok and cand_prof['model_token'] and model_tok == cand_prof['model_token'])
            same_gpu = bool(gpu_core and cand_prof['gpu_core'] and (gpu_core == cand_prof['gpu_core'] or gpu_core in cand_prof['gpu_core'] or cand_prof['gpu_core'] in gpu_core))
            same_ip = bool(ip_addr and cand_prof['ip_address'] and ip_addr == cand_prof['ip_address'])

            if same_model and (same_gpu or same_ip):
                return cand_hw_id
            if same_ip and dev.last_active_at and dev.last_active_at >= recent_cutoff:
                # إذا تطابق نفس الـ IP ونظام Android و(GPU متطابق أو المتصفح أخفى الموديل بكلمة K)
                if same_gpu or not model_tok or not cand_prof['model_token']:
                    return cand_hw_id

    return None


def compute_canonical_hardware_id(
    traits: dict[str, Any] | None = None,
    *,
    installation_id: str = '',
    request=None,
    net_ctx: dict[str, Any] | None = None,
    existing_device: RegisteredDevice | None = None,
) -> str:
    """يولّد أو يسترجع معرّف الجهاز المادي الموحّد (DEV-XXXXXXXX) لتفادي التكرار وحظر التطبيق والمتصفح معاً."""
    if existing_device is not None and isinstance(existing_device.integrity_signals, dict):
        saved = str(existing_device.integrity_signals.get('hardware_id') or '').strip()
        if saved.startswith('DEV-') and len(saved) == 12:
            # تحقّق إن كان هناك جهاز أندرويد رئيسي بنفس الموديل/IP لربط التطبيق والمتصفح تحت معرّف أقدم واحد
            profile = _extract_device_hw_profile(traits, device=existing_device, request=request)
            if net_ctx and net_ctx.get('ip_address') and not profile.get('ip_address'):
                profile['ip_address'] = str(net_ctx['ip_address'])
            linked = _find_matching_canonical_hardware_id(
                profile,
                installation_id=installation_id or existing_device.installation_id,
                exclude_pk=existing_device.pk,
            )
            return linked or saved

    profile = _extract_device_hw_profile(traits, device=existing_device, request=request)
    if net_ctx and net_ctx.get('ip_address') and not profile.get('ip_address'):
        profile['ip_address'] = str(net_ctx['ip_address'])

    matched = _find_matching_canonical_hardware_id(
        profile,
        installation_id=installation_id,
        exclude_pk=existing_device.pk if existing_device else None,
    )
    if matched:
        return matched

    seed_parts = [
        profile.get('os_family', ''),
        profile.get('model_token', ''),
        profile.get('gpu_core', ''),
        profile.get('web_hw_sig', ''),
        str(installation_id or (existing_device.installation_id if existing_device else '')),
    ]
    # إذا توافرت سمات عتاد صلبة (تطبيق أصلي بموديل + GPU أو ويب ببصمة WebGL/Canvas)، استبعد installation_id لتوحيد المعرّف
    if (profile.get('os_family') == 'android' and profile.get('model_token') and profile.get('gpu_core')) or profile.get('web_hw_sig'):
        seed_parts[-1] = profile.get('os_family', '')

    digest = hmac.new(
        _fingerprint_secret(),
        f"hw_id_v1:{'|'.join(seed_parts)}".encode('utf-8'),
        hashlib.sha256,
    ).hexdigest()[:8].upper()
    return f"DEV-{digest}"


def get_device_hardware_id(device: RegisteredDevice) -> str:
    """يرجع معرّف الجهاز الموحد DEV-XXXXXXXX من سجل الجهاز أو يحسبه ويحفظه."""
    sigs = dict(device.integrity_signals) if isinstance(device.integrity_signals, dict) else {}
    existing = str(sigs.get('hardware_id') or '').strip()
    if existing.startswith('DEV-') and len(existing) == 12:
        return existing

    hw_id = compute_canonical_hardware_id(
        {
            'device_name': device.device_name,
            'manufacturer': device.manufacturer,
            'model': device.model,
            'os_name': device.os_name,
            'cpu_arch': device.cpu_arch,
            'gpu_renderer': device.gpu_renderer,
            'package_name': device.package_name,
        },
        installation_id=device.installation_id,
        existing_device=device,
    )
    sigs['hardware_id'] = hw_id
    device.integrity_signals = sigs
    try:
        RegisteredDevice.objects.filter(pk=device.pk).update(integrity_signals=sigs)
    except Exception:
        pass
    return hw_id


def _filter_active_non_expired_block(blocks_qs) -> DeviceBlock | None:
    now = timezone.now()
    for blk in blocks_qs.order_by('-created_at'):
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


def get_active_device_block(
    installation_id: str = '',
    *,
    hardware_id: str = '',
    request=None,
    net_ctx: dict[str, Any] | None = None,
) -> DeviceBlock | None:
    """
    يتحقق من وجود حظر نشط للجهاز عبر:
    - installation_id المباشر
    - معرّف العتاد الموحد hardware_id (DEV-XXXXXXXX) عبر fingerprint_hash
    - الربط العابر للمنصات (حظر هاتف أندرويد يحظر التطبيق والمتصفح معاً)
    """
    clean_inst = str(installation_id or '').strip()
    clean_hw = str(hardware_id or '').strip()

    if not clean_hw and request is not None:
        clean_hw = str(request.META.get('HTTP_X_HARDWARE_ID') or '').strip()

    if not clean_hw and clean_inst:
        existing_dev = RegisteredDevice.objects.filter(installation_id=clean_inst).first()
        if existing_dev is not None:
            clean_hw = get_device_hardware_id(existing_dev)

    if not clean_hw and request is not None:
        meta = getattr(request, 'META', {}) or {}
        ua = str(meta.get('HTTP_USER_AGENT') or '')
        parsed = parse_web_user_agent(ua) if ua else {'os_label': ''}
        model_hdr = str(meta.get('HTTP_X_DEVICE_MODEL') or '').strip()
        gpu_hdr = str(meta.get('HTTP_X_DEVICE_GPU') or '').strip()
        req_traits = {
            'os_name': 'Android' if 'dart/' in ua.lower() or str(meta.get('HTTP_X_CLIENT_PLATFORM') or '').lower() == 'android' else f"Web ({parsed.get('os_label', '')})",
            'model': model_hdr,
            'gpu_renderer': gpu_hdr,
            'package_name': '' if str(meta.get('HTTP_X_CLIENT_PLATFORM') or '').lower() == 'android' else WEB_PACKAGE_NAME,
        }
        profile = _extract_device_hw_profile(req_traits, request=request)
        if net_ctx and net_ctx.get('ip_address'):
            profile['ip_address'] = str(net_ctx['ip_address'])
        matched_hw = _find_matching_canonical_hardware_id(profile, installation_id=clean_inst)
        if matched_hw:
            clean_hw = matched_hw

    q_filter = Q()
    if clean_inst:
        q_filter |= Q(installation_id=clean_inst)
    if clean_hw:
        q_filter |= Q(fingerprint_hash=clean_hw) | Q(installation_id=clean_hw)

    if q_filter:
        blk = _filter_active_non_expired_block(DeviceBlock.objects.filter(q_filter, is_active=True))
        if blk:
            return blk

    # مطابقة احتياطية للأندرويد (مثلاً عند فتح متصفح خفي من نفس هاتف الأندرويد المحظور)
    if request is not None:
        ctx = net_ctx or extract_network_context(request)
        ip_addr = ctx.get('ip_address')
        meta = getattr(request, 'META', {}) or {}
        ua = str(meta.get('HTTP_USER_AGENT') or '')
        os_fam = _resolve_os_family(
            str(meta.get('HTTP_X_CLIENT_PLATFORM') or ''),
            '',
            ua,
        )
        if os_fam == 'android' and ip_addr:
            req_model = extract_android_model_from_ua(
                ua,
                str(meta.get('HTTP_SEC_CH_UA_MODEL') or meta.get('HTTP_X_DEVICE_MODEL') or ''),
            )
            blocked_androids = RegisteredDevice.objects.filter(
                trust_status=DeviceTrustStatus.BLOCKED,
                last_ip=ip_addr,
                os_name__icontains='android',
            ).order_by('-last_active_at')[:10]
            for bdev in blocked_androids:
                cand_model = _clean_hw_token(bdev.model)
                if not req_model or not cand_model or req_model == cand_model or cand_model in req_model:
                    blk = _filter_active_non_expired_block(
                        DeviceBlock.objects.filter(
                            Q(device=bdev) | Q(installation_id=bdev.installation_id) | Q(fingerprint_hash=get_device_hardware_id(bdev)),
                            is_active=True,
                        )
                    )
                    if blk:
                        return blk
                    return DeviceBlock(
                        device=bdev,
                        user=bdev.user,
                        installation_id=bdev.installation_id,
                        fingerprint_hash=get_device_hardware_id(bdev),
                        block_type='permanent',
                        reason=bdev.revoked_reason or 'هذا الجهاز محظور إدارياً (تطبيق + متصفح).',
                        is_active=True,
                    )

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
                link='/devices/',
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


def serialize_device_summary(device: RegisteredDevice, current_installation_id: str = '') -> dict[str, Any]:
    active_sess = device.sessions.filter(status='active', expires_at__gt=timezone.now()).exists()
    hw_id = get_device_hardware_id(device)
    return {
        'id': device.id,
        'device_uuid': str(device.device_uuid),
        'installation_id': device.installation_id,
        'hardware_id': hw_id,
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
    2) التحقق من عدم وجود حظر إداري DeviceBlock (مباشر أو عبر معرف العتاد الموحد DEV-XXXXXXXX).
    3) التحقق من حد الأجهزة المسموح (دون استبدال صامت).
    4) إنشاء/تحديث بصمة fp_v1 وسجل الانحراف وسجل IP.
    5) إنشاء أو تحديث DeviceSession وتقييم المخاطر.
    """
    valid, clean_id, err = validate_installation_id(installation_id, user=user)
    if not valid:
        return {'allowed': False, 'code': 'INVALID_INSTALLATION_ID', 'error': err}

    traits = normalize_device_info(device_info)
    tamper_signals = traits.get('integrity_signals') or {}
    if request is not None and (
        clean_id.startswith('web-') or traits.get('package_name') == WEB_PACKAGE_NAME
    ):
        existing_wt = tamper_signals.get('web_traits') if isinstance(tamper_signals.get('web_traits'), dict) else {}
        merged_for_spoof = {
            **existing_wt,
            'gpu_renderer': traits.get('gpu_renderer') or existing_wt.get('gpu_renderer', ''),
            'gpu_vendor': traits.get('gpu_vendor') or existing_wt.get('gpu_vendor', ''),
            'navigator_platform': traits.get('web_navigator_platform') or existing_wt.get('navigator_platform', ''),
            'max_touch_points': traits.get('web_max_touch_points') if traits.get('web_max_touch_points') != '' else existing_wt.get('max_touch_points'),
        }
        detected_spoofs = detect_web_fingerprint_spoofing(request, client_traits=merged_for_spoof)
        if detected_spoofs:
            prior_spoofs = list(tamper_signals.get('web_spoof_reasons') or [])
            tamper_signals = {
                **tamper_signals,
                'web_spoof_reasons': list(dict.fromkeys([*prior_spoofs, *detected_spoofs])),
            }
    net_ctx = extract_network_context(request, integrity_signals=tamper_signals)

    existing = (
        RegisteredDevice.objects.select_for_update()
        .filter(user=user, installation_id=clean_id)
        .first()
    )
    canonical_hw_id = compute_canonical_hardware_id(
        traits,
        installation_id=clean_id,
        request=request,
        net_ctx=net_ctx,
        existing_device=existing,
    )
    tamper_signals = {**tamper_signals, 'hardware_id': canonical_hw_id}

    active_block = get_active_device_block(
        clean_id,
        hardware_id=canonical_hw_id,
        request=request,
        net_ctx=net_ctx,
    )
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
            details={
                'block_id': active_block.id,
                'hardware_id': canonical_hw_id,
                'reason': active_block.reason,
            },
        )
        return {
            'allowed': False,
            'code': 'DEVICE_BLOCKED',
            'hardware_id': canonical_hw_id,
            'error': f'هذا الجهاز محظور من استخدام المنصة: {active_block.reason}',
            'block_type': active_block.block_type,
            'expires_at': active_block.expires_at.isoformat() if active_block.expires_at else None,
        }

    if existing and existing.trust_status == DeviceTrustStatus.BLOCKED:
        return {
            'allowed': False,
            'code': 'DEVICE_BLOCKED',
            'hardware_id': canonical_hw_id,
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
    if (
        prev_fp
        and isinstance(prev_fp.normalized_traits, dict)
        and traits.get('package_name') == WEB_PACKAGE_NAME
    ):
        prev_traits = prev_fp.normalized_traits
        # إذا كان الجهاز مُتحققاً مسبقاً كـ iPadOS في وضع سطح المكتب والطلب الحالي خالٍ من client_traits
        if (
            prev_traits.get('cpu_arch') == 'ipados'
            and traits.get('cpu_arch') == 'macos'
            and not traits.get('web_max_touch_points')
            and traits.get('manufacturer') == 'Apple Safari'
        ):
            traits['cpu_arch'] = 'ipados'
            traits['os_name'] = 'Web (iPadOS)'
            traits['model'] = f"{traits.get('manufacturer', 'Apple Safari')} on iPadOS"
            traits['device_name'] = f"متصفح {traits.get('manufacturer', 'Apple Safari')} (iPadOS)"
        for _wkey in (
            'cpu_info',
            'gpu_renderer',
            'gpu_vendor',
            'screen_resolution',
            'web_canvas_hash',
            'web_webgl_hash',
            'web_audio_hash',
            'web_hw_sig',
            'web_max_touch_points',
            'web_color_depth',
            'web_navigator_platform',
        ):
            if not traits.get(_wkey) and prev_traits.get(_wkey):
                traits[_wkey] = prev_traits[_wkey]
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
        existing_signals = device.integrity_signals if isinstance(device.integrity_signals, dict) else {}
        merged_signals = dict(existing_signals)
        merged_signals.update(tamper_signals)
        if 'web_traits' not in tamper_signals and 'web_traits' in existing_signals:
            merged_signals['web_traits'] = existing_signals['web_traits']
        device.integrity_signals = merged_signals
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

    if risk_result['risk_level'] == 'critical' and (
        device.package_name == WEB_PACKAGE_NAME
        and (fp_info.get('core_mismatch') or tamper_signals.get('web_spoof_reasons'))
    ):
        DeviceSession.objects.filter(device=device, status='active').update(
            status='revoked',
            ended_at=now,
            revoked_reason='critical_web_fingerprint_mismatch',
        )
        PlaybackSession.objects.filter(
            user=user,
            device_id=clean_id,
            status='active',
        ).update(status='revoked', revoked_reason='critical_web_fingerprint_mismatch', view_window_expires_at=now)
        from .video_security import clear_watch_window
        clear_watch_window(user, now=now)
        return {
            'allowed': False,
            'code': 'WEB_FINGERPRINT_MISMATCH',
            'error': 'تم رصد اختلاف صارم في بصمة المتصفح أو محاولة تلاعب بالبيئة، وتم إيقاف الجلسة لحماية الحساب.',
            'device': serialize_device_summary(device, clean_id),
            'risk': risk_result,
        }

    return {
        'allowed': True,
        'is_new_device': is_new_device,
        'device_limit': limit,
        'hardware_id': canonical_hw_id,
        'device': serialize_device_summary(device, clean_id),
        'device_obj': device,
        'session_obj': session,
        'session_uuid': str(session.session_uuid),
        'fingerprint': fp_info,
        'risk': risk_result,
    }


def check_device_allowed(user, installation_id: str, request=None) -> tuple[bool, str | None, str | None]:
    """
    فحص صارم قبل منح تصريح التشغيل المحمي أو الموارد الحساسة:
    يتحقق من الحظر الإداري، إلغاء تفويض الجهاز، أو التقييد المؤقت، وحد الأجهزة.
    """
    clean_id = str(installation_id or '').strip()
    if not clean_id and request is None:
        return True, None, None

    block = get_active_device_block(clean_id, request=request)
    if block:
        return False, 'DEVICE_BLOCKED', f'هذا الجهاز محظور: {block.reason}'

    device = RegisteredDevice.objects.filter(user=user, installation_id=clean_id).first() if clean_id else None
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


def _find_all_devices_for_hardware(
    *,
    hardware_id: str = '',
    installation_id: str = '',
    primary_device: RegisteredDevice | None = None,
) -> list[RegisteredDevice]:
    """يجمع كافة سجلات الأجهزة (تطبيق أندرويد + متصفح ويب + حسابات متعددة) المرتبطة بنفس الجهاز المادي."""
    matched: list[RegisteredDevice] = []
    seen_pks: set[int] = set()

    def _add(dev: RegisteredDevice | None):
        if dev is not None and dev.pk not in seen_pks:
            seen_pks.add(dev.pk)
            matched.append(dev)

    _add(primary_device)
    clean_inst = str(installation_id or (primary_device.installation_id if primary_device else '')).strip()
    clean_hw = str(hardware_id or '').strip()
    if not clean_hw and primary_device is not None:
        clean_hw = get_device_hardware_id(primary_device)

    if clean_inst:
        for d in RegisteredDevice.objects.filter(installation_id=clean_inst):
            _add(d)
            if not clean_hw:
                clean_hw = get_device_hardware_id(d)

    if clean_hw:
        for d in RegisteredDevice.objects.only(
            'id', 'user_id', 'installation_id', 'device_name', 'os_name', 'cpu_arch',
            'model', 'manufacturer', 'gpu_renderer', 'package_name',
            'last_ip', 'last_active_at', 'integrity_signals', 'trust_status',
            'is_active', 'revoked_at', 'revoked_reason', 'current_fingerprint',
        ):
            if get_device_hardware_id(d) == clean_hw:
                _add(d)

    return matched


@transaction.atomic
def block_device_admin(
    *,
    device: RegisteredDevice | None = None,
    installation_id: str = '',
    hardware_id: str = '',
    admin_user,
    block_type: str = 'permanent',
    reason: str = 'Administrative security block',
    duration_hours: int = 24,
    request=None,
) -> DeviceBlock:
    """حظر الجهاز المادي بالكامل (تطبيق + متصفح + جميع الحسابات المرتبطة) وإبطال كافة جلساته فوراً."""
    now = timezone.now()
    clean_inst = str(installation_id or (device.installation_id if device else '')).strip()
    resolved_hw = str(hardware_id or '').strip()
    if not resolved_hw and device is not None:
        resolved_hw = get_device_hardware_id(device)

    linked_devices = _find_all_devices_for_hardware(
        hardware_id=resolved_hw,
        installation_id=clean_inst,
        primary_device=device,
    )
    if device is None and linked_devices:
        device = linked_devices[0]
    if not resolved_hw and linked_devices:
        resolved_hw = get_device_hardware_id(linked_devices[0])
    if not clean_inst and linked_devices:
        clean_inst = linked_devices[0].installation_id
    if not clean_inst and resolved_hw:
        clean_inst = resolved_hw

    target_user = device.user if device else None
    expires_at = now + timedelta(hours=max(int(duration_hours), 1)) if block_type == 'temporary' else None
    norm_block_type = 'temporary' if block_type == 'temporary' else 'permanent'

    block = DeviceBlock.objects.create(
        device=device,
        user=target_user,
        installation_id=clean_inst,
        fingerprint_hash=resolved_hw or (device.current_fingerprint if device else ''),
        block_type=norm_block_type,
        reason=reason[:255],
        is_active=True,
        blocked_by=admin_user,
        expires_at=expires_at,
    )

    all_inst_ids = {clean_inst} if clean_inst else set()
    for d in linked_devices:
        if d.installation_id:
            all_inst_ids.add(d.installation_id)

    if all_inst_ids:
        RegisteredDevice.objects.filter(installation_id__in=all_inst_ids).update(
            trust_status=DeviceTrustStatus.BLOCKED,
            is_active=False,
            revoked_at=now,
            revoked_reason=reason[:255],
        )
        DeviceSession.objects.filter(installation_id__in=all_inst_ids, status='active').update(
            status='revoked',
            ended_at=now,
            revoked_reason='device_blocked_by_admin',
        )
        PlaybackSession.objects.filter(device_id__in=all_inst_ids, status='active').update(
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
        details={
            'block_id': block.id,
            'hardware_id': resolved_hw,
            'linked_installation_ids': sorted(all_inst_ids),
            'reason': reason,
            'admin_id': getattr(admin_user, 'id', None),
        },
    )
    return block


@transaction.atomic
def unblock_device_admin(
    *,
    device: RegisteredDevice | None = None,
    installation_id: str = '',
    hardware_id: str = '',
    admin_user,
    reason: str = 'Unblocked by administrator',
    request=None,
) -> int:
    """فك الحظر الإداري عن الجهاز المادي بالكامل (تطبيق + متصفح) واستعادة إمكانية استخدامه."""
    now = timezone.now()
    clean_inst = str(installation_id or (device.installation_id if device else '')).strip()
    resolved_hw = str(hardware_id or '').strip()
    if not resolved_hw and device is not None:
        resolved_hw = get_device_hardware_id(device)

    linked_devices = _find_all_devices_for_hardware(
        hardware_id=resolved_hw,
        installation_id=clean_inst,
        primary_device=device,
    )
    if not resolved_hw and linked_devices:
        resolved_hw = get_device_hardware_id(linked_devices[0])
    all_inst_ids = {clean_inst} if clean_inst else set()
    for d in linked_devices:
        if d.installation_id:
            all_inst_ids.add(d.installation_id)

    blk_q = Q()
    if all_inst_ids:
        blk_q |= Q(installation_id__in=all_inst_ids)
    if resolved_hw:
        blk_q |= Q(fingerprint_hash=resolved_hw) | Q(installation_id=resolved_hw)

    updated = 0
    if blk_q:
        updated = DeviceBlock.objects.filter(blk_q, is_active=True).update(
            is_active=False,
            unblocked_at=now,
            unblocked_by=admin_user,
            unblock_reason=reason[:255],
        )

    if all_inst_ids:
        RegisteredDevice.objects.filter(
            installation_id__in=all_inst_ids,
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
        details={
            'unblocked_records': updated,
            'hardware_id': resolved_hw,
            'linked_installation_ids': sorted(all_inst_ids),
            'reason': reason,
            'admin_id': getattr(admin_user, 'id', None),
        },
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


_DESKTOP_OR_EMULATED_GPU_TOKENS = (
    'direct3d',
    'd3d11',
    'd3d9',
    'nvidia',
    'geforce',
    'quadro',
    'rtx ',
    'gtx ',
    'radeon',
    'amd ',
    'amd/',
    'intel(r)',
    'intel iris',
    'uhd graphics',
    'hd graphics',
    'swiftshader',
    'mesa',
    'llvmpipe',
    'softpipe',
    'virgl',
    'vmware',
    'virtualbox',
    'google inc.',
    'angle (',
    'microsoft basic',
)

_BROWSER_UA_MARKERS = (
    'mozilla/',
    'applewebkit/',
    'chrome/',
    'safari/',
    'firefox/',
    'edg/',
    'opr/',
    'opera/',
    'crios/',
    'fxios/',
    'edgios/',
)


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


WEB_IOS_ONLY_ERROR = (
    'عرض وتشغيل المحاضرات عبر المتصفح متاح فقط لأجهزة iPhone و iPad (ومحظور على أجهزة Mac والكمبيوتر وأندرويد) '
    'لحماية روابط المحاضرات. يرجى استخدام تطبيق تعلّم أو متصفح iPhone/iPad رسمي.'
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
        from .video_security import clear_watch_window
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
    from .video_security import build_watermark_payload, create_or_rotate_playback_session

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


def _platform_tag_for_device(device: RegisteredDevice) -> str:
    pkg = str(device.package_name or '').strip()
    os_low = str(device.os_name or '').lower()
    if pkg == WEB_PACKAGE_NAME or os_low.startswith('web'):
        return 'web_browser'
    if 'ios' in os_low:
        return 'ios_app'
    return 'android_app'


def build_unified_devices_registry(
    *,
    search_query: str = '',
    trust_filter: str = '',
    limit: int = 100,
) -> list[dict[str, Any]]:
    """
    يبني قائمة موحّدة ومُزالة التكرار للأجهزة المادية (جهاز واحد لكل هاتف/كمبيوتر فعلي)،
    مع دمج الحسابات المتعددة وتطبيق الأندرويد والمتصفح تحت معرّف DEV-XXXXXXXX واحد.
    """
    q = str(search_query or '').strip().lower()
    tf = str(trust_filter or '').strip().lower()

    active_block_insts: set[str] = set()
    active_block_hw_ids: set[str] = set()
    block_reasons_by_key: dict[str, str] = {}
    for blk in DeviceBlock.objects.filter(is_active=True).order_by('-created_at'):
        if blk.installation_id:
            active_block_insts.add(blk.installation_id)
            block_reasons_by_key.setdefault(blk.installation_id, blk.reason)
        if blk.fingerprint_hash:
            active_block_hw_ids.add(blk.fingerprint_hash)
            block_reasons_by_key.setdefault(blk.fingerprint_hash, blk.reason)

    devices_qs = (
        RegisteredDevice.objects
        .select_related('user')
        .order_by('-last_active_at')[:500]
    )

    groups: dict[str, dict[str, Any]] = {}
    for dev in devices_qs:
        hw_id = get_device_hardware_id(dev)
        plat = _platform_tag_for_device(dev)
        entry = groups.get(hw_id)

        user_name = (dev.user.get_full_name() or '').strip() or dev.user.username or dev.user.email
        user_info = {
            'user_id': dev.user_id,
            'full_name': user_name,
            'username': dev.user.username,
            'email': dev.user.email,
            'role': getattr(dev.user, 'role', 'student'),
            'is_banned': bool(getattr(dev.user, 'is_banned', False)),
        }

        if entry is None:
            native_label = f"{dev.manufacturer} {dev.model}".strip()
            display_name = native_label if plat != 'web_browser' and native_label else (dev.device_name or dev.model or 'Unknown Device')
            entry = {
                'hardware_id': hw_id,
                'primary_device_id': dev.id,
                'primary_installation_id': dev.installation_id,
                'installation_ids': [],
                'device_ids': [],
                'display_name': display_name,
                'manufacturer': dev.manufacturer,
                'model': dev.model,
                'os_summary': f"{dev.os_name} {dev.android_version}".strip(),
                'platforms': [],
                'linked_accounts': [],
                '_seen_user_ids': set(),
                'is_blocked': False,
                'block_reason': '',
                'trust_status': dev.trust_status,
                'max_risk_score': int(dev.risk_score or 0),
                'last_ip': dev.last_ip or '',
                'last_country': dev.last_country or '',
                'last_active_at': dev.last_active_at.isoformat() if dev.last_active_at else None,
            }
            groups[hw_id] = entry

        # تفضيل الاسم الأصلي للهاتف (مثل Samsung SM-A546E) على اسم المتصفح عند اجتماع التطبيق والويب
        if plat != 'web_browser':
            native_label = f"{dev.manufacturer} {dev.model}".strip()
            if native_label:
                entry['display_name'] = native_label
                entry['os_summary'] = f"{dev.os_name} {dev.android_version}".strip()
                entry['primary_device_id'] = dev.id
                entry['primary_installation_id'] = dev.installation_id

        if dev.installation_id and dev.installation_id not in entry['installation_ids']:
            entry['installation_ids'].append(dev.installation_id)
        if dev.id not in entry['device_ids']:
            entry['device_ids'].append(dev.id)
        if plat not in entry['platforms']:
            entry['platforms'].append(plat)
        if dev.user_id not in entry['_seen_user_ids']:
            entry['_seen_user_ids'].add(dev.user_id)
            entry['linked_accounts'].append(user_info)

        if (
            dev.trust_status == DeviceTrustStatus.BLOCKED
            or dev.installation_id in active_block_insts
            or hw_id in active_block_hw_ids
        ):
            entry['is_blocked'] = True
            entry['trust_status'] = DeviceTrustStatus.BLOCKED
            if not entry['block_reason']:
                entry['block_reason'] = (
                    block_reasons_by_key.get(hw_id)
                    or block_reasons_by_key.get(dev.installation_id)
                    or dev.revoked_reason
                    or 'محظور إدارياً'
                )
        elif not entry['is_blocked']:
            rank = {'restricted': 3, 'suspicious': 2, 'pending': 1, 'trusted': 0, 'revoked': 0}
            if rank.get(dev.trust_status, 0) > rank.get(entry['trust_status'], 0):
                entry['trust_status'] = dev.trust_status

        entry['max_risk_score'] = max(entry['max_risk_score'], int(dev.risk_score or 0))
        if not entry['last_ip'] and dev.last_ip:
            entry['last_ip'] = dev.last_ip

    policy = SecurityPolicyConfig.load()
    result: list[dict[str, Any]] = []
    for entry in groups.values():
        entry.pop('_seen_user_ids', None)
        entry['accounts_count'] = len(entry['linked_accounts'])
        entry['is_multi_account'] = entry['accounts_count'] > 1
        entry['is_maintenance_approved'] = policy.is_device_maintenance_approved(
            entry['hardware_id'],
            *entry['installation_ids'],
        )
        entry['platform_labels'] = [
            'تطبيق أندرويد' if p == 'android_app' else ('متصفح ويب' if p == 'web_browser' else 'تطبيق iOS')
            for p in entry['platforms']
        ]

        if q:
            haystack = ' '.join(
                [
                    entry['hardware_id'],
                    entry['display_name'],
                    entry['os_summary'],
                    entry['last_ip'],
                    *entry['installation_ids'],
                    *[f"{a['full_name']} {a['username']} {a['email']}" for a in entry['linked_accounts']],
                ]
            ).lower()
            if q not in haystack:
                continue

        if tf == 'blocked' and not entry['is_blocked']:
            continue
        elif tf == 'multi_account' and not entry['is_multi_account']:
            continue
        elif tf == 'maintenance_approved' and not entry['is_maintenance_approved']:
            continue
        elif tf and tf not in ('blocked', 'multi_account', 'maintenance_approved', 'all') and entry['trust_status'] != tf:
            continue

        result.append(entry)
        if len(result) >= max(int(limit), 1):
            break

    return result


def is_maintenance_admin_approved_device(
    request=None,
    *,
    hardware_id: str = '',
    installation_id: str = '',
    policy: SecurityPolicyConfig | None = None,
) -> bool:
    """
    يتحقق من اعتماد الجهاز من لوحة الإدارة للسماح بظهور زر (دخول الإدارة) في وضع الصيانة.
    """
    pol = policy or SecurityPolicyConfig.load()
    approved_set = {x.upper() for x in pol.maintenance_approved_devices}
    if not approved_set:
        return False

    identifiers: list[str] = []
    if hardware_id:
        identifiers.append(hardware_id)
    if installation_id:
        identifiers.append(installation_id)

    if request is not None:
        meta = getattr(request, 'META', {}) or {}
        for h in ('HTTP_X_HARDWARE_ID', 'HTTP_X_DEVICE_ID', 'HTTP_X_INSTALLATION_ID'):
            val = str(meta.get(h) or '').strip()
            if val:
                identifiers.append(val)
        web_or_dev = _extract_web_or_device_id_from_request(request)
        if web_or_dev:
            identifiers.append(web_or_dev)

    if pol.is_device_maintenance_approved(*identifiers):
        return True

    # إذا كان لدينا installation_id أو hardware_id، افحص أيضاً الأجهزة المرتبطة بنفس الجهاز المادي
    clean_hw = str(hardware_id or '').strip()
    clean_inst = str(installation_id or '').strip()
    if clean_inst and not clean_hw:
        dev = RegisteredDevice.objects.filter(installation_id=clean_inst).first()
        if dev is not None:
            clean_hw = get_device_hardware_id(dev)
            if pol.is_device_maintenance_approved(clean_hw):
                return True

    if clean_hw:
        for d in _find_all_devices_for_hardware(hardware_id=clean_hw, installation_id=clean_inst):
            if pol.is_device_maintenance_approved(d.installation_id, get_device_hardware_id(d)):
                return True

    return False


def evaluate_boot_security_gate(
    request,
    *,
    client_signals: dict[str, Any] | None = None,
    user=None,
) -> dict[str, Any]:
    """
    بوابة التحقق الأولى قبل عبور شاشة التحميل للتطبيق والموقع:
    تمنع الدخول نهائياً عند:
    1) حظر الجهاز (تطبيق + متصفح عبر DEV-XXXXXXXX أو installation_id)
    2) تشغيل VPN أو Proxy على الشبكة
    3) فتح إعدادات المطور (Developer Options / ADB)
    4) توجيه البورتات أو DNS غير طبيعي أو شهادة MITM
    5) وضع الصيانة العام (لغير الإدارة)
    """
    from core.models import SiteSetting

    sig = client_signals if isinstance(client_signals, dict) else {}
    meta = getattr(request, 'META', {}) if request is not None else {}

    def _hdr_bool(hdr_name: str, key: str) -> bool:
        if key in sig:
            return bool(sig.get(key))
        return str(meta.get(hdr_name) or '').strip().lower() in ('1', 'true', 'yes', 'on')

    merged_sig = {
        'vpn_interface_active': _hdr_bool('HTTP_X_VPN_ACTIVE', 'vpn_interface_active'),
        'developer_options_enabled': _hdr_bool('HTTP_X_DEV_OPTIONS', 'developer_options_enabled'),
        'adb_enabled': _hdr_bool('HTTP_X_ADB_ENABLED', 'adb_enabled'),
        'proxy_detected': _hdr_bool('HTTP_X_PROXY_DETECTED', 'proxy_detected'),
        'port_forwarding_detected': _hdr_bool('HTTP_X_PORT_FORWARDING', 'port_forwarding_detected'),
        'abnormal_dns_detected': _hdr_bool('HTTP_X_ABNORMAL_DNS', 'abnormal_dns_detected'),
    }

    net_ctx = extract_network_context(request, integrity_signals=merged_sig)
    inst_id = _extract_web_or_device_id_from_request(request)
    if not inst_id and is_web_client_request(request) and request is not None:
        inst_id = get_or_create_web_installation_id(request)

    hw_id = str(meta.get('HTTP_X_HARDWARE_ID') or '').strip()
    if not hw_id and inst_id:
        dev = RegisteredDevice.objects.filter(installation_id=inst_id).first()
        if dev is not None:
            hw_id = get_device_hardware_id(dev)
    if not hw_id and request is not None:
        ua = str(meta.get('HTTP_USER_AGENT') or '')
        parsed = parse_web_user_agent(ua) if ua else {'os_label': ''}
        is_native_android = 'dart/' in ua.lower() or str(meta.get('HTTP_X_CLIENT_PLATFORM') or '').lower() == 'android'
        req_traits = {
            'os_name': 'Android' if is_native_android else f"Web ({parsed.get('os_label', '')})",
            'model': str(meta.get('HTTP_X_DEVICE_MODEL') or '').strip(),
            'gpu_renderer': str(meta.get('HTTP_X_DEVICE_GPU') or '').strip(),
            'package_name': '' if is_native_android else WEB_PACKAGE_NAME,
        }
        hw_id = compute_canonical_hardware_id(
            req_traits,
            installation_id=inst_id,
            request=request,
            net_ctx=net_ctx,
        )

    policy = SecurityPolicyConfig.load()
    site_settings = SiteSetting.load()
    can_admin_login = is_maintenance_admin_approved_device(
        request,
        hardware_id=hw_id,
        installation_id=inst_id,
        policy=policy,
    )

    # 1) فحص حظر الجهاز (شامل عبر التطبيق والمتصفح)
    blk = get_active_device_block(
        inst_id,
        hardware_id=hw_id,
        request=request,
        net_ctx=net_ctx,
    )
    if blk:
        return {
            'boot_allowed': False,
            'code': 'DEVICE_BLOCKED',
            'title': 'هذا الجهاز محظور من استخدام المنصة',
            'message': f'تم إيقاف هذا الجهاز عن استخدام التطبيق والموقع من قِبل الإدارة: {blk.reason}',
            'hardware_id': blk.fingerprint_hash if str(blk.fingerprint_hash).startswith('DEV-') else hw_id,
            'is_maintenance_mode': bool(site_settings.is_maintenance_mode),
            'can_admin_login': False,
        }

    # 2) فحص VPN / Proxy IP
    if policy.block_vpn_connections and (merged_sig['vpn_interface_active'] or net_ctx.get('is_vpn_or_proxy')):
        return {
            'boot_allowed': False,
            'code': 'VPN_DETECTED',
            'title': 'تم رصد اتصال VPN نشط',
            'message': 'لا يُسمح بفتح التطبيق أو الموقع أثناء تشغيل الـ VPN. يرجى إيقاف الـ VPN تماماً ثم الضغط على إعادة المحاولة.',
            'hardware_id': hw_id,
            'is_maintenance_mode': bool(site_settings.is_maintenance_mode),
            'can_admin_login': False,
        }

    # 3) فحص خيارات المطور وتصحيح USB (ADB)
    if policy.block_developer_options and (merged_sig['developer_options_enabled'] or merged_sig['adb_enabled']):
        return {
            'boot_allowed': False,
            'code': 'DEV_OPTIONS_ENABLED',
            'title': 'إعدادات المطور مفتوحة',
            'message': 'لحماية المحتوى، لا يعمل التطبيق أثناء تفعيل خيارات المطور (Developer Options) أو تصحيح USB. أغلقها من إعدادات الجهاز ثم أعد المحاولة.',
            'hardware_id': hw_id,
            'is_maintenance_mode': bool(site_settings.is_maintenance_mode),
            'can_admin_login': False,
        }

    # 4) فحص توجيه البورتات أو DNS غير الطبيعي أو البروكسي المحلي
    if policy.block_abnormal_dns_or_ports and (
        merged_sig['proxy_detected']
        or merged_sig['port_forwarding_detected']
        or merged_sig['abnormal_dns_detected']
    ):
        return {
            'boot_allowed': False,
            'code': 'ABNORMAL_NETWORK_OR_DNS',
            'title': 'تم رصد توجيه شبكة أو DNS غير طبيعي',
            'message': 'تم اكتشاف تحويل لبورتات الشبكة أو بروكسي محلي أو خادم DNS غير قياسي. يرجى إعادة ضبط الشبكة والـ DNS على الوضع التلقائي وإغلاق أي أداة فحص.',
            'hardware_id': hw_id,
            'is_maintenance_mode': bool(site_settings.is_maintenance_mode),
            'can_admin_login': False,
        }

    # 5) فحص وضع الصيانة العام
    is_admin = bool(
        user is not None
        and getattr(user, 'is_authenticated', False)
        and (getattr(user, 'is_superuser', False) or getattr(user, 'role', '') == 'admin')
    )
    if site_settings.is_maintenance_mode and not is_admin:
        return {
            'boot_allowed': False,
            'code': 'MAINTENANCE_MODE',
            'title': 'المنصة في وضع الصيانة حالياً',
            'message': 'نقوم حالياً ببعض التحسينات والصيانة لخدمتكم بشكل أفضل. سنعود للعمل خلال وقت قصير.',
            'hardware_id': hw_id,
            'is_maintenance_mode': True,
            'can_admin_login': can_admin_login,
        }

    return {
        'boot_allowed': True,
        'code': 'OK',
        'title': '',
        'message': '',
        'hardware_id': hw_id,
        'is_maintenance_mode': bool(site_settings.is_maintenance_mode),
        'can_admin_login': can_admin_login,
    }


"""api_v1.services.device_security.fingerprint
Extracted from api_v1/device_security_service.py.
"""
from __future__ import annotations

import hashlib
import hmac
import os
import re
from typing import Any
from django.conf import settings
from api_v1.models import DeviceFingerprint

from api_v1.services.device_security.constants import (
    BENIGN_DRIFT_FIELDS,
    CORE_FINGERPRINT_FIELDS,
    FINGERPRINT_ALGORITHM_VERSION,
    SUPPORTING_FINGERPRINT_FIELDS,
    WEB_PACKAGE_NAME,
    WEB_STRICT_CORE_FIELDS,
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

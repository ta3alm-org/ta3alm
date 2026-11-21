"""api_v1.services.device_security.hardware
Extracted from api_v1/device_security_service.py.
"""
from __future__ import annotations

import hashlib
import hmac
import re
from datetime import timedelta
from typing import Any
from django.utils import timezone
from api_v1.models import RegisteredDevice

from api_v1.services.device_security.constants import WEB_PACKAGE_NAME
from api_v1.services.device_security.fingerprint import _fingerprint_secret
from api_v1.services.device_security.network import get_server_observed_ip


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

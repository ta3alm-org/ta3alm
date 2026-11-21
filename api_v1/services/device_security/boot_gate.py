"""api_v1.services.device_security.boot_gate
Extracted from api_v1/device_security_service.py.
"""
from __future__ import annotations

from typing import Any
from api_v1.models import (
    RegisteredDevice,
    SecurityPolicyConfig,
)

from api_v1.services.device_security.blocks import get_active_device_block
from api_v1.services.device_security.constants import WEB_PACKAGE_NAME
from api_v1.services.device_security.hardware import (
    _find_all_devices_for_hardware,
    compute_canonical_hardware_id,
    get_device_hardware_id,
)
from api_v1.services.device_security.network import extract_network_context
from api_v1.services.device_security.web import (
    _extract_web_or_device_id_from_request,
    get_or_create_web_installation_id,
    is_web_client_request,
    parse_web_user_agent,
)


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

    if request is not None and client_signals is None:
        cached_gate = getattr(request, '_cached_boot_security_gate', None)
        if cached_gate is not None:
            return cached_gate

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

    result = {
        'boot_allowed': True,
        'code': 'OK',
        'title': '',
        'message': '',
        'hardware_id': hw_id,
        'is_maintenance_mode': bool(site_settings.is_maintenance_mode),
        'can_admin_login': can_admin_login,
    }
    if request is not None and client_signals is None:
        request._cached_boot_security_gate = result
    return result

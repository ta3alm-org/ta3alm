"""api_v1.services.device_security.network
Extracted from api_v1/device_security_service.py.
"""
from __future__ import annotations

import ipaddress
from datetime import timedelta
from typing import Any
from django.utils import timezone
from api_v1.models import RegisteredDevice

from api_v1.services.device_security.constants import (
    MAX_IP_HISTORY_ENTRIES,
    _VPN_ISP_KEYWORDS,
)


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

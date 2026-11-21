"""api_v1.selectors.device_selectors
Extracted from api_v1/device_security_service.py.
"""
from __future__ import annotations

from typing import Any
from django.conf import settings
from api_v1.models import (
    DeviceBlock,
    DeviceTrustStatus,
    RegisteredDevice,
    SecurityPolicyConfig,
)

from api_v1.services.device_security.constants import WEB_PACKAGE_NAME
from api_v1.services.device_security.hardware import get_device_hardware_id


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

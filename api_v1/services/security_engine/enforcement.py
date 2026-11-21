"""api_v1.services.security_engine.enforcement
Extracted from api_v1/security_engine.py.
"""
from __future__ import annotations

from typing import Any
from django.db import transaction
from django.utils import timezone
from rest_framework.authtoken.models import Token
from dashboard_admin.models import AuditLog
from api_v1.device_security_service import (
    block_device_admin,
    record_security_event,
    unblock_device_admin,
)
from api_v1.models import (
    DeviceBlock,
    DeviceSession,
    DeviceTrustStatus,
    PlaybackSession,
    RegisteredDevice,
    UserSecurityProfile,
)

from api_v1.services.security_engine.behavioral import is_protected_admin_user


@transaction.atomic
def enforce_security_ban(
    *,
    user=None,
    device: RegisteredDevice | None = None,
    installation_id: str = '',
    mode: str = 'device_and_user',
    reason: str = 'تم فرض حظر أمني تلقائي/إداري لحماية المنصة.',
    block_type: str = 'permanent',
    duration_hours: int = 24,
    actor=None,
    request=None,
) -> dict[str, Any]:
    """
    ينفّذ الحظر على:
    - device_only: حظر الجهاز المحدد (أو أجهزة المستخدم المرتبطة) وإبطال جلساته دون حظر الحساب.
    - user_only: حظر الحساب وإبطال جلساته دون وضع DeviceBlock دائم على الجهاز.
    - device_and_user: حظر الحساب والجهاز معاً وإلغاء كافة التوكنات وجلسات التشغيل.
    """
    clean_mode = mode if mode in ('device_only', 'user_only', 'device_and_user') else 'device_and_user'
    clean_inst = str(installation_id or (device.installation_id if device else '') or '').strip()
    now = timezone.now()

    if user is None and device is not None:
        user = device.user

    if is_protected_admin_user(user) and clean_mode in ('user_only', 'device_and_user'):
        # حماية حسابات الإدارة العليا من الحظر الآلي العرضي
        return {
            'enforced': False,
            'mode': 'protected_admin_skip',
            'blocked_devices': 0,
            'user_banned': False,
        }

    blocked_devices = 0
    if clean_mode in ('device_only', 'device_and_user'):
        target_devices: list[RegisteredDevice] = []
        if device is not None:
            target_devices.append(device)
        elif clean_inst:
            matched = RegisteredDevice.objects.filter(installation_id=clean_inst).first()
            if matched:
                target_devices.append(matched)
            else:
                block_device_admin(
                    device=None,
                    installation_id=clean_inst,
                    hardware_id=clean_inst if clean_inst.startswith('DEV-') else '',
                    admin_user=actor,
                    block_type=block_type,
                    reason=reason,
                    duration_hours=duration_hours,
                    request=request,
                )
                blocked_devices += 1
        elif user is not None:
            target_devices.extend(list(RegisteredDevice.objects.filter(user=user)))

        seen_insts: set[str] = set()
        for dev in target_devices:
            if dev.installation_id in seen_insts:
                continue
            seen_insts.add(dev.installation_id)
            block_device_admin(
                device=dev,
                installation_id=dev.installation_id,
                admin_user=actor,
                block_type=block_type,
                reason=reason,
                duration_hours=duration_hours,
                request=request,
            )
            blocked_devices += 1

    user_banned = False
    if clean_mode in ('user_only', 'device_and_user') and user is not None and not is_protected_admin_user(user):
        user.is_banned = True
        user.save(update_fields=['is_banned'])
        user_banned = True

        DeviceSession.objects.filter(user=user, status='active').update(
            status='revoked',
            ended_at=now,
            revoked_reason=f'security_ban:{clean_mode}',
        )
        PlaybackSession.objects.filter(user=user, status='active').update(
            status='revoked',
            revoked_reason=f'security_ban:{clean_mode}',
            view_window_expires_at=now,
        )
        Token.objects.filter(user=user).delete()

    if user is not None:
        sec_prof, _ = UserSecurityProfile.objects.get_or_create(user=user)
        sec_prof.auto_ban_mode = clean_mode
        sec_prof.ban_reason = reason[:255]
        sec_prof.behavior_risk_score = max(sec_prof.behavior_risk_score, 90)
        sec_prof.behavior_risk_level = 'critical'
        sec_prof.save(
            update_fields=[
                'auto_ban_mode',
                'ban_reason',
                'behavior_risk_score',
                'behavior_risk_level',
                'analyzed_at',
            ]
        )

    record_security_event(
        event_type=f'security_ban_{clean_mode}',
        severity='critical',
        risk_score=95,
        user=user,
        device=device,
        installation_id=clean_inst,
        request=request,
        action_taken=clean_mode,
        details={
            'mode': clean_mode,
            'reason': reason,
            'blocked_devices': blocked_devices,
            'user_banned': user_banned,
            'actor_id': getattr(actor, 'id', None),
        },
    )

    if request is not None:
        AuditLog.log(
            request,
            AuditLog.ACTION_BAN if user_banned else AuditLog.ACTION_BLOCK_DEVICE,
            target_label=(
                (user.email or user.username) if user else clean_inst or 'unknown'
            ),
            target_id=getattr(user, 'id', None),
            details={'mode': clean_mode, 'installation_id': clean_inst, 'reason': reason},
        )

    return {
        'enforced': True,
        'mode': clean_mode,
        'blocked_devices': blocked_devices,
        'user_banned': user_banned,
    }


@transaction.atomic
def unban_user_and_devices(
    *,
    user=None,
    installation_id: str = '',
    mode: str = 'both',
    actor=None,
    reason: str = 'رفع الحظر بواسطة مسؤول المنصة',
    request=None,
) -> dict[str, Any]:
    """فك الحظر عن الحساب، الجهاز، أو كليهما مع إعادة ضبط مؤشرات التصعيد."""
    clean_mode = mode if mode in ('user_only', 'device_only', 'both') else 'both'
    user_unbanned = False
    devices_unblocked = 0

    if clean_mode in ('user_only', 'both') and user is not None:
        if user.is_banned:
            user.is_banned = False
            user.save(update_fields=['is_banned'])
        user_unbanned = True
        sec_prof, _ = UserSecurityProfile.objects.get_or_create(user=user)
        sec_prof.auto_ban_mode = 'none'
        sec_prof.ban_reason = ''
        sec_prof.proxy_tamper_strikes = 0
        sec_prof.total_failed_logins = 0
        sec_prof.behavior_risk_score = min(sec_prof.behavior_risk_score, 20)
        sec_prof.behavior_risk_level = 'low'
        sec_prof.save(
            update_fields=[
                'auto_ban_mode',
                'ban_reason',
                'proxy_tamper_strikes',
                'total_failed_logins',
                'behavior_risk_score',
                'behavior_risk_level',
                'analyzed_at',
            ]
        )

    if clean_mode in ('device_only', 'both'):
        if installation_id:
            dev = RegisteredDevice.objects.filter(installation_id=installation_id).first()
            devices_unblocked += unblock_device_admin(
                device=dev,
                installation_id=installation_id,
                hardware_id=installation_id if installation_id.startswith('DEV-') else '',
                admin_user=actor,
                reason=reason,
                request=request,
            )
        elif user is not None:
            for dev in RegisteredDevice.objects.filter(user=user):
                if dev.trust_status == DeviceTrustStatus.BLOCKED or DeviceBlock.objects.filter(
                    installation_id=dev.installation_id, is_active=True
                ).exists():
                    devices_unblocked += unblock_device_admin(
                        device=dev,
                        installation_id=dev.installation_id,
                        admin_user=actor,
                        reason=reason,
                        request=request,
                    )

    if request is not None:
        AuditLog.log(
            request,
            AuditLog.ACTION_UNBAN,
            target_label=(user.email or user.username) if user else installation_id,
            target_id=getattr(user, 'id', None),
            details={'mode': clean_mode, 'devices_unblocked': devices_unblocked, 'reason': reason},
        )

    return {
        'user_unbanned': user_unbanned,
        'devices_unblocked': devices_unblocked,
    }

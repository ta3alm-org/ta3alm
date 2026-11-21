"""api_v1.services.device_security.blocks
Extracted from api_v1/device_security_service.py.
"""
from __future__ import annotations

from datetime import timedelta
from typing import Any
from django.db import transaction
from django.db.models import Q
from django.utils import timezone
from api_v1.models import (
    DeviceBlock,
    DeviceSession,
    DeviceTrustStatus,
    PlaybackSession,
    RegisteredDevice,
)

from api_v1.services.device_security.constants import WEB_PACKAGE_NAME
from api_v1.services.device_security.events import record_security_event
from api_v1.services.device_security.hardware import (
    _clean_hw_token,
    _extract_device_hw_profile,
    _find_all_devices_for_hardware,
    _find_matching_canonical_hardware_id,
    _resolve_os_family,
    extract_android_model_from_ua,
    get_device_hardware_id,
)
from api_v1.services.device_security.network import extract_network_context
from api_v1.services.device_security.web import parse_web_user_agent


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

    # مسار فائق السرعة: إذا لم يوجد أي حظر نشط في النظام حالياً نخرج فوراً بدون أي مسح للجداول
    has_any_blocks = (
        DeviceBlock.objects.filter(is_active=True).exists()
        or RegisteredDevice.objects.filter(trust_status=DeviceTrustStatus.BLOCKED).exists()
    )
    if not has_any_blocks:
        return None

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

"""api_v1.services.device_security.registration
Extracted from api_v1/device_security_service.py.
"""
from __future__ import annotations

from datetime import timedelta
from typing import Any
from django.db import transaction
from django.utils import timezone
from api_v1.models import (
    DeviceFingerprint,
    DeviceSession,
    DeviceTrustStatus,
    PlaybackSession,
    RegisteredDevice,
    SecurityPolicyConfig,
)

from api_v1.services.device_security.blocks import get_active_device_block
from api_v1.services.device_security.constants import WEB_PACKAGE_NAME
from api_v1.services.device_security.events import (
    record_device_activity,
    record_security_event,
)
from api_v1.services.device_security.fingerprint import (
    generate_versioned_fingerprint,
    normalize_device_info,
    validate_installation_id,
)
from api_v1.services.device_security.hardware import (
    compute_canonical_hardware_id,
    get_device_hardware_id,
)
from api_v1.services.device_security.network import (
    analyze_ip_transition,
    extract_network_context,
)
from api_v1.services.device_security.risk import evaluate_and_apply_risk
from api_v1.services.device_security.web import detect_web_fingerprint_spoofing


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
    from api_v1.selectors.device_selectors import get_user_device_limit
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
        from api_v1.video_security import clear_watch_window
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
    from api_v1.selectors.device_selectors import get_user_device_limit
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

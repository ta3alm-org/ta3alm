"""core.signals.devices_security
Extracted from core/signals.py.
"""
from __future__ import annotations

import logging
from django.db.models.signals import (
    post_save,
    pre_save,
)
from django.dispatch import receiver
from core.notifications_service import (
    _user_display_name,
    notify_platform_admins,
    notify_user,
)

logger = logging.getLogger('core.signals')


# =========================================================================
# 6. أمان الأجهزة، الحظر الأمني، الجلسات، وأحداث العبث والتحديثات
# =========================================================================
@receiver(pre_save, sender='api_v1.RegisteredDevice')
def _capture_registered_device_prev(sender, instance, **kwargs):
    if kwargs.get('raw') or not instance.pk:
        return
    try:
        from api_v1.models import RegisteredDevice
        instance._notif_prev_dev = (
            RegisteredDevice.objects.filter(pk=instance.pk)
            .values('is_active', 'trust_status')
            .first()
        )
    except Exception:
        instance._notif_prev_dev = None


@receiver(post_save, sender='api_v1.RegisteredDevice')
def _notify_registered_device_events(sender, instance, created, **kwargs):
    if kwargs.get('raw') or not instance.user_id:
        return
    try:
        dev_label = instance.device_name or instance.model or instance.os_name or 'جهاز جديد'
        user_label = _user_display_name(instance.user)
        if created:
            notify_user(
                instance.user,
                'تسجيل دخول من جهاز جديد',
                f"تم تسجيل «{dev_label}» ({instance.os_name}) كجهاز مسجّل على حسابك.",
                link='/devices/',
            )
        else:
            prev = getattr(instance, '_notif_prev_dev', None)
            instance._notif_prev_dev = None
            if not prev:
                return
            if prev.get('is_active') is True and instance.is_active is False:
                notify_user(
                    instance.user,
                    'تم إيقاف أو إزالة جهاز',
                    f"تم إلغاء اعتماد الجهاز «{dev_label}» من حسابك.",
                    link='/devices/',
                )
            elif (
                prev.get('trust_status') != instance.trust_status
                and instance.trust_status in ('suspicious', 'restricted')
            ):
                notify_platform_admins(
                    'تنبيه تصنيف جهاز عالي المخاطر',
                    f"تغيّرت حالة الجهاز «{dev_label}» للحساب ({user_label}) إلى {instance.trust_status} (نسبة المخاطرة {instance.risk_score}%).",
                    link='/admin-panel/security/',
                    roles=('owner', 'moderator'),
                )
    except Exception:
        logger.exception("Error in _notify_registered_device_events")


@receiver(pre_save, sender='api_v1.DeviceBlock')
def _capture_device_block_prev(sender, instance, **kwargs):
    if kwargs.get('raw') or not instance.pk:
        return
    try:
        from api_v1.models import DeviceBlock
        instance._notif_prev_block_active = (
            DeviceBlock.objects.filter(pk=instance.pk).values_list('is_active', flat=True).first()
        )
    except Exception:
        instance._notif_prev_block_active = None


@receiver(post_save, sender='api_v1.DeviceBlock')
def _notify_device_block_events(sender, instance, created, **kwargs):
    if kwargs.get('raw'):
        return
    try:
        target_user = instance.user or (instance.device.user if instance.device_id else None)
        if not target_user:
            return
        dev_name = (
            instance.device.device_name or instance.device.model
            if instance.device_id
            else instance.installation_id[:16]
        )
        if created and instance.is_active:
            notify_user(
                target_user,
                'تم حظر أحد أجهزة حسابك أمنياً',
                f"تم حظر الجهاز ({dev_name}). السبب: {instance.reason}.",
                link='/devices/',
            )
        else:
            prev_active = getattr(instance, '_notif_prev_block_active', None)
            instance._notif_prev_block_active = None
            if prev_active is True and instance.is_active is False:
                notify_user(
                    target_user,
                    'تم فك الحظر عن جهازك',
                    f"رفعت الإدارة الحظر عن الجهاز ({dev_name}) وأصبح بإمكانك استخدامه مجدداً.",
                    link='/devices/',
                )
    except Exception:
        logger.exception("Error in _notify_device_block_events")


@receiver(post_save, sender='api_v1.DeviceSecurityEvent')
def _notify_admins_critical_security_event(sender, instance, created, **kwargs):
    if kwargs.get('raw') or not created:
        return
    if instance.severity not in ('high', 'critical'):
        return
    try:
        user_label = _user_display_name(instance.user) if instance.user_id else 'مستخدم غير معروف'
        loc = instance.region_name or instance.country_code or instance.ip_address or 'غير محدد'
        notify_platform_admins(
            f'حدث أمني ({instance.severity}): {instance.event_type}',
            f"الحساب: {user_label} • درجة المخاطرة: {instance.risk_score} • الموقع/IP: {loc}.",
            link='/admin-panel/security/',
            roles=('owner', 'moderator'),
        )
    except Exception:
        logger.exception("Error in _notify_admins_critical_security_event")

"""core.signals.site_settings
Extracted from core/signals.py.
"""
from __future__ import annotations

import logging
from django.db.models.signals import (
    post_save,
    pre_save,
)
from django.dispatch import receiver
from core.models import SiteSetting
from core.notifications_service import notify_platform_admins

logger = logging.getLogger('core.signals')


@receiver(pre_save, sender=SiteSetting)
def _capture_site_setting_prev(sender, instance, **kwargs):
    if kwargs.get('raw') or not instance.pk:
        return
    try:
        instance._notif_prev_site = (
            SiteSetting.objects.filter(pk=instance.pk)
            .values('is_maintenance_mode', 'android_latest_version_code')
            .first()
        )
    except Exception:
        instance._notif_prev_site = None


@receiver(post_save, sender=SiteSetting)
def _notify_site_setting_changes(sender, instance, created, **kwargs):
    if kwargs.get('raw') or created:
        return
    prev = getattr(instance, '_notif_prev_site', None)
    instance._notif_prev_site = None
    if not prev:
        return
    try:
        if prev.get('is_maintenance_mode') != instance.is_maintenance_mode:
            state_txt = 'تفعيل وضع الصيانة العامة' if instance.is_maintenance_mode else 'إنهاء وضع الصيانة وإعادة تشغيل المنصة'
            notify_platform_admins(
                'تحديث حالة المنصة',
                f"تم {state_txt} على منصة تعلّم.",
                link='/admin-panel/',
                roles=('owner', 'moderator'),
            )
        prev_ver = int(prev.get('android_latest_version_code') or 1)
        if int(instance.android_latest_version_code or 1) > prev_ver:
            notify_platform_admins(
                f'اعتماد إصدار أندرويد جديد v{instance.android_latest_version_name}',
                f"تم نشر تحديث التطبيق (Build {instance.android_latest_version_code}) في إعدادات التحديث الداخلي.",
                link='/admin-panel/',
                roles=('owner', 'moderator'),
            )
    except Exception:
        logger.exception("Error in _notify_site_setting_changes")

"""core.signals.session_fcm
Extracted from core/signals.py.
"""
from __future__ import annotations

import logging
from django.db.models.signals import post_save
from django.dispatch import receiver
from django.contrib.auth.signals import user_logged_out

logger = logging.getLogger('core.signals')


@receiver(user_logged_out)
def _clear_video_watch_window_on_logout(sender, request, user, **kwargs):
    if not user or not getattr(user, 'id', None):
        return
    try:
        from api_v1.video_security import clear_watch_window
        clear_watch_window(user)
    except Exception:
        logger.exception("Error clearing watch window on logout")


@receiver(post_save, sender='core.Notification')
def _dispatch_fcm_on_notification_created(sender, instance, created, **kwargs):
    if kwargs.get('raw') or not created or not getattr(instance, 'pk', None):
        return
    try:
        from core.fcm_service import schedule_fcm_push_for_notifications
        schedule_fcm_push_for_notifications([instance.pk])
    except Exception:
        logger.exception("Error scheduling FCM push for notification id=%s", getattr(instance, 'pk', None))

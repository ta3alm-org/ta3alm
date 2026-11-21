"""core.signals.accounts
Extracted from core/signals.py.
"""
from __future__ import annotations

import logging
from django.contrib.auth import get_user_model
from django.db.models.signals import (
    post_save,
    pre_save,
)
from django.dispatch import receiver
from core.notifications_service import (
    _user_display_name,
    notify_user,
)

logger = logging.getLogger('core.signals')
User = get_user_model()


# =========================================================================
# 1. حسابات المستخدمين، التحقق OTP، كلمات المرور، الحظر، وروابط الدخول المؤقت
# =========================================================================
@receiver(pre_save, sender=User)
def _capture_user_prev_state(sender, instance, **kwargs):
    if kwargs.get('raw') or not instance.pk:
        return
    try:
        old = User.objects.filter(pk=instance.pk).values('password', 'is_banned').first()
        instance._notif_prev_user = old
    except Exception:
        instance._notif_prev_user = None


@receiver(post_save, sender=User)
def _notify_user_security_changes(sender, instance, created, **kwargs):
    if kwargs.get('raw') or created:
        return
    prev = getattr(instance, '_notif_prev_user', None)
    if not prev:
        return
    instance._notif_prev_user = None
    try:
        if prev.get('password') and instance.password != prev.get('password'):
            notify_user(
                instance,
                'تم تحديث كلمة المرور',
                'تم تغيير كلمة مرور حسابك بنجاح. إذا لم تقم بهذه الخطوة، يرجى تأمين أجهزة حسابك أو التواصل مع الدعم فوراً.',
                link='/devices/',
            )
        if prev.get('is_banned') is False and instance.is_banned is True:
            notify_user(
                instance,
                'تم إيقاف الحساب مؤقتاً',
                'تم حظر حسابك من قِبل إدارة المنصة. تواصل مع الدعم الفني لمراجعة حالة الحساب.',
                link='/banned/',
            )
        elif prev.get('is_banned') is True and instance.is_banned is False:
            notify_user(
                instance,
                'تم رفع الحظر عن حسابك',
                'أعادت الإدارة تفعيل حسابك على منصة تعلّم. مرحباً بعودتك!',
                link='/notifications/all/',
            )
    except Exception:
        logger.exception("Error in _notify_user_security_changes")


@receiver(pre_save, sender='accounts.EmailVerification')
def _capture_email_verification_prev(sender, instance, **kwargs):
    if kwargs.get('raw') or not instance.pk:
        return
    try:
        from accounts.models import EmailVerification
        instance._notif_prev_verified = (
            EmailVerification.objects.filter(pk=instance.pk)
            .values_list('is_verified', flat=True)
            .first()
        )
    except Exception:
        instance._notif_prev_verified = None


@receiver(post_save, sender='accounts.EmailVerification')
def _notify_email_verified_welcome(sender, instance, created, **kwargs):
    if kwargs.get('raw'):
        return
    was_verified = False if created else bool(getattr(instance, '_notif_prev_verified', False))
    instance._notif_prev_verified = None
    if instance.is_verified and not was_verified and instance.user_id:
        try:
            name = _user_display_name(instance.user)
            notify_user(
                instance.user,
                'مرحباً بك في منصة تعلّم!',
                f'أهلاً {name}، تم تأكيد حسابك وتفعيله بنجاح. يمكنك الآن استعراض الدروس والاختبارات بأمان.',
                link='/redirect/',
            )
        except Exception:
            logger.exception("Error in _notify_email_verified_welcome")


@receiver(post_save, sender='accounts.OneTimeLoginLink')
def _notify_one_time_login_link(sender, instance, created, **kwargs):
    if kwargs.get('raw') or not created or not instance.user_id:
        return
    try:
        notify_user(
            instance.user,
            'تم إصدار رابط دخول مؤقت لحسابك',
            'تم توليد رابط/كود دخول لمرة واحدة لحسابك من الإدارة.',
            link='/devices/',
        )
    except Exception:
        logger.exception("Error in _notify_one_time_login_link")

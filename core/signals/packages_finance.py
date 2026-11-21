"""core.signals.packages_finance
Extracted from core/signals.py.
"""
from __future__ import annotations

import logging
from django.db.models.signals import (
    post_save,
    pre_save,
)
from django.dispatch import receiver
from core.models import ManualPayment
from core.notifications_service import (
    _user_display_name,
    notify_platform_admins,
    notify_user,
)

logger = logging.getLogger('core.signals')


# =========================================================================
# 4. المدفوعات، شراء الحزم، الاشتراكات، المحفظة وطلبات السحب
# =========================================================================
@receiver(pre_save, sender='students.PackageEnrollment')
def _capture_pkg_enrollment_prev(sender, instance, **kwargs):
    if kwargs.get('raw') or not instance.pk:
        return
    try:
        from students.models import PackageEnrollment
        instance._notif_prev_paid = (
            PackageEnrollment.objects.filter(pk=instance.pk).values_list('is_paid', flat=True).first()
        )
    except Exception:
        instance._notif_prev_paid = None


@receiver(post_save, sender='students.PackageEnrollment')
def _notify_package_purchased(sender, instance, created, **kwargs):
    if kwargs.get('raw'):
        return
    was_paid = False if created else bool(getattr(instance, '_notif_prev_paid', False))
    instance._notif_prev_paid = None
    if instance.is_paid and not was_paid:
        try:
            pkg = instance.package
            student_user = instance.student.user
            notify_user(
                student_user,
                'تم تفعيل حزمتك التعليمية',
                f"أصبحت حزمة «{pkg.title}» متاحة بالكامل في حسابك. ابدأ التعلم الآن!",
                link=f'/student/package/{pkg.id}/content/',
            )
            notify_user(
                pkg.teacher.user,
                'مبيعة جديدة لحزمتك!',
                f"اشترى الطالب {_user_display_name(student_user)} حزمة «{pkg.title}» وتمت إضافة صافي الأرباح لمحفظتك.",
                link='/teacher/wallet/',
            )
        except Exception:
            logger.exception("Error in _notify_package_purchased")


@receiver(pre_save, sender=ManualPayment)
def _capture_manual_payment_prev(sender, instance, **kwargs):
    if kwargs.get('raw') or not instance.pk:
        return
    try:
        instance._notif_prev_status = (
            ManualPayment.objects.filter(pk=instance.pk).values_list('status', flat=True).first()
        )
    except Exception:
        instance._notif_prev_status = None


@receiver(post_save, sender=ManualPayment)
def _notify_manual_payment_events(sender, instance, created, **kwargs):
    if kwargs.get('raw'):
        return
    try:
        payer = instance.user
        payer_name = _user_display_name(payer)
        type_label = instance.get_payment_type_display()

        if created:
            notify_user(
                payer,
                'تم استلام طلب الدفع اليدوي',
                f"استلمنا طلبك (#{instance.id} - {type_label}) بمبلغ {instance.amount} ج.م، وهو قيد مراجعة الإدارة.",
                link='/notifications/all/',
            )
            notify_platform_admins(
                f'طلب دفع يدوي جديد (#{instance.id})',
                f"قدّم {payer_name} إيصال دفع يدوي بمبلغ {instance.amount} ج.م ({type_label}).",
                link='/admin-panel/finance/',
                roles=('owner', 'finance'),
            )
        else:
            prev_status = getattr(instance, '_notif_prev_status', None)
            instance._notif_prev_status = None
            if prev_status != 'approved' and instance.status == 'approved':
                target_link = (
                    '/teacher/subscription/'
                    if instance.payment_type == 'teacher_subscription'
                    else (f'/student/package/{instance.target_id}/content/' if instance.target_id else '/student/dashboard/')
                )
                notify_user(
                    payer,
                    'تم قبول وتفعيل طلب الدفع!',
                    f"تمت الموافقة على طلب الدفع (#{instance.id}) بمبلغ {instance.amount} ج.م وتفعيل خدمتك بنجاح.",
                    link=target_link,
                )
            elif prev_status != 'rejected' and instance.status == 'rejected':
                notify_user(
                    payer,
                    'لم يتم قبول طلب الدفع اليدوي',
                    f"تم رفض طلب الدفع (#{instance.id}) بمبلغ {instance.amount} ج.م. تأكد من صحة الإيصال أو تواصل مع الدعم.",
                    link='/notifications/all/',
                )
    except Exception:
        logger.exception("Error in _notify_manual_payment_events")


@receiver(post_save, sender='teachers.PaymentTransaction')
def _notify_subscription_payment_tx(sender, instance, created, **kwargs):
    if kwargs.get('raw') or not created:
        return
    try:
        teacher_user = instance.teacher.user
        teacher_name = _user_display_name(teacher_user)
        notify_user(
            teacher_user,
            'تم تجديد اشتراكك بنجاح',
            f"تم تأكيد سداد مبلغ {instance.amount} ج.م وتمديد اشتراكك بالمنصة.",
            link='/teacher/subscription/',
        )
        notify_platform_admins(
            'عملية تجديد اشتراك معلم',
            f"قام المعلم {teacher_name} بسداد {instance.amount} ج.م لتجديد الاشتراك.",
            link='/admin-panel/finance/',
            roles=('owner', 'finance'),
        )
    except Exception:
        logger.exception("Error in _notify_subscription_payment_tx")


@receiver(pre_save, sender='teachers.WithdrawRequest')
def _capture_withdraw_prev(sender, instance, **kwargs):
    if kwargs.get('raw') or not instance.pk:
        return
    try:
        from teachers.models import WithdrawRequest
        prev = (
            WithdrawRequest.objects.filter(pk=instance.pk)
            .values('is_paid', 'status')
            .first()
        )
        instance._notif_prev_is_paid = prev.get('is_paid') if prev else None
        instance._notif_prev_status = prev.get('status') if prev else None
    except Exception:
        instance._notif_prev_is_paid = None
        instance._notif_prev_status = None


@receiver(post_save, sender='teachers.WithdrawRequest')
def _notify_withdraw_request_events(sender, instance, created, **kwargs):
    if kwargs.get('raw'):
        return
    try:
        teacher_user = instance.wallet.teacher.user
        teacher_name = _user_display_name(teacher_user)
        method_label = instance.get_method_display()

        if created:
            notify_user(
                teacher_user,
                'تم تسجيل طلب سحب أرباح',
                f"طلبك لسحب {instance.amount} ج.م عبر {method_label} قيد المراجعة المالية.",
                link='/teacher/wallet/',
            )
            notify_platform_admins(
                f'طلب سحب أرباح جديد (#{instance.id})',
                f"طلب المعلم {teacher_name} سحب {instance.amount} ج.م عبر {method_label}.",
                link='/admin-panel/finance/withdrawals/',
                roles=('owner', 'finance'),
            )
        else:
            prev_paid = getattr(instance, '_notif_prev_is_paid', None)
            prev_status = getattr(instance, '_notif_prev_status', None)
            instance._notif_prev_is_paid = None
            instance._notif_prev_status = None
            if (prev_paid is False and instance.is_paid is True) or (
                prev_status != 'paid' and instance.status == 'paid'
            ):
                notify_user(
                    teacher_user,
                    'تم تحويل أرباحك!',
                    f"تم اعتماد وتحويل مبلغ {instance.amount} ج.م عبر {method_label} إلى ({instance.details}).",
                    link='/teacher/wallet/',
                )
            elif prev_status != 'rejected' and instance.status == 'rejected':
                reason_text = (instance.rejection_reason or '').strip()
                reason_suffix = f" السبب: {reason_text}" if reason_text else ""
                notify_user(
                    teacher_user,
                    'تم رفض طلب السحب وإرجاع الرصيد',
                    f"تم رفض طلب سحب مبلغ {instance.amount} ج.م عبر {method_label} وإعادة المبلغ إلى رصيد محفظتك المتاح.{reason_suffix}",
                    link='/teacher/wallet/',
                )
    except Exception:
        logger.exception("Error in _notify_withdraw_request_events")

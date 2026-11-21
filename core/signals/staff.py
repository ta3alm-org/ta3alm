"""core.signals.staff
Extracted from core/signals.py.
"""
from __future__ import annotations

import logging
from django.db.models.signals import (
    post_delete,
    post_save,
    pre_save,
)
from django.dispatch import receiver
from core.notifications_service import (
    _user_display_name,
    notify_user,
)

logger = logging.getLogger('core.signals')


# =========================================================================
# 5. فريق العمل (المساعدون والفريق الإداري)
# =========================================================================
@receiver(pre_save, sender='assistants.AssistantJob')
def _capture_assistant_job_prev(sender, instance, **kwargs):
    if kwargs.get('raw') or not instance.pk:
        return
    try:
        from assistants.models import AssistantJob
        instance._notif_prev_job = (
            AssistantJob.objects.filter(pk=instance.pk)
            .values(
                'is_active',
                'can_manage_students',
                'can_manage_exams',
                'can_manage_videos',
                'can_manage_packages',
            )
            .first()
        )
    except Exception:
        instance._notif_prev_job = None


@receiver(post_save, sender='assistants.AssistantJob')
def _notify_assistant_job_events(sender, instance, created, **kwargs):
    if kwargs.get('raw'):
        return
    try:
        assistant_user = instance.assistant.user
        teacher_user = instance.teacher.user
        assistant_name = _user_display_name(assistant_user)
        teacher_name = _user_display_name(teacher_user)

        if created:
            if not instance.is_active:
                notify_user(
                    teacher_user,
                    'طلب انضمام مساعد جديد',
                    f"طلب المساعد {assistant_name} الانضمام إلى فريق العمل الخاص بك.",
                    link='/teacher/assistants/manage/',
                )
                notify_user(
                    assistant_user,
                    'تم إرسال طلب الانضمام',
                    f"تم إرسال طلب انضمامك كمساعد للمعلم أ. {teacher_name}، وهو قيد المراجعة.",
                    link='/assistants/dashboard/',
                )
            else:
                notify_user(
                    assistant_user,
                    'تم إضافتك كمساعد معلم',
                    f"أُضيفت صلاحيتك كمساعد في فريق أ. {teacher_name}.",
                    link='/assistants/dashboard/',
                )
        else:
            prev = getattr(instance, '_notif_prev_job', None)
            instance._notif_prev_job = None
            if not prev:
                return
            if prev.get('is_active') is False and instance.is_active is True:
                notify_user(
                    assistant_user,
                    'تم قبولك في فريق المعلم!',
                    f"وافق أ. {teacher_name} على انضمامك كمساعد. يمكنك الآن متابعة المجموعات المسموحة.",
                    link='/assistants/dashboard/',
                )
            elif instance.is_active and any(
                prev.get(field) != getattr(instance, field)
                for field in (
                    'can_manage_students',
                    'can_manage_exams',
                    'can_manage_videos',
                    'can_manage_packages',
                )
            ):
                notify_user(
                    assistant_user,
                    'تم تحديث صلاحياتك كمساعد',
                    f"عدّل أ. {teacher_name} صلاحيات إدارتك داخل المنصة.",
                    link='/assistants/dashboard/',
                )
    except Exception:
        logger.exception("Error in _notify_assistant_job_events")


@receiver(post_delete, sender='assistants.AssistantJob')
def _notify_assistant_job_removed(sender, instance, **kwargs):
    try:
        if not instance.assistant_id or not instance.teacher_id:
            return
        teacher_name = _user_display_name(instance.teacher.user)
        notify_user(
            instance.assistant.user,
            'إنهاء الارتباط كمساعد معلم',
            f"تم إيقاف أو إنهاء ارتباط عملك مع أ. {teacher_name}.",
            link='/assistants/dashboard/',
        )
    except Exception:
        logger.exception("Error in _notify_assistant_job_removed")


@receiver(pre_save, sender='dashboard_admin.AdminProfile')
def _capture_admin_profile_prev(sender, instance, **kwargs):
    if kwargs.get('raw') or not instance.pk:
        return
    try:
        from dashboard_admin.models import AdminProfile
        instance._notif_prev_role = (
            AdminProfile.objects.filter(pk=instance.pk).values('admin_role', 'is_active_admin').first()
        )
    except Exception:
        instance._notif_prev_role = None


@receiver(post_save, sender='dashboard_admin.AdminProfile')
def _notify_admin_staff_assigned(sender, instance, created, **kwargs):
    if kwargs.get('raw') or not instance.user_id:
        return
    try:
        role_label = instance.get_admin_role_display()
        if created:
            notify_user(
                instance.user,
                'تم تعيينك في الفريق الإداري',
                f"مُنحت صلاحية «{role_label}» في إدارة منصة تعلّم.",
                link='/admin-panel/',
            )
        else:
            prev = getattr(instance, '_notif_prev_role', None)
            instance._notif_prev_role = None
            if prev and prev.get('admin_role') != instance.admin_role:
                notify_user(
                    instance.user,
                    'تحديث صلاحيتك الإدارية',
                    f"تم تعديل دورك الإداري في المنصة إلى «{role_label}».",
                    link='/admin-panel/',
                )
    except Exception:
        logger.exception("Error in _notify_admin_staff_assigned")


@receiver(post_delete, sender='dashboard_admin.AdminProfile')
def _notify_admin_staff_removed(sender, instance, **kwargs):
    try:
        if not instance.user_id:
            return
        notify_user(
            instance.user,
            'تحديث الصلاحيات الإدارية',
            'تمت إزالة صلاحياتك من الفريق الإداري للمنصة.',
            link='/notifications/all/',
        )
    except Exception:
        logger.exception("Error in _notify_admin_staff_removed")

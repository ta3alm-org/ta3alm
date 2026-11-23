"""core.signals.academics
Extracted from core/signals.py.
"""
from __future__ import annotations

import logging
from django.contrib.auth import get_user_model
from django.core.exceptions import ObjectDoesNotExist
from django.db.models.signals import (
    m2m_changed,
    post_delete,
    post_save,
    pre_save,
)
from django.dispatch import receiver
from core.notifications_service import (
    _user_display_name,
    notify_group_students,
    notify_package_students,
    notify_teacher_and_assistants,
    notify_user,
)

logger = logging.getLogger('core.signals')


# =========================================================================
# 2. المجموعات، المحاضرات، الملفات، أكواد المشاهدة، والامتحانات
# =========================================================================
@receiver(pre_save, sender='students.Enrollment')
def _capture_enrollment_prev(sender, instance, **kwargs):
    if kwargs.get('raw') or not instance.pk:
        return
    try:
        from students.models import Enrollment
        instance._notif_prev_active = (
            Enrollment.objects.filter(pk=instance.pk).values_list('is_active', flat=True).first()
        )
    except Exception:
        instance._notif_prev_active = None


@receiver(post_save, sender='students.Enrollment')
def _notify_enrollment_events(sender, instance, created, **kwargs):
    if kwargs.get('raw'):
        return
    try:
        group = instance.group
        student_user = instance.student.user
        teacher = group.teacher
        student_name = _user_display_name(student_user)
        teacher_name = _user_display_name(teacher.user)

        if created:
            if instance.is_active:
                notify_user(
                    student_user,
                    'تم انضمامك إلى مجموعة جديدة',
                    f'تم تفعيل اشتراكك في مجموعة «{group.name}» مع أ. {teacher_name}.',
                    link=f'/student/group/{group.id}/',
                )
            else:
                notify_teacher_and_assistants(
                    teacher,
                    'طلب انضمام جديد',
                    f'الطالب {student_name} طلب الانضمام إلى مجموعة «{group.name}».',
                    link=f'/teacher/group/{group.id}/requests/',
                    permission_field='can_manage_students',
                )
                notify_user(
                    student_user,
                    'تم إرسال طلب الانضمام',
                    f'طلبك للانضمام إلى مجموعة «{group.name}» مع أ. {teacher_name} بانتظار موافقة المعلم.',
                    link='/student/dashboard/',
                )
        else:
            prev_active = getattr(instance, '_notif_prev_active', None)
            instance._notif_prev_active = None
            if prev_active is False and instance.is_active is True:
                notify_user(
                    student_user,
                    'تم قبول طلبك!',
                    f'وافق أ. {teacher_name} على انضمامك لمجموعة «{group.name}». ابدأ التعلم الآن!',
                    link=f'/student/group/{group.id}/',
                )
    except Exception:
        logger.exception("Error in _notify_enrollment_events")


@receiver(post_delete, sender='students.Enrollment')
def _notify_enrollment_deleted(sender, instance, **kwargs):
    try:
        User = get_user_model()
        origin = kwargs.get('origin')
        if isinstance(origin, User) or getattr(origin, 'model', None) is User:
            return
        if not instance.student_id or not instance.group_id:
            return
        try:
            group = instance.group
            student = instance.student
            student_user = student.user
        except ObjectDoesNotExist:
            return
        if not student_user or not User.objects.filter(pk=student_user.pk).exists():
            return
        if instance.is_active:
            notify_user(
                student_user,
                'تحديث عضوية المجموعة',
                f'تم إنهاء اشتراكك وإزالتك من مجموعة «{group.name}».',
                link='/search/',
            )
        else:
            notify_user(
                student_user,
                'تم رفض طلب الانضمام',
                f'لم يتم قبول طلب انضمامك إلى مجموعة «{group.name}». يمكنك البحث عن مجموعات أخرى.',
                link='/search/',
            )
    except Exception:
        logger.exception("Error in _notify_enrollment_deleted")


@receiver(pre_save, sender='teachers.Lecture')
def _capture_lecture_prev(sender, instance, **kwargs):
    if kwargs.get('raw') or not instance.pk:
        return
    try:
        from teachers.models import Lecture
        instance._notif_prev_active = (
            Lecture.objects.filter(pk=instance.pk).values_list('is_active', flat=True).first()
        )
    except Exception:
        instance._notif_prev_active = None


@receiver(post_save, sender='teachers.Lecture')
def _notify_lecture_published(sender, instance, created, **kwargs):
    if kwargs.get('raw') or not instance.group_id:
        return
    try:
        group = instance.group
        was_active = False if created else bool(getattr(instance, '_notif_prev_active', False))
        instance._notif_prev_active = None

        if created and instance.is_active:
            notify_group_students(
                group,
                'محاضرة جديدة متاحة',
                f"تم نشر محاضرة «{instance.title}» في مجموعة {group.name}.",
                link=f'/student/lecture/{instance.id}/watch/',
            )
        elif not created and not was_active and instance.is_active:
            notify_group_students(
                group,
                'تم تفعيل محاضرة في مجموعتك',
                f"المحاضرة «{instance.title}» أصبحت متاحة الآن للمشاهدة في مجموعة {group.name}.",
                link=f'/student/lecture/{instance.id}/watch/',
            )
    except Exception:
        logger.exception("Error in _notify_lecture_published")


@receiver(post_save, sender='teachers.PDFFile')
def _notify_pdf_uploaded(sender, instance, created, **kwargs):
    if kwargs.get('raw') or not created:
        return
    try:
        if instance.group_id:
            group = instance.group
            notify_group_students(
                group,
                'ملف ومذكرة جديدة',
                f"أُضيف ملف «{instance.title}» في مجموعة {group.name}.",
                link=f'/student/group/{group.id}/',
            )
    except Exception:
        logger.exception("Error in _notify_pdf_uploaded")


@receiver(pre_save, sender='exams.Exam')
def _capture_exam_prev(sender, instance, **kwargs):
    if kwargs.get('raw') or not instance.pk:
        return
    try:
        from exams.models import Exam
        instance._notif_prev_active = (
            Exam.objects.filter(pk=instance.pk).values_list('is_active', flat=True).first()
        )
    except Exception:
        instance._notif_prev_active = None


@receiver(post_save, sender='exams.Exam')
def _notify_exam_published(sender, instance, created, **kwargs):
    if kwargs.get('raw') or not instance.group_id:
        return
    try:
        group = instance.group
        was_active = False if created else bool(getattr(instance, '_notif_prev_active', False))
        instance._notif_prev_active = None

        if instance.is_active and (created or not was_active):
            notify_group_students(
                group,
                'اختبار جديد جاهز للحل',
                f"تم إتاحة اختبار «{instance.title}» (المدة: {instance.duration_minutes} دقيقة) في مجموعة {group.name}.",
                link=f'/student/exam/{instance.id}/take/',
            )
    except Exception:
        logger.exception("Error in _notify_exam_published")


def _notify_package_content_added(sender, instance, action, reverse, model, pk_set, **kwargs):
    if action != 'post_add' or reverse or not pk_set or not instance or not instance.is_active:
        return
    try:
        from teachers.models import CoursePackage
        if not isinstance(instance, CoursePackage):
            return
        model_name = model.__name__ if model else ''
        count = len(pk_set)
        if model_name == 'Lecture':
            label = 'محاضرة جديدة' if count == 1 else f'{count} محاضرات جديدة'
        elif model_name == 'Exam':
            label = 'اختبار جديد' if count == 1 else f'{count} اختبارات جديدة'
        elif model_name == 'PDFFile':
            label = 'ملف جديد' if count == 1 else f'{count} ملفات جديدة'
        else:
            label = 'محتوى جديد'

        notify_package_students(
            instance,
            f'تحديث في حزمة «{instance.title}»',
            f'تم إضافة {label} داخل حزمة «{instance.title}». ادخل الآن لاستعراض المحتوى الجديد.',
            link=f'/student/package/{instance.id}/content/',
        )
    except Exception:
        logger.exception("Error in _notify_package_content_added")


def connect_m2m_signals():
    """يربط إشارات الجداول الوسيطة (M2M) التي تُنشأ ديناميكياً بعد اكتمال تحميل التطبيقات."""
    from teachers.models import CoursePackage

    for field_name in ('lectures', 'exams', 'pdfs'):
        through_model = getattr(CoursePackage, field_name).through
        m2m_changed.connect(
            _notify_package_content_added,
            sender=through_model,
            dispatch_uid=f'ta3alm_pkg_m2m_{field_name}',
        )


@receiver(pre_save, sender='teachers.VideoCode')
def _capture_videocode_prev(sender, instance, **kwargs):
    if kwargs.get('raw') or not instance.pk:
        return
    try:
        from teachers.models import VideoCode
        instance._notif_prev_vc = (
            VideoCode.objects.filter(pk=instance.pk).values('is_used', 'current_views').first()
        )
    except Exception:
        instance._notif_prev_vc = None


@receiver(post_save, sender='teachers.VideoCode')
def _notify_videocode_events(sender, instance, created, **kwargs):
    if kwargs.get('raw') or created or not instance.used_by_id:
        return
    prev = getattr(instance, '_notif_prev_vc', None)
    instance._notif_prev_vc = None
    if not prev:
        return
    try:
        student_user = instance.used_by.user
        lecture = instance.lecture
        if prev.get('is_used') is False and instance.is_used is True:
            notify_user(
                student_user,
                'تم تفعيل كود المحاضرة',
                f"فُتحت لك محاضرة «{lecture.title}» بنجاح (الحد المتاح: {instance.max_views} مشاهدة).",
                link=f'/student/lecture/{lecture.id}/watch/',
            )
        elif (
            instance.current_views > (prev.get('current_views') or 0)
            and instance.current_views >= instance.max_views
        ):
            target_link = f'/student/group/{lecture.group_id}/' if lecture.group_id else '/notifications/all/'
            notify_user(
                student_user,
                'انتهاء مشاهدات الكود',
                f"استنفدت كافة المشاهدات المتاحة لمحاضرة «{lecture.title}» ({instance.max_views}/{instance.max_views}).",
                link=target_link,
            )
    except Exception:
        logger.exception("Error in _notify_videocode_events")

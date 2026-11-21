"""core.signals.results
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
    notify_teacher_and_assistants,
    notify_user,
)

logger = logging.getLogger('core.signals')


# =========================================================================
# 3. نتائج الامتحانات، الحصص وسجل الأداء، وتتبع إتمام فيديو الحزمة
# =========================================================================
@receiver(post_save, sender='exams.ExamResult')
def _notify_exam_result(sender, instance, created, **kwargs):
    if kwargs.get('raw') or not created:
        return
    try:
        exam = instance.exam
        student_user = instance.student.user
        total = exam.total_marks()
        score_text = f'{instance.score}/{total}' if total else str(instance.score)
        student_link = f'/student/group/{exam.group_id}/marks/' if exam.group_id else '/notifications/all/'

        notify_user(
            student_user,
            'نتيجة الاختبار',
            f"أكملت اختبار «{exam.title}» وحصلت على درجة {score_text}.",
            link=student_link,
        )
        if exam.group_id:
            notify_teacher_and_assistants(
                exam.group.teacher,
                'تسليم اختبار جديد',
                f"أنهى الطالب {_user_display_name(student_user)} اختبار «{exam.title}» بدرجة {score_text}.",
                link=f'/teacher/group/{exam.group_id}/students/',
                permission_field='can_manage_exams',
            )
    except Exception:
        logger.exception("Error in _notify_exam_result")


@receiver(post_save, sender='students.PackageExamResult')
def _notify_package_exam_result(sender, instance, created, **kwargs):
    if kwargs.get('raw') or not created:
        return
    try:
        exam = instance.exam
        pkg = instance.package
        student_user = instance.student.user
        total = exam.total_marks()
        score_text = f'{instance.score}/{total}' if total else str(instance.score)

        notify_user(
            student_user,
            'نتيجة اختبار الحزمة',
            f"حصلت على درجة {score_text} في اختبار «{exam.title}» ضمن حزمة «{pkg.title}».",
            link=f'/student/package/{pkg.id}/content/',
        )
        notify_teacher_and_assistants(
            pkg.teacher,
            'إتمام اختبار في حزمة تعليمية',
            f"أكمل الطالب {_user_display_name(student_user)} اختبار «{exam.title}» بحزمة «{pkg.title}» بدرجة {score_text}.",
            link=f'/teacher/package/{pkg.id}/manage/',
            permission_field='can_manage_exams',
        )
    except Exception:
        logger.exception("Error in _notify_package_exam_result")


@receiver(post_save, sender='students.PerformanceLog')
def _notify_performance_log(sender, instance, created, **kwargs):
    if kwargs.get('raw'):
        return
    try:
        parts = ['حاضر' if instance.is_present else 'غائب']
        if instance.homework_score is not None:
            parts.append(f'الواجب {instance.homework_score}/{instance.homework_max}')
        if instance.class_exam_score is not None:
            parts.append(f'امتحان الحصة {instance.class_exam_score}/{instance.class_exam_max}')
        if instance.recitation_score is not None:
            parts.append(f'التسميع {instance.recitation_score}/{instance.recitation_max}')
        if instance.comprehensive_exam_score is not None:
            parts.append(f'الشامل {instance.comprehensive_exam_score}/{instance.comprehensive_exam_max}')
        if instance.note:
            parts.append(f'ملاحظة: {instance.note}')

        action_word = 'رصد' if created else 'تحديث'
        notify_user(
            instance.student.user,
            f'{action_word} سجل الأداء — الحصة {instance.session_number}',
            f"مجموعة «{instance.group.name}»: " + ' • '.join(parts),
            link=f'/student/group/{instance.group_id}/marks/',
        )
    except Exception:
        logger.exception("Error in _notify_performance_log")


@receiver(pre_save, sender='students.VideoViewTracking')
def _capture_video_tracking_prev(sender, instance, **kwargs):
    if kwargs.get('raw') or not instance.pk:
        return
    try:
        from students.models import VideoViewTracking
        instance._notif_prev_completed = (
            VideoViewTracking.objects.filter(pk=instance.pk).values_list('is_completed', flat=True).first()
        )
    except Exception:
        instance._notif_prev_completed = None


@receiver(post_save, sender='students.VideoViewTracking')
def _notify_package_video_completed(sender, instance, created, **kwargs):
    if kwargs.get('raw'):
        return
    was_completed = False if created else bool(getattr(instance, '_notif_prev_completed', False))
    instance._notif_prev_completed = None
    if instance.is_completed and not was_completed and instance.points_awarded > 0:
        try:
            notify_user(
                instance.student.user,
                'إتمام مشاهدة محاضرة بالحزمة',
                f"أتممت مشاهدة «{instance.lecture.title}» في حزمة «{instance.package.title}» وتمت إضافة {instance.points_awarded} نقطة لرصيدك.",
                link=f'/student/package/{instance.package_id}/content/',
            )
        except Exception:
            logger.exception("Error in _notify_package_video_completed")

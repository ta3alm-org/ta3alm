"""
core/signals.py
التقاط أحداث النماذج عبر المنصة (الويب + API + لوحة الإدارة) وإرسال إشعارات دقيقة لكل دور دون تكرار.
"""
from __future__ import annotations

import logging
from django.contrib.auth import get_user_model
from django.db.models.signals import m2m_changed, post_delete, post_save, pre_save
from django.dispatch import receiver

from .models import ManualPayment, SiteSetting
from .notifications_service import (
    _user_display_name,
    notify_group_students,
    notify_package_students,
    notify_platform_admins,
    notify_teacher_and_assistants,
    notify_user,
)

logger = logging.getLogger(__name__)
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
        if not instance.student_id or not instance.group_id:
            return
        group = instance.group
        student_user = instance.student.user
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


from django.contrib.auth.signals import user_logged_out


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
        from .fcm_service import schedule_fcm_push_for_notifications
        schedule_fcm_push_for_notifications([instance.pk])
    except Exception:
        logger.exception("Error scheduling FCM push for notification id=%s", getattr(instance, 'pk', None))

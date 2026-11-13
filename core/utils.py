from .models import Notification
from django.db.models import Sum

def send_notification(user, title, message, link=None):
    """
    دالة لإرسال إشعار لمستخدم معين.
    """
    Notification.objects.create(
        recipient=user,
        title=title,
        message=message,
        link=link
    )


def get_optimized_group_leaderboard(group):
    """
    حساب لوحة شرف المجموعة باستخدام 3 استعلامات فقط بدلاً من N+1.
    """
    from students.models import PerformanceLog
    from exams.models import ExamResult

    enrollments = list(group.enrollments.filter(is_active=True).select_related('student__user'))
    if not enrollments:
        return []

    student_ids = [e.student_id for e in enrollments]

    # 1. تجميع درجات السجلات في استعلام واحد
    perf_rows = PerformanceLog.objects.filter(
        group=group, student_id__in=student_ids
    ).values('student_id').annotate(
        hw=Sum('homework_score'),
        ce=Sum('class_exam_score'),
        rec=Sum('recitation_score'),
        comp=Sum('comprehensive_exam_score'),
    )
    perf_map = {
        r['student_id']: (r['hw'] or 0) + (r['ce'] or 0) + (r['rec'] or 0) + (r['comp'] or 0)
        for r in perf_rows
    }

    # 2. تجميع درجات الامتحانات في استعلام واحد
    exam_rows = ExamResult.objects.filter(
        exam__group=group, student_id__in=student_ids
    ).values('student_id').annotate(total=Sum('score'))
    exam_map = {r['student_id']: (r['total'] or 0) for r in exam_rows}

    leaderboard = []
    for enroll in enrollments:
        sid = enroll.student_id
        total = perf_map.get(sid, 0) + exam_map.get(sid, 0)
        leaderboard.append({'student': enroll.student, 'total_score': total})

    leaderboard.sort(key=lambda x: x['total_score'], reverse=True)
    for i, item in enumerate(leaderboard):
        item['rank'] = i + 1
    return leaderboard


def get_optimized_package_leaderboard(package):
    """
    حساب لوحة شرف الحزمة باستخدام 3 استعلامات فقط بدلاً من N+1.
    """
    from students.models import VideoViewTracking, PackageExamResult

    enrollments = list(package.enrollments.filter(is_paid=True).select_related('student__user'))
    if not enrollments:
        return []

    student_ids = [e.student_id for e in enrollments]

    video_rows = VideoViewTracking.objects.filter(
        package=package, student_id__in=student_ids, is_completed=True
    ).values('student_id').annotate(total=Sum('points_awarded'))
    video_map = {r['student_id']: (r['total'] or 0) for r in video_rows}

    exam_rows = PackageExamResult.objects.filter(
        package=package, student_id__in=student_ids
    ).values('student_id').annotate(total=Sum('score'))
    exam_map = {r['student_id']: (r['total'] or 0) for r in exam_rows}

    leaderboard = []
    for enroll in enrollments:
        sid = enroll.student_id
        total = video_map.get(sid, 0) + exam_map.get(sid, 0)
        leaderboard.append({'student': enroll.student, 'score': total})

    leaderboard.sort(key=lambda x: x['score'], reverse=True)
    for i, item in enumerate(leaderboard):
        item['rank'] = i + 1
    return leaderboard

from .models import Notification

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

from django.db.models import Sum
from django.db.models.functions import Coalesce

def get_optimized_group_leaderboard(group):
    from teachers.models import PerformanceLog
    from exams.models import ExamResult
    
    enrollments = group.enrollments.filter(is_active=True).select_related('student__user')
    student_ids = [e.student_id for e in enrollments]

    perf_totals = PerformanceLog.objects.filter(group=group, student_id__in=student_ids).values('student_id').annotate(
        total_perf=Sum(
            Coalesce('homework_score', 0.0) +
            Coalesce('class_exam_score', 0.0) +
            Coalesce('recitation_score', 0.0) +
            Coalesce('comprehensive_exam_score', 0.0)
        )
    )
    perf_dict = {p['student_id']: p['total_perf'] for p in perf_totals}

    exam_totals = ExamResult.objects.filter(exam__group=group, student_id__in=student_ids).values('student_id').annotate(
        total_exam=Sum('score')
    )
    exam_dict = {e['student_id']: e['total_exam'] for e in exam_totals}

    leaderboard = []
    for enroll in enrollments:
        sid = enroll.student_id
        score = float(perf_dict.get(sid, 0.0) or 0.0) + float(exam_dict.get(sid, 0.0) or 0.0)
        leaderboard.append({'student': enroll.student, 'total_score': round(score, 2)})

    leaderboard.sort(key=lambda x: x['total_score'], reverse=True)
    for i, item in enumerate(leaderboard):
        item['rank'] = i + 1
    return leaderboard

def get_optimized_package_leaderboard(package):
    from students.models import VideoViewTracking
    from exams.models import PackageExamResult
    
    enrollments = package.enrollments.filter(is_paid=True).select_related('student__user')
    student_ids = [e.student_id for e in enrollments]

    video_totals = VideoViewTracking.objects.filter(package=package, student_id__in=student_ids, is_completed=True).values('student_id').annotate(
        total_video=Sum('points_awarded')
    )
    video_dict = {v['student_id']: v['total_video'] for v in video_totals}

    pexam_totals = PackageExamResult.objects.filter(package=package, student_id__in=student_ids).values('student_id').annotate(
        total_exam=Sum('score')
    )
    pexam_dict = {p['student_id']: p['total_exam'] for p in pexam_totals}

    leaderboard = []
    for enroll in enrollments:
        sid = enroll.student_id
        score = float(video_dict.get(sid, 0.0) or 0.0) + float(pexam_dict.get(sid, 0.0) or 0.0)
        leaderboard.append({'student': enroll.student, 'score': round(score, 2)})

    leaderboard.sort(key=lambda x: x['score'], reverse=True)
    for i, item in enumerate(leaderboard):
        item['rank'] = i + 1
    return leaderboard

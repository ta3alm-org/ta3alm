"""students.views.access
Extracted from students/views.py.
"""

from django.shortcuts import get_object_or_404
from teachers.models import Group
from students.models import Enrollment
from exams.models import ExamResult
from core.utils import get_optimized_group_leaderboard
from students.models import VideoViewTracking
from django.db import models


def _clear_student_web_watch_state(request) -> None:
    """يمسح نوافذ المشاهدة النشطة عند العودة للقوائم أو الخروج من صفحة المحاضرة."""
    if not getattr(request, 'user', None) or not request.user.is_authenticated:
        return
    from api_v1.video_security import clear_watch_window
    clear_watch_window(request.user)
    session = getattr(request, 'session', None)
    if session is not None:
        stale_keys = [
            k for k in list(session.keys())
            if isinstance(k, str) and (k.startswith('viewed_lec_') or k.startswith('viewed_pkg_lec_'))
        ]
        for k in stale_keys:
            session.pop(k, None)


# --- دالة مساعدة للتحقق من الطالب واشتراك المعلم ---
# دالة التحقق الذكية (تشمل الباقات والاشتراك)
def check_student_access(user, group_id):
    if user.role != 'student':
        return None, "not_student"
    
    group = get_object_or_404(Group, id=group_id)
    teacher = group.teacher

    # 1. التحقق من صلاحية الاشتراك الزمنية
    if not teacher.has_active_subscription():
        return group, "teacher_expired"

    # 2. التحقق من الانضمام
    try:
        enrollment = Enrollment.objects.get(student=user.student_profile, group=group, is_active=True)
    except Enrollment.DoesNotExist:
        return group, "not_enrolled"

    # 3. التحقق من حد الباقة (الخدعة الذكية)
    limit = teacher.get_student_limit() # مثلاً 1000
    
    # نجلب كل طلاب المعلم (عبر كل المجموعات) مرتبين بتاريخ الانضمام (الأقدم فالأحدث)
    # ونأخذ أول 1000 طالب فقط (المحظوظين)
    allowed_students_ids = Enrollment.objects.filter(
        group__teacher=teacher, 
        is_active=True
    ).order_by('joined_at').values_list('student__id', flat=True)[:limit]

    # هل الطالب الحالي ضمن المحظوظين؟
    if user.student_profile.id not in allowed_students_ids:
        # الطالب زائد عن الحد (رقم 1001)
        return group, "limit_exceeded"
    
    # +++++ فحص جديد: هل المجموعة مسموحة للمعلم؟ +++++
    allowed_ids = group.teacher.get_allowed_group_ids()
    if group.id not in allowed_ids:
        return group, "group_locked_by_plan" # حالة جديدة
    # ++++++++++++++++++++++++++++++++++++++++++++++
    

    return group, "ok"


def calculate_leaderboard(group):
    return get_optimized_group_leaderboard(group)


# دالة حساب ترتيب الحزمة
def get_package_leaderboard(package):
    enrollments = package.enrollments.filter(is_paid=True)
    leaderboard = []

    for enroll in enrollments:
        student = enroll.student
        total_score = 0
        
        # 1. نقاط الفيديوهات
        video_points = VideoViewTracking.objects.filter(
            student=student, package=package
        ).aggregate(sum=models.Sum('points_awarded'))['sum'] or 0
        
        # 2. درجات الامتحانات (داخل هذه الحزمة فقط)
        # نحتاج لتصفية النتائج للامتحانات الموجودة في الحزمة
        exam_points = ExamResult.objects.filter(
            student=student, 
            exam__in=package.exams.all()
        ).aggregate(sum=models.Sum('score'))['sum'] or 0
        
        total_score = video_points + exam_points
        
        leaderboard.append({'student': student, 'score': total_score})

    # ترتيب
    leaderboard.sort(key=lambda x: x['score'], reverse=True)
    return leaderboard

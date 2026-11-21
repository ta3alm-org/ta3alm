"""teachers.views.permissions
Extracted from teachers/views.py.
"""

from assistants.models import AssistantJob
from django.shortcuts import get_object_or_404
from teachers.models import Group


# ==========================================
# دالة مساعدة للتحقق من الصلاحيات (معلم أو مساعد)
# ==========================================
def get_group_permission(request, group_id, permission_type=None):
    """
    تتحقق هل المستخدم هو مالك المجموعة، أو مساعد لديه الصلاحية المطلوبة.
    ترجع: (Group Object, is_owner Boolean)
    """
    group = get_object_or_404(Group, id=group_id)
    user = request.user

    # فحص الحد (حتى للمالك والمساعد)
    allowed_ids = group.teacher.get_allowed_group_ids()
    if group.id not in allowed_ids:
        return None, False # نمنع الدخول تماماً


    # 1. المالك (المعلم المعتمد)
    if group.teacher.user == user:
        if not group.teacher.is_approved:
            return None, False
        if not user.phone or len(user.phone.strip()) < 11 or not group.teacher.image:
            return None, False
        return group, True

    # 2. المساعد
    if user.role == 'assistant':
        job = AssistantJob.objects.filter(
            assistant__user=user, 
            teacher=group.teacher, 
            is_active=True
        ).first()
        
        if job:
            # التحقق من الصلاحيات
            if permission_type == 'students' and job.can_manage_students:
                return group, False
            elif permission_type == 'exams' and job.can_manage_exams:
                return group, False
            elif permission_type == 'videos' and job.can_manage_videos:
                return group, False
            elif permission_type is None: # دخول عام
                return group, False

    return None, False


def get_package_permission(request, package_id, permission_type=None):
    from teachers.models import CoursePackage
    package = get_object_or_404(CoursePackage, id=package_id)
    user = request.user

    # 1. المالك (المعلم المعتمد)
    if package.teacher.user == user:
        if not package.teacher.is_approved:
            return None, False
        if not user.phone or len(user.phone.strip()) < 11 or not package.teacher.image:
            return None, False
        return package, True

    # 2. المساعد
    if user.role == 'assistant':
        job = AssistantJob.objects.filter(
            assistant__user=user, 
            teacher=package.teacher, 
            is_active=True
        ).first()
        
        if job:
            if permission_type == 'videos' and job.can_manage_videos:
                return package, False
            elif permission_type == 'exams' and job.can_manage_exams:
                return package, False
            elif permission_type is None:
                return package, False

    return None, False

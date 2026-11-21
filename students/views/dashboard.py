"""students.views.dashboard
Extracted from students/views.py.
"""

from django.shortcuts import (
    render,
    redirect,
    get_object_or_404,
)
from django.contrib.auth.decorators import login_required
from django.contrib import messages
from django.db.models import Q
from teachers.models import Group
from students.models import Enrollment
from accounts.models import StudentProfile
from core.models import Subject
from students.models import PackageEnrollment
from teachers.models import CoursePackage

from students.views.access import _clear_student_web_watch_state


# 1. لوحة تحكم الطالب (سنعرض فيها المجموعات المشترك بها)
@login_required
def student_dashboard(request):
    if request.user.role != 'student':
        return redirect('home')

    _clear_student_web_watch_state(request)
    try:
        student = request.user.student_profile
    except StudentProfile.DoesNotExist:
        return redirect('complete_profile')

    # جلب المجموعات مع البيانات المرتبطة لتجنب N+1 Queries
    enrollments = (
        student.enrollments
        .filter(is_active=True)
        .select_related('group__teacher__current_plan', 'group__teacher__user')
    )
    pending_groups = student.enrollments.filter(is_active=False).select_related('group__teacher__user')
    my_packages = PackageEnrollment.objects.filter(student=student, is_paid=True).select_related('package')

    # التحقق من حالة كل مجموعة (بناءً على باقة المعلم)
    active_enrollments = []
    locked_enrollments = []

    for enroll in enrollments:
        teacher = enroll.group.teacher
        allowed_ids = list(teacher.get_allowed_group_ids())
        if enroll.group.id in allowed_ids:
            active_enrollments.append(enroll)
        else:
            locked_enrollments.append(enroll)

    context = {
        'my_groups': active_enrollments,       # المجموعات النشطة والمسموح بها
        'locked_groups': locked_enrollments,   # المجموعات المقيّدة (تجاوز حد الباقة)
        'pending_groups': pending_groups,      # طلبات الانتظار
        'my_packages': my_packages,
    }

    return render(request, 'students/dashboard.html', context)


def list_packages(request):
    # نعرض فقط الحزم التي يملك معلموها صلاحية "أونلاين" في باقتهم الحالية ومعتمدون من الإدارة
    packages = CoursePackage.objects.filter(
        is_active=True,
        teacher__is_approved=True,
        teacher__user__is_banned=False,
        teacher__current_plan__allow_online_packages=True
    ).order_by('-created_at')
    
    return render(request, 'students/list_packages.html', {'packages': packages})


# 2. صفحة البحث عن مجموعات جديدة (متاحة للزوار والطلاب)
def search_groups(request):
    # 1. التعريف الأولي (الأساسي)
    # نضمن أن المتغير groups موجود دائماً حتى لو لم يدخل في أي if
    groups = (
        Group.objects
        .select_related('teacher__user', 'teacher__subject')
        .filter(teacher__is_approved=True, teacher__user__is_banned=False)
        .order_by('-created_at')
    )
    
    query = request.GET.get('q')
    grade = request.GET.get('grade')
    subject_id = request.GET.get('subject')

    # 2. الفلاتر (تعديل المتغير الموجود)
    if query:
        groups = groups.filter(
            Q(name__icontains=query) | 
            Q(teacher__user__first_name__icontains=query) |
            Q(teacher__user__last_name__icontains=query) |
            # لاحظ: teacher__subject__name لأن subject أصبح ForeignKey
            Q(teacher__subject__name__icontains=query)
        )
    
    if grade:
        groups = groups.filter(grade=grade)
        
    if subject_id:
        groups = groups.filter(teacher__subject__id=subject_id)

    # 3. بيانات الطالب (لزر الانضمام)
    my_enrollment_ids = []
    if request.user.is_authenticated and getattr(request.user, 'role', '') == 'student':
        try:
            student = request.user.student_profile
            my_enrollment_ids = student.enrollments.values_list('group_id', flat=True)
        except Exception:
            pass

    # 4. قائمة المواد للفلتر
    subjects = Subject.objects.all()

    context = {
        'groups': groups, # الآن هو موجود ومفلتر
        'my_enrollment_ids': my_enrollment_ids,
        'query': query,
        'subjects': subjects
    }
    return render(request, 'students/search.html', context)


# 3. إرسال طلب انضمام
@login_required
def join_group(request, group_id):
    if not hasattr(request.user, 'student_profile'):
        return redirect('home')
    student = request.user.student_profile
    group = get_object_or_404(Group, id=group_id)
    teacher = group.teacher
    if not teacher.is_approved or teacher.user.is_banned:
        messages.error(request, "هذا المعلم غير متاح للانضمام حالياً.")
        return redirect('search_groups')
    current_count = teacher.get_total_students()
    limit = teacher.get_student_limit()

    # التأكد أنه لم ينضم سابقاً (سواء مقبول أو انتظار)
    existing = Enrollment.objects.filter(student=student, group=group).exists()
    if current_count >= limit:
        messages.error(request, "عفواً، لا يمكن الانضمام. لقد وصل المعلم للحد الأقصى من الطلاب.")
        return redirect('student_dashboard')
    if not existing:
        Enrollment.objects.create(student=student, group=group, is_active=False)
        messages.success(request, f"تم إرسال طلب الانضمام لمجموعة '{group.name}' بنجاح، في انتظار موافقة المعلم.")
    else:
        messages.warning(request, "أنت بالفعل عضو في هذه المجموعة أو الطلب قيد الانتظار.")
        
    return redirect('student_dashboard')


@login_required
def student_settings(request):
    if request.user.role != 'student': return redirect('home')
    return render(request, 'students/settings.html', {'student': request.user})

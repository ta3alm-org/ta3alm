"""teachers.views.dashboard
Extracted from teachers/views.py.
"""

from core.notifications_service import maybe_notify_teacher_subscription_expiry
from django.shortcuts import (
    render,
    redirect,
)
from django.contrib.auth.decorators import login_required
from django.contrib import messages
from teachers.models import TeacherProfile
from teachers.forms import GroupForm


# ==========================================
# 1. لوحة تحكم المعلم (Dashboard)
# ==========================================
@login_required
def teacher_dashboard(request):
    if request.user.role != 'teacher':
        return redirect('home')
    try:
        teacher = request.user.teacher_profile
    except TeacherProfile.DoesNotExist:
        return redirect('complete_profile')

    if not teacher.is_approved:
        return render(request, 'teachers/pending_approval.html', {'teacher': teacher})
    
    if request.method == 'POST':
        # التحقق من الحد الأقصى للمجموعات
        current_groups = teacher.groups.count()
        limit = teacher.current_plan.group_limit if teacher.current_plan else 5
        
        if current_groups >= limit:
            messages.error(request, f"لقد وصلت للحد الأقصى من المجموعات ({limit}). يرجى ترقية الباقة.")
            return redirect('teacher_dashboard')

        # ... (باقي كود الإنشاء) ...
        form = GroupForm(request.POST)
        if form.is_valid():
            new_group = form.save(commit=False)
            new_group.teacher = teacher
            new_group.save()
            messages.success(request, f"تم إنشاء مجموعة '{new_group.name}' بنجاح!")
            return redirect('teacher_dashboard')
    else:
        form = GroupForm()

    # جلب المجموعات
    groups = teacher.groups.all().order_by('created_at')
    allowed_ids = list(teacher.get_allowed_group_ids()) # قائمة المسموح

    # معلومات الاشتراك
    days_left = teacher.days_remaining()
    is_active = teacher.has_active_subscription()
    maybe_notify_teacher_subscription_expiry(teacher)

        # ++++++ كود البحث (جديد) ++++++
    query = request.GET.get('q')
    if query:
        groups = groups.filter(name__icontains=query)
    # ++++++++++++++++++++++++++++++


    context = {
        'groups': groups,
        'form': form,
        'days_left': days_left,
        'is_active': is_active,
        'subscription_end': teacher.subscription_end_date,
        'allowed_ids': allowed_ids,
    }
    return render(request, 'teachers/dashboard.html', context)

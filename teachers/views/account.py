"""teachers.views.account
Extracted from teachers/views.py.
"""

from assistants.models import AssistantJob
from django.shortcuts import (
    render,
    redirect,
    get_object_or_404,
)
from django.contrib.auth.decorators import login_required
from django.contrib import messages
from teachers.forms import TeacherSettingsForm
from assistants.forms import AssistantPermissionsForm
from teachers.models import SubscriptionPlan


# ==========================================
# 4. إعدادات المعلم (Settings)
# ==========================================
@login_required
def teacher_settings(request):
    try: teacher = request.user.teacher_profile
    except: return redirect('home')
    
    if request.method == 'POST':
        form = TeacherSettingsForm(request.POST, request.FILES, instance=teacher)
        if form.is_valid():
            form.save()
            request.user.first_name = form.cleaned_data['first_name']
            request.user.last_name = form.cleaned_data['last_name']
            request.user.save()
            messages.success(request, "تم تحديث البيانات.")
            return redirect('teacher_settings')
    else:
        form = TeacherSettingsForm(instance=teacher, initial={'first_name': request.user.first_name, 'last_name': request.user.last_name})
    return render(request, 'teachers/settings.html', {'form': form})


@login_required
def delete_teacher_account(request):
    if request.method == 'POST' and request.user.role == 'teacher':
        request.user.delete()
        messages.info(request, "تم حذف حسابك.")
        return redirect('home')
    return redirect('teacher_settings')


# ==========================================
# 5. إدارة المساعدين (Manage Assistants)
# ==========================================
@login_required
def manage_assistants(request):
    try: teacher = request.user.teacher_profile
    except: return redirect('home')

    if request.method == 'POST':
        job_id = request.POST.get('job_id')
        action = request.POST.get('action')
        job = get_object_or_404(AssistantJob, id=job_id, teacher=teacher)
        
        if action == 'accept':
            # التحقق من عدد المساعدين الحاليين
            current_assistants = teacher.assistants_jobs.filter(is_active=True).count()
            limit = teacher.current_plan.assistant_limit if teacher.current_plan else 2
            
            if current_assistants >= limit:
                messages.error(request, f"لا يمكن قبول المزيد. حد باقتك {limit} مساعدين.")
            else:
                job.is_active = True
                job.save()
                messages.success(request, "تم قبول المساعد.")    

        elif action in ['reject', 'delete']:
            job.delete(); messages.warning(request, "تم الحذف.")
            
        elif action == 'update_permissions':
            form = AssistantPermissionsForm(request.POST, instance=job)
            if form.is_valid(): form.save(); messages.success(request, "تم تحديث الصلاحيات.")
        
        return redirect('manage_assistants')

    active = teacher.assistants_jobs.filter(is_active=True).select_related('assistant__user')
    pending = teacher.assistants_jobs.filter(is_active=False).select_related('assistant__user')
    permissions_form = AssistantPermissionsForm() # للعرض فقط

    return render(request, 'teachers/manage_assistants.html', {
        'active_assistants': active, 'pending_requests': pending, 'permissions_form': permissions_form
    })


# ==========================================
# 6. المدفوعات والاشتراك (Paymob)
# ==========================================
@login_required
def subscription_info(request):
    try: teacher = request.user.teacher_profile
    except: return redirect('home')
    plans = SubscriptionPlan.objects.all().order_by('price')
    return render(request, 'teachers/subscription.html', {'teacher': teacher, 'is_active': teacher.has_active_subscription(), 'days_left': teacher.days_remaining(),'plans':plans})

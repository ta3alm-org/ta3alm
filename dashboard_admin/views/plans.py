"""dashboard_admin.views.plans
Extracted from dashboard_admin/views.py.
"""

from django.shortcuts import (
    render,
    redirect,
    get_object_or_404,
)
from django.contrib import messages
from teachers.models import SubscriptionPlan
from dashboard_admin.models import AuditLog
from dashboard_admin.decorators import owner_required

from dashboard_admin.views.base import _base_context


# ==========================================================
# 9. إدارة باقات الاشتراك
# ==========================================================
@owner_required
def manage_plans(request):
    ctx = _base_context(request)
    plans = SubscriptionPlan.objects.all()

    if request.method == 'POST':
        action = request.POST.get('action')

        def clean_int(val, default=0):
            try:
                return int(val)
            except (ValueError, TypeError):
                return default

        if action == 'add':
            plan = SubscriptionPlan.objects.create(
                name=request.POST.get('name', ''),
                price=clean_int(request.POST.get('price')),
                description=request.POST.get('desc', ''),
                student_limit=clean_int(request.POST.get('student_limit'), 1000),
                group_limit=clean_int(request.POST.get('group_limit'), 5),
                assistant_limit=clean_int(request.POST.get('assistant_limit'), 2),
                allow_online_packages=(request.POST.get('allow_online') == 'on'),
                allow_question_images=(request.POST.get('allow_images') == 'on'),
                is_default=(request.POST.get('is_default') == 'on'),
            )
            AuditLog.log(request, AuditLog.ACTION_ADD_PLAN,
                         target_label=plan.name, target_id=plan.id)
            messages.success(request, "تم إضافة الباقة.")

        elif action == 'edit':
            plan = get_object_or_404(SubscriptionPlan, id=request.POST.get('plan_id'))
            plan.name           = request.POST.get('name', '')
            plan.price          = clean_int(request.POST.get('price'))
            plan.description    = request.POST.get('desc', '')
            plan.student_limit  = clean_int(request.POST.get('student_limit'), 1000)
            plan.group_limit    = clean_int(request.POST.get('group_limit'), 5)
            plan.assistant_limit = clean_int(request.POST.get('assistant_limit'), 2)
            plan.allow_online_packages = (request.POST.get('allow_online') == 'on')
            plan.allow_question_images = (request.POST.get('allow_images') == 'on')
            plan.is_default     = (request.POST.get('is_default') == 'on')
            plan.save()
            AuditLog.log(request, AuditLog.ACTION_EDIT_PLAN,
                         target_label=plan.name, target_id=plan.id)
            messages.success(request, "تم تعديل الباقة.")

        elif action == 'delete':
            plan = get_object_or_404(SubscriptionPlan, id=request.POST.get('plan_id'))
            name = plan.name
            AuditLog.log(request, AuditLog.ACTION_DELETE_PLAN,
                         target_label=name, target_id=plan.id)
            plan.delete()
            messages.warning(request, f"تم حذف الباقة «{name}».")

        return redirect('admin_panel:manage_plans')

    ctx['plans'] = plans
    return render(request, 'admin_panel/manage_plans.html', ctx)

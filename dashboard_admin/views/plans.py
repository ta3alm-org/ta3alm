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

from django.template.loader import render_to_string

from dashboard_admin.views.base import _base_context
from dashboard_admin.views.ajax import (
    ajax_error,
    ajax_success,
    is_ajax_request,
)


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

        def is_checked(field_name):
            return request.POST.get(field_name) in ('on', '1', 'true', 'yes')

        msg = ''
        if action == 'add':
            name = (request.POST.get('name') or '').strip()
            if not name:
                err_msg = "يرجى إدخال اسم الباقة."
                if is_ajax_request(request):
                    return ajax_error(err_msg, errors={'name': [err_msg]}, status=400)
                messages.error(request, err_msg)
                return redirect('admin_panel:manage_plans')

            plan = SubscriptionPlan.objects.create(
                name=name,
                price=clean_int(request.POST.get('price')),
                description=request.POST.get('desc', ''),
                student_limit=clean_int(request.POST.get('student_limit'), 1000),
                group_limit=clean_int(request.POST.get('group_limit'), 5),
                assistant_limit=clean_int(request.POST.get('assistant_limit'), 2),
                allow_online_packages=is_checked('allow_online'),
                allow_question_images=is_checked('allow_images'),
                is_default=is_checked('is_default'),
            )
            AuditLog.log(request, AuditLog.ACTION_ADD_PLAN,
                         target_label=plan.name, target_id=plan.id)
            msg = "تم إضافة الباقة."
            if not is_ajax_request(request):
                messages.success(request, msg)

        elif action == 'edit':
            plan = get_object_or_404(SubscriptionPlan, id=request.POST.get('plan_id'))
            name = (request.POST.get('name') or '').strip()
            if not name:
                err_msg = "يرجى إدخال اسم الباقة."
                if is_ajax_request(request):
                    return ajax_error(err_msg, errors={'name': [err_msg]}, status=400)
                messages.error(request, err_msg)
                return redirect('admin_panel:manage_plans')

            plan.name           = name
            plan.price          = clean_int(request.POST.get('price'))
            plan.description    = request.POST.get('desc', '')
            plan.student_limit  = clean_int(request.POST.get('student_limit'), 1000)
            plan.group_limit    = clean_int(request.POST.get('group_limit'), 5)
            plan.assistant_limit = clean_int(request.POST.get('assistant_limit'), 2)
            plan.allow_online_packages = is_checked('allow_online')
            plan.allow_question_images = is_checked('allow_images')
            plan.is_default     = is_checked('is_default')
            plan.save()
            AuditLog.log(request, AuditLog.ACTION_EDIT_PLAN,
                         target_label=plan.name, target_id=plan.id)
            msg = "تم تعديل الباقة."
            if not is_ajax_request(request):
                messages.success(request, msg)

        elif action == 'delete':
            plan = get_object_or_404(SubscriptionPlan, id=request.POST.get('plan_id'))
            name = plan.name
            AuditLog.log(request, AuditLog.ACTION_DELETE_PLAN,
                         target_label=name, target_id=plan.id)
            plan.delete()
            msg = f"تم حذف الباقة «{name}»."
            if not is_ajax_request(request):
                messages.warning(request, msg)

        else:
            if is_ajax_request(request):
                return ajax_error("إجراء غير معروف.", status=400)

        if is_ajax_request(request):
            updated_plans = SubscriptionPlan.objects.all()
            grid_html = render_to_string(
                'admin_panel/partials/_plans_grid.html',
                {'plans': updated_plans},
                request=request,
            )
            return ajax_success(
                msg,
                data={
                    'action': action,
                    'plans_count': updated_plans.count(),
                    'grid_html': grid_html,
                },
            )

        return redirect('admin_panel:manage_plans')

    ctx['plans'] = plans
    return render(request, 'admin_panel/manage_plans.html', ctx)

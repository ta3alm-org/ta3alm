"""dashboard_admin.views.curriculum
Extracted from dashboard_admin/views.py.
"""

from django.shortcuts import (
    render,
    redirect,
    get_object_or_404,
)
from django.contrib import messages
from dashboard_admin.decorators import owner_required
from core.models import CurriculumUnit
from dashboard_admin.forms import (
    CurriculumUnitForm,
    CurriculumLessonFormSet,
)

from django.db import transaction
from django.urls import reverse

from dashboard_admin.views.base import _base_context
from dashboard_admin.views.ajax import (
    ajax_error,
    ajax_success,
    form_errors_dict,
    formset_errors_list,
    is_ajax_request,
)


@owner_required
def manage_curriculum(request):
    ctx = _base_context(request)
    units = CurriculumUnit.objects.select_related('subject').prefetch_related('lessons').order_by('grade', 'term', 'subject', 'order')
    ctx['units'] = units
    return render(request, 'admin_panel/curriculum_list.html', ctx)


@owner_required
def curriculum_unit_create(request):
    ctx = _base_context(request)
    if request.method == 'POST':
        form = CurriculumUnitForm(request.POST)
        if form.is_valid():
            with transaction.atomic():
                sid = transaction.savepoint()
                unit = form.save()
                formset = CurriculumLessonFormSet(request.POST, instance=unit)
                if formset.is_valid():
                    formset.save()
                    msg = "تم إضافة الوحدة ودروسها بنجاح."
                    if is_ajax_request(request):
                        return ajax_success(
                            msg,
                            data={
                                'unit_id': unit.id,
                                'redirect_url': reverse('admin_panel:manage_curriculum'),
                            },
                        )
                    messages.success(request, msg)
                    return redirect('admin_panel:manage_curriculum')
                transaction.savepoint_rollback(sid)
        else:
            formset = CurriculumLessonFormSet(request.POST)

        if is_ajax_request(request):
            merged = form_errors_dict(form)
            fs_msgs, fs_errs = formset_errors_list(formset)
            merged.update(fs_errs)
            err_msg = fs_msgs[0] if fs_msgs else "يرجى مراجعة الحقول المطلوبة."
            return ajax_error(err_msg, errors=merged, status=400)
    else:
        form = CurriculumUnitForm()
        formset = CurriculumLessonFormSet()
    
    ctx['form'] = form
    ctx['formset'] = formset
    ctx['is_edit'] = False
    return render(request, 'admin_panel/curriculum_form.html', ctx)


@owner_required
def curriculum_unit_edit(request, unit_id):
    ctx = _base_context(request)
    unit = get_object_or_404(CurriculumUnit, id=unit_id)
    if request.method == 'POST':
        form = CurriculumUnitForm(request.POST, instance=unit)
        formset = CurriculumLessonFormSet(request.POST, instance=unit)
        if form.is_valid() and formset.is_valid():
            form.save()
            formset.save()
            msg = "تم تعديل الوحدة ودروسها بنجاح."
            if is_ajax_request(request):
                return ajax_success(
                    msg,
                    data={
                        'unit_id': unit.id,
                        'redirect_url': reverse('admin_panel:manage_curriculum'),
                    },
                )
            messages.success(request, msg)
            return redirect('admin_panel:manage_curriculum')

        if is_ajax_request(request):
            merged = form_errors_dict(form)
            fs_msgs, fs_errs = formset_errors_list(formset)
            merged.update(fs_errs)
            err_msg = fs_msgs[0] if fs_msgs else "يرجى مراجعة الحقول المطلوبة."
            return ajax_error(err_msg, errors=merged, status=400)
    else:
        form = CurriculumUnitForm(instance=unit)
        formset = CurriculumLessonFormSet(instance=unit)
    
    ctx['form'] = form
    ctx['formset'] = formset
    ctx['is_edit'] = True
    ctx['unit'] = unit
    return render(request, 'admin_panel/curriculum_form.html', ctx)


@owner_required
def curriculum_unit_delete(request, unit_id):
    if request.method == 'POST':
        unit = get_object_or_404(CurriculumUnit, id=unit_id)
        unit.delete()
        msg = "تم حذف الوحدة بجميع دروسها بنجاح."
        if is_ajax_request(request):
            return ajax_success(msg, data={'unit_id': unit_id, 'deleted': True})
        messages.success(request, msg)
    elif is_ajax_request(request):
        return ajax_error("طريقة الطلب غير مدعومة.", status=405)
    return redirect('admin_panel:manage_curriculum')

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

from dashboard_admin.views.base import _base_context


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
            unit = form.save()
            formset = CurriculumLessonFormSet(request.POST, instance=unit)
            if formset.is_valid():
                formset.save()
                messages.success(request, "تم إضافة الوحدة ودروسها بنجاح.")
                return redirect('admin_panel:manage_curriculum')
        else:
            formset = CurriculumLessonFormSet(request.POST)
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
            messages.success(request, "تم تعديل الوحدة ودروسها بنجاح.")
            return redirect('admin_panel:manage_curriculum')
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
        messages.success(request, "تم حذف الوحدة بجميع دروسها بنجاح.")
    return redirect('admin_panel:manage_curriculum')

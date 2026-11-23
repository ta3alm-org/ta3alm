"""teachers.views.files
Extracted from teachers/views.py.
"""

import os
import uuid
from django.core.files.storage import default_storage
from django.db import DataError
from assistants.models import AssistantJob
from django.shortcuts import (
    render,
    redirect,
    get_object_or_404,
)
from django.contrib.auth.decorators import login_required
from django.contrib import messages
from teachers.models import PDFFile
from django.urls import reverse
from teachers.models import CoursePackage
from django.utils.http import url_has_allowed_host_and_scheme

from teachers.views.permissions import (
    get_group_permission,
    get_package_permission,
)


def _safe_referer_redirect(request, fallback_url):
    """يتحقق من أمان رابط العودة (HTTP_REFERER) لمنع الثغرات الأمنية للإعادة التوجيه المفتوح."""
    referer = (request.META.get('HTTP_REFERER') or '').strip()
    if referer and url_has_allowed_host_and_scheme(
        referer,
        allowed_hosts={request.get_host()},
        require_https=request.is_secure(),
    ):
        return redirect(referer)
    return redirect(fallback_url)


def _resolve_pdf_link_from_request(request):
    uploaded_file = request.FILES.get('file')
    link = (request.POST.get('link') or '').strip()
    if uploaded_file:
        ext = os.path.splitext(uploaded_file.name)[1].lower() or '.pdf'
        if ext not in ('.pdf', '.doc', '.docx', '.ppt', '.pptx'):
            return None, "نوع الملف غير مدعوم. يُسمح بملفات PDF والمستندات فقط."
        saved_path = default_storage.save(f"pdfs/{uuid.uuid4().hex[:16]}{ext}", uploaded_file)
        return default_storage.url(saved_path), None
    if link:
        return link, None
    return None, "يرجى اختيار ملف PDF أو إدخال رابط الملف."


@login_required
def add_pdf_to_group(request, group_id):
    group, is_owner = get_group_permission(request, group_id, permission_type='videos')
    if not group:
        return redirect('home')

    if request.method == 'POST':
        title = (request.POST.get('title') or '').strip()
        resolved_link, err = _resolve_pdf_link_from_request(request)
        if not title:
            messages.error(request, "يرجى إدخال اسم الملف.")
        elif len(title) > 200:
            messages.error(request, "اسم الملف طويل جداً (الحد الأقصى 200 حرف).")
        elif err:
            messages.error(request, err)
        elif len(resolved_link) > 2000:
            messages.error(request, "رابط الملف طويل جداً (الحد الأقصى 2000 حرف).")
        else:
            try:
                PDFFile.objects.create(group=group, title=title, link=resolved_link)
                messages.success(request, "تم إضافة الملف.")
            except DataError:
                messages.error(request, "رابط الملف أو اسمه أطول من الحد المسموح به في قاعدة البيانات حالياً.")
    return _safe_referer_redirect(request, reverse('group_detail', args=[group.id]))


# 2. إضافة للحزمة (يدوي)
@login_required
def add_pdf_to_package(request, package_id):
    package, is_owner = get_package_permission(request, package_id, permission_type='videos')
    if not package:
        return redirect('home')

    if request.method == 'POST':
        title = (request.POST.get('title') or '').strip()
        resolved_link, err = _resolve_pdf_link_from_request(request)
        if not title:
            messages.error(request, "يرجى إدخال اسم الملف.")
        elif len(title) > 200:
            messages.error(request, "اسم الملف طويل جداً (الحد الأقصى 200 حرف).")
        elif err:
            messages.error(request, err)
        elif len(resolved_link) > 2000:
            messages.error(request, "رابط الملف طويل جداً (الحد الأقصى 2000 حرف).")
        else:
            try:
                pdf = PDFFile.objects.create(group=None, title=title, link=resolved_link)
                package.pdfs.add(pdf)
                messages.success(request, "تم إضافة الملف للحزمة.")
            except DataError:
                messages.error(request, "رابط الملف أو اسمه أطول من الحد المسموح به في قاعدة البيانات حالياً.")
    return _safe_referer_redirect(request, reverse('teacher_package_detail', args=[package.id]))


# 3. حذف PDF
@login_required
def delete_pdf(request, pdf_id):
    pdf = get_object_or_404(PDFFile, id=pdf_id)
    if pdf.group:
        group, is_owner = get_group_permission(request, pdf.group.id, permission_type='videos')
        if not group: return redirect('home')
    else:
        pkg = pdf.packages.first()
        if pkg:
            package, is_owner = get_package_permission(request, pkg.id, permission_type='videos')
            if not package: return redirect('home')
        else:
            return redirect('home')
    
    # تحديد مكان العودة
    redirect_url = 'home'
    if pdf.group:
        redirect_url = reverse('group_detail', args=[pdf.group.id])
    else:
        pkg = pdf.packages.first()
        if pkg: redirect_url = reverse('teacher_package_detail', args=[pkg.id])
    
    pdf.delete()
    messages.success(request, "تم الحذف.")
    return redirect(redirect_url)


# ==========================================
# صفحة ملفات المجموعة (للمعلم)
# ==========================================
@login_required
def group_files_teacher(request, group_id):
    group, is_owner = get_group_permission(request, group_id, permission_type='videos')
    if not group: return redirect('home')
    
    if not is_owner and not group.teacher.has_active_subscription():
        return render(request, 'students/teacher_unavailable.html', {'teacher_name': group.teacher.user.first_name})

    pending_count = group.enrollments.filter(is_active=False).count()

    return render(request, 'teachers/group_files.html', {
        'group': group,
        'active_tab': 'files',
        'is_owner': is_owner,
        'pending_count': pending_count
    })


# ==========================================
# صفحة ملفات الحزمة (للمعلم)
# ==========================================
@login_required
def package_files_teacher(request, package_id):
    package = get_object_or_404(CoursePackage, id=package_id)
    
    # التحقق من الملكية
    is_owner = False
    if package.teacher.user == request.user:
        is_owner = True
    elif request.user.role == 'assistant':
        job = AssistantJob.objects.filter(assistant__user=request.user, teacher=package.teacher, is_active=True).first()
        if job and job.can_manage_packages:
            is_owner = False
        else:
            return redirect('home')
    else:
        return redirect('home')

    return render(request, 'teachers/package_dashboard/files.html', {
        'package': package,
        'active_tab': 'files',
        'is_owner': is_owner
    })

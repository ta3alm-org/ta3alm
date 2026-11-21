"""dashboard_admin.views.staff
Extracted from dashboard_admin/views.py.
"""

from django.shortcuts import (
    render,
    redirect,
    get_object_or_404,
)
from django.contrib import messages
from django.contrib.auth import get_user_model
from dashboard_admin.models import (
    AdminProfile,
    AdminRole,
    AuditLog,
)
from dashboard_admin.decorators import owner_required
from dashboard_admin.forms import (
    AppointAdminForm,
    CreateAdminForm,
)

from dashboard_admin.views.base import _base_context

User = get_user_model()


# ==========================================================
# 11. إدارة فريق الإدارة (Staff Management)
# ==========================================================
@owner_required
def manage_staff(request):
    ctx = _base_context(request)

    staff_list = AdminProfile.objects.select_related('user', 'appointed_by').order_by('admin_role')

    if request.method == 'POST':
        action = request.POST.get('action')

        if action == 'create':
            form = CreateAdminForm(request.POST)
            if form.is_valid():
                email      = form.cleaned_data['email']
                first_name = form.cleaned_data['first_name']
                last_name  = form.cleaned_data['last_name']
                password   = form.cleaned_data['password']
                admin_role = form.cleaned_data['admin_role']

                target = User.objects.create_user(
                    username=email,
                    email=email,
                    password=password,
                    first_name=first_name,
                    last_name=last_name,
                    role='admin',
                    is_staff=True,
                    is_superuser=(admin_role == 'owner'),
                )
                AdminProfile.objects.create(
                    user=target,
                    admin_role=admin_role,
                    notes=form.cleaned_data.get('notes', ''),
                    is_active_admin=True,
                    appointed_by=request.user,
                )
                AuditLog.log(request, AuditLog.ACTION_APPOINT_ADMIN,
                             target_label=target.get_full_name() or email,
                             target_id=target.id,
                             details={'role': admin_role, 'created_new': True})
                messages.success(request, f"تم إنشاء حساب المسؤول {target.get_full_name()} بنجاح.")
            else:
                for field, errs in form.errors.items():
                    for err in errs:
                        messages.error(request, f"{err}")

        elif action == 'appoint':
            form = AppointAdminForm(request.POST)
            if form.is_valid():
                email = form.cleaned_data['user_email']
                try:
                    target = User.objects.get(email=email)
                    admin_role = form.cleaned_data['admin_role']
                    target.role = 'admin'
                    target.is_staff = True
                    if admin_role == 'owner':
                        target.is_superuser = True
                    target.save(update_fields=['role', 'is_staff', 'is_superuser'])
                    AdminProfile.objects.update_or_create(
                        user=target,
                        defaults={
                            'admin_role':      admin_role,
                            'notes':           form.cleaned_data.get('notes', ''),
                            'is_active_admin': True,
                            'appointed_by':    request.user,
                        }
                    )
                    AuditLog.log(request, AuditLog.ACTION_APPOINT_ADMIN,
                                 target_label=target.get_full_name() or email,
                                 target_id=target.id,
                                 details={'role': admin_role})
                    messages.success(request, f"تم تعيين {target.get_full_name() or email} كمسؤول.")
                except User.DoesNotExist:
                    messages.error(request, "لا يوجد مستخدم بهذا البريد الإلكتروني.")
            else:
                messages.error(request, "بيانات غير صحيحة.")

        elif action == 'remove':
            profile_id = request.POST.get('profile_id')
            profile = get_object_or_404(AdminProfile, id=profile_id)
            name = profile.user.get_full_name() or profile.user.email
            profile.user.role = 'student'   # إعادة لدور افتراضي محايد
            profile.user.is_staff = False
            profile.user.is_superuser = False
            profile.user.save(update_fields=['role', 'is_staff', 'is_superuser'])
            AuditLog.log(request, AuditLog.ACTION_REMOVE_ADMIN,
                         target_label=name, target_id=profile.user.id)
            profile.delete()
            messages.warning(request, f"تم إزالة {name} من الفريق الإداري.")

        return redirect('admin_panel:manage_staff')

    ctx.update({
        'staff_list':    staff_list,
        'appoint_form':  AppointAdminForm(),
        'create_form':   CreateAdminForm(),
        'admin_roles':   AdminRole.choices,
    })
    return render(request, 'admin_panel/manage_staff.html', ctx)

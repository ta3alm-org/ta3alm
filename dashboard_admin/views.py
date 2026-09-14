"""
dashboard_admin/views.py
لوحة تحكم الإدارة — منقولة من core وموسَّعة
"""
from django.shortcuts import render, redirect, get_object_or_404
from django.contrib import messages
from django.contrib.auth import get_user_model
from django.db.models import Sum, Count, Q
from django.utils import timezone
from datetime import timedelta

from teachers.models import TeacherProfile, PaymentTransaction, SubscriptionPlan, WithdrawRequest
from accounts.models import StudentProfile
from assistants.models import AssistantProfile
from students.models import PackageEnrollment
from core.models import SiteSetting

from .models import AdminProfile, AdminRole, AuditLog
from .decorators import admin_required, owner_required, finance_required, moderator_required
from .forms import (
    AdminUserEditForm, AdminTeacherEditForm,
    AdminStudentEditForm, AdminAssistantEditForm,
    AppointAdminForm, CreateAdminForm,
)

User = get_user_model()


# ----------------------------------------------------------
# مساعد: يُعيد context الـ sidebar الموحَّد
# ----------------------------------------------------------
def _base_context(request):
    """Context مشترك لكل صفحات الإدارة (sidebar + صلاحيات)."""
    user = request.user
    profile = getattr(user, 'admin_profile', None)

    # جلب عدد الإشعارات غير المقروءة
    from core.models import Notification
    unread_count = Notification.objects.filter(recipient=user, is_read=False).count()

    from core.models import SiteSetting
    site_settings = SiteSetting.load()

    zoho_connected = False
    try:
        from .models import ZohoMailConfig
        z_cfg = ZohoMailConfig.load()
        zoho_connected = z_cfg.is_connected()
    except Exception:
        pass

    return {
        'admin_user':         user,
        'admin_profile':      profile,
        'is_owner':           user.is_superuser or (profile and profile.is_owner),
        'can_manage_users':   user.is_superuser or (profile and profile.can_manage_users),
        'can_delete_users':   user.is_superuser or (profile and profile.can_delete_users),
        'can_view_finance':   user.is_superuser or (profile and profile.can_view_finance),
        'can_manage_plans':   user.is_superuser or (profile and profile.can_manage_plans),
        'can_view_audit':     user.is_superuser or (profile and profile.can_view_audit_log),
        'can_manage_support': user.is_superuser or (profile and (profile.is_owner or profile.can_manage_users or profile.admin_role == AdminRole.SUPPORT)),
        'unread_count':       unread_count,
        'site_settings':      site_settings,
        'zoho_connected':     zoho_connected,
    }



# ==========================================================
# 1. لوحة الإحصاءات الرئيسية (Dashboard)
# ==========================================================
@admin_required
def dashboard(request):
    ctx = _base_context(request)

    # إحصاءات
    ctx['total_teachers']   = TeacherProfile.objects.count()
    ctx['total_students']   = StudentProfile.objects.count()
    ctx['total_assistants'] = AssistantProfile.objects.count()

    # ✅ إصلاح N+1: استعلام واحد يستخدم filter بدلاً من Python loop
    ctx['active_teachers_count'] = TeacherProfile.objects.filter(
        subscription_end_date__gt=timezone.now()
    ).count()

    # آخر الأحداث
    ctx['recent_logs'] = AuditLog.objects.select_related('admin').order_by('-created_at')[:10]

    return render(request, 'admin_panel/dashboard.html', ctx)



# ==========================================================
# 2. تبديل وضع الصيانة
# ==========================================================
@owner_required
def toggle_maintenance(request):
    if request.method == 'POST':
        settings = SiteSetting.load()
        settings.is_maintenance_mode = not settings.is_maintenance_mode
        settings.save()
        status = "تفعيل" if settings.is_maintenance_mode else "إلغاء"
        AuditLog.log(request, AuditLog.ACTION_TOGGLE_MAINT,
                     details={'maintenance': settings.is_maintenance_mode})
        messages.warning(request, f"تم {status} وضع الصيانة.")
    return redirect('admin_panel:dashboard')



# ==========================================================
# 3. إدارة المستخدمين
# ==========================================================
@moderator_required
def manage_users(request):
    ctx = _base_context(request)

    query = request.GET.get('q', '').strip()
    role_filter = request.GET.get('role', '')

    teachers   = TeacherProfile.objects.select_related('user', 'current_plan').order_by('-id')
    students   = StudentProfile.objects.select_related('user').order_by('-id')
    assistants = AssistantProfile.objects.select_related('user').order_by('-id')

    if query:
        q_filter = (
            Q(user__first_name__icontains=query) |
            Q(user__last_name__icontains=query)  |
            Q(user__email__icontains=query)       |
            Q(user__phone__icontains=query)
        )
        teachers   = teachers.filter(q_filter)
        students   = students.filter(q_filter | Q(parent_phone__icontains=query))
        assistants = assistants.filter(q_filter | Q(phone__icontains=query))

    ctx.update({
        'teachers':    teachers,
        'students':    students,
        'assistants':  assistants,
        'all_plans':   SubscriptionPlan.objects.all(),
        'query':       query,
        'role_filter': role_filter,
    })
    return render(request, 'admin_panel/manage_users.html', ctx)


# ==========================================================
# 4. إجراءات على المستخدم (حظر / رفع / حذف / تجديد)
# ==========================================================
@moderator_required
def user_action(request):
    if request.method != 'POST':
        return redirect('admin_panel:manage_users')

    user_id = request.POST.get('user_id')
    action  = request.POST.get('action')

    try:
        target = User.objects.get(id=user_id)
    except User.DoesNotExist:
        messages.error(request, "المستخدم غير موجود.")
        return redirect('admin_panel:manage_users')

    # حماية: لا يُمسّ المالك أو الـ superuser
    if target.is_superuser:
        messages.error(request, "لا يمكن التأثير على حساب المالك.")
        return redirect('admin_panel:manage_users')

    # حماية: المشرف لا يستطيع حذف مستخدمين
    requester_profile = getattr(request.user, 'admin_profile', None)
    can_delete = request.user.is_superuser or (requester_profile and requester_profile.can_delete_users)

    if action == 'ban':
        target.is_banned = True
        target.save(update_fields=['is_banned'])
        AuditLog.log(request, AuditLog.ACTION_BAN,
                     target_label=f"{target.get_full_name()} ({target.email})",
                     target_id=target.id)
        messages.warning(request, f"تم حظر {target.get_full_name() or target.email}.")

    elif action == 'unban':
        target.is_banned = False
        target.save(update_fields=['is_banned'])
        AuditLog.log(request, AuditLog.ACTION_UNBAN,
                     target_label=f"{target.get_full_name()} ({target.email})",
                     target_id=target.id)
        messages.success(request, f"تم رفع الحظر عن {target.get_full_name() or target.email}.")

    elif action == 'delete':
        if not can_delete:
            messages.error(request, "ليس لديك صلاحية حذف المستخدمين.")
        else:
            name = target.get_full_name() or target.email
            AuditLog.log(request, AuditLog.ACTION_DELETE,
                         target_label=name, target_id=target.id,
                         details={'role': target.role, 'email': target.email})
            target.delete()
            messages.error(request, f"تم حذف المستخدم «{name}» وجميع بياناته نهائياً.")

    elif action == 'renew_free':
        if not hasattr(target, 'teacher_profile'):
            messages.error(request, "هذا المستخدم ليس معلماً.")
        else:
            teacher  = target.teacher_profile
            plan_id  = request.POST.get('plan_id')
            if plan_id:
                plan = get_object_or_404(SubscriptionPlan, id=plan_id)
                teacher.current_plan = plan

            teacher.subscription_end_date = (
                teacher.subscription_end_date + timedelta(days=30)
                if teacher.has_active_subscription()
                else timezone.now() + timedelta(days=30)
            )
            teacher.save()
            AuditLog.log(request, AuditLog.ACTION_RENEW_SUB,
                         target_label=target.get_full_name(),
                         target_id=target.id,
                         details={'plan': teacher.current_plan.name if teacher.current_plan else '-'})
            messages.success(request, f"تم تجديد اشتراك {target.get_full_name()}.")

    return redirect('admin_panel:manage_users')


# ==========================================================
# 5. تعديل بيانات مستخدم
# ==========================================================
@moderator_required
def edit_user(request, user_id):
    ctx = _base_context(request)
    target = get_object_or_404(User, id=user_id)

    teacher_form = student_form = assistant_form = None

    if request.method == 'POST':
        if 'generate_login_link' in request.POST:
            from accounts.models import OneTimeLoginLink
            link = OneTimeLoginLink.objects.create(user=target)
            login_url = request.build_absolute_uri('/login/auto/' + str(link.token) + '/')
            request.session['one_time_link'] = login_url
            return redirect('admin_panel:edit_user', user_id=target.id)
            
        if 'change_password' in request.POST:
            new_password = request.POST.get('new_password')
            if new_password:
                target.set_password(new_password)
                target.save()
                AuditLog.log(request, AuditLog.ACTION_EDIT_USER, target_label=f"تغيير كلمة مرور {target.get_full_name()}", target_id=target.id)
                messages.success(request, "تم تغيير كلمة المرور بنجاح.")
            else:
                messages.error(request, "يرجى إدخال كلمة مرور جديدة.")
            return redirect('admin_panel:edit_user', user_id=target.id)

        user_form = AdminUserEditForm(request.POST, instance=target)

        if target.role == 'teacher' and hasattr(target, 'teacher_profile'):
            teacher_form = AdminTeacherEditForm(request.POST, instance=target.teacher_profile)
            if user_form.is_valid() and teacher_form.is_valid():
                user_form.save()
                teacher_form.save()
                AuditLog.log(request, AuditLog.ACTION_EDIT_USER,
                             target_label=target.get_full_name(), target_id=target.id)
                messages.success(request, "تم تعديل بيانات المعلم.")
                return redirect('admin_panel:manage_users')

        elif target.role == 'student' and hasattr(target, 'student_profile'):
            student_form = AdminStudentEditForm(request.POST, instance=target.student_profile)
            if user_form.is_valid() and student_form.is_valid():
                user_form.save()
                student_form.save()
                AuditLog.log(request, AuditLog.ACTION_EDIT_USER,
                             target_label=target.get_full_name(), target_id=target.id)
                messages.success(request, "تم تعديل بيانات الطالب.")
                return redirect('admin_panel:manage_users')

        elif target.role == 'assistant' and hasattr(target, 'assistant_profile'):
            assistant_form = AdminAssistantEditForm(request.POST, instance=target.assistant_profile)
            if user_form.is_valid() and assistant_form.is_valid():
                user_form.save()
                assistant_form.save()
                AuditLog.log(request, AuditLog.ACTION_EDIT_USER,
                             target_label=target.get_full_name(), target_id=target.id)
                messages.success(request, "تم تعديل بيانات المساعد.")
                return redirect('admin_panel:manage_users')
        else:
            if user_form.is_valid():
                user_form.save()
                messages.success(request, "تم التعديل.")
                return redirect('admin_panel:manage_users')
    else:
        user_form = AdminUserEditForm(instance=target)
        if target.role == 'teacher' and hasattr(target, 'teacher_profile'):
            teacher_form = AdminTeacherEditForm(instance=target.teacher_profile)
        elif target.role == 'student' and hasattr(target, 'student_profile'):
            student_form = AdminStudentEditForm(instance=target.student_profile)
        elif target.role == 'assistant' and hasattr(target, 'assistant_profile'):
            assistant_form = AdminAssistantEditForm(instance=target.assistant_profile)

    ctx.update({
        'target_user':    target,
        'user_form':      user_form,
        'teacher_form':   teacher_form,
        'student_form':   student_form,
        'assistant_form': assistant_form,
        'one_time_link':  request.session.pop('one_time_link', None),
    })
    return render(request, 'admin_panel/edit_user.html', ctx)


# ==========================================================
# 6. التقارير المالية
# ==========================================================
@finance_required
def finance_report(request):
    ctx = _base_context(request)

    query = request.GET.get('q', '').strip()
    transactions = PaymentTransaction.objects.select_related('teacher__user').order_by('-date')

    if query:
        transactions = transactions.filter(
            Q(teacher__user__first_name__icontains=query) |
            Q(teacher__user__phone__icontains=query)       |
            Q(transaction_id__icontains=query)
        )

    total_revenue = transactions.aggregate(total=Sum('amount'))['total'] or 0

    ctx.update({
        'transactions': transactions,
        'total_revenue': total_revenue,
        'query': query,
    })
    return render(request, 'admin_panel/finance_report.html', ctx)


# ==========================================================
# 7. طلبات السحب
# ==========================================================
@finance_required
def withdrawals(request):
    ctx = _base_context(request)

    withdraw_requests = WithdrawRequest.objects.select_related(
        'wallet__teacher__user'
    ).order_by('-created_at')

    if request.method == 'POST':
        req_id = request.POST.get('req_id')
        req = get_object_or_404(WithdrawRequest, id=req_id)
        req.is_paid = True
        req.save()
        AuditLog.log(request, AuditLog.ACTION_PAY_WITHDRAW,
                     target_label=str(req), target_id=req.id,
                     details={'amount': str(req.amount)})
        messages.success(request, f"تم تسجيل تحويل {req.amount} EGP.")
        return redirect('admin_panel:withdrawals')

    ctx['requests'] = withdraw_requests
    return render(request, 'admin_panel/withdrawals.html', ctx)


# ==========================================================
# 8. مدفوعات الطلاب على الحزم
# ==========================================================
@finance_required
def student_payments(request):
    ctx = _base_context(request)

    payments = PackageEnrollment.objects.filter(
        is_paid=True
    ).select_related('student__user', 'package__teacher__user').order_by('-joined_at')

    # ✅ إصلاح N+1: aggregate بدلاً من sum في Python
    total_revenue = payments.aggregate(total=Sum('package__price'))['total'] or 0

    ctx.update({'payments': payments, 'total_revenue': total_revenue})
    return render(request, 'admin_panel/student_payments.html', ctx)


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


# ==========================================================
# 10. سجل الأحداث (Audit Log)
# ==========================================================
@owner_required
def audit_log(request):
    ctx = _base_context(request)

    logs = AuditLog.objects.select_related('admin').order_by('-created_at')

    action_filter = request.GET.get('action', '')
    if action_filter:
        logs = logs.filter(action=action_filter)

    ctx.update({
        'logs':           logs[:200],
        'action_choices': AuditLog.ACTION_CHOICES,
        'action_filter':  action_filter,
    })
    return render(request, 'admin_panel/audit_log.html', ctx)


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
            create_form = CreateAdminForm(request.POST)
            if create_form.is_valid():
                email = create_form.cleaned_data['email']
                password = create_form.cleaned_data['password']
                first_name = create_form.cleaned_data['first_name']
                last_name = create_form.cleaned_data['last_name']
                admin_role = create_form.cleaned_data['admin_role']
                
                if admin_role == 'owner' and not request.user.is_superuser:
                    messages.error(request, "عذراً، فقط السوبر يوزر يمكنه إنشاء مالك جديد.")
                    return redirect('admin_panel:manage_staff')

                target = User.objects.create_user(
                    username=email,
                    email=email,
                    password=password,
                    first_name=first_name,
                    last_name=last_name,
                    role='admin',
                    is_staff=True if admin_role == 'owner' else False,
                    is_superuser=True if admin_role == 'owner' else False,
                )
                
                AdminProfile.objects.create(
                    user=target,
                    admin_role=admin_role,
                    notes=create_form.cleaned_data.get('notes', ''),
                    is_active_admin=True,
                    appointed_by=request.user,
                )
                
                AuditLog.log(request, AuditLog.ACTION_APPOINT_ADMIN,
                             target_label=target.get_full_name() or email,
                             target_id=target.id,
                             details={'role': admin_role, 'type': 'create_new'})
                messages.success(request, f"تم إنشاء حساب المسؤول ({target.get_full_name()}) بنجاح.")
                return redirect('admin_panel:manage_staff')
            else:
                for field, errors in create_form.errors.items():
                    for error in errors:
                        messages.error(request, f"{field}: {error}")
                return redirect('admin_panel:manage_staff')

        if action == 'appoint':
            form = AppointAdminForm(request.POST)
            if form.is_valid():
                email = form.cleaned_data['user_email']
                try:
                    target = User.objects.get(email=email)
                    if target.is_superuser and form.cleaned_data['admin_role'] != 'owner':
                        messages.error(request, "هذا المستخدم هو سوبر يوزر بالفعل ولا يمكن تغيير دوره لمستوى أقل.")
                    else:
                        if form.cleaned_data['admin_role'] == 'owner':
                            if not request.user.is_superuser:
                                messages.error(request, "عذراً، فقط السوبر يوزر يمكنه إضافة مالك جديد.")
                                return redirect('admin_panel:manage_staff')
                            target.is_superuser = True
                            target.is_staff = True
                        target.role = 'admin'
                        target.save(update_fields=['role', 'is_superuser', 'is_staff'])
                        AdminProfile.objects.update_or_create(
                            user=target,
                            defaults={
                                'admin_role':      form.cleaned_data['admin_role'],
                                'notes':           form.cleaned_data.get('notes', ''),
                                'is_active_admin': True,
                                'appointed_by':    request.user,
                            }
                        )
                        AuditLog.log(request, AuditLog.ACTION_APPOINT_ADMIN,
                                     target_label=target.get_full_name() or email,
                                     target_id=target.id,
                                     details={'role': form.cleaned_data['admin_role']})
                        messages.success(request, f"تم تعيين {target.get_full_name() or email} كمسؤول.")
                except User.DoesNotExist:
                    messages.error(request, "لا يوجد مستخدم بهذا البريد الإلكتروني.")
            else:
                messages.error(request, "بيانات غير صحيحة.")

        elif action == 'remove':
            profile_id = request.POST.get('profile_id')
            profile = get_object_or_404(AdminProfile, id=profile_id)
            name = profile.user.get_full_name() or profile.user.email
            
            if profile.admin_role == 'owner' and not request.user.is_superuser:
                messages.error(request, "عذراً، فقط السوبر يوزر يمكنه إزالة مالك النظام.")
                return redirect('admin_panel:manage_staff')
                
            profile.user.role = 'student'   # إعادة لدور افتراضي محايد
            profile.user.is_superuser = False
            profile.user.is_staff = False
            profile.user.save(update_fields=['role', 'is_superuser', 'is_staff'])
            AuditLog.log(request, AuditLog.ACTION_REMOVE_ADMIN,
                         target_label=name, target_id=profile.user.id)
            profile.delete()
            messages.warning(request, f"تم إزالة {name} من الفريق الإداري وسحب الصلاحيات.")

        return redirect('admin_panel:manage_staff')

    ctx.update({
        'staff_list':    staff_list,
        'appoint_form':  AppointAdminForm(),
        'create_form':   CreateAdminForm(),
        'admin_roles':   AdminRole.choices,
    })
    return render(request, 'admin_panel/manage_staff.html', ctx)

# ==========================================================
# 12. طلبات الدفع اليدوي
# ==========================================================
@finance_required
def manual_payments(request):
    from core.models import ManualPayment
    ctx = _base_context(request)

    payments = ManualPayment.objects.select_related('user').order_by('-created_at')

    if request.method == 'POST':
        payment_id = request.POST.get('payment_id')
        action = request.POST.get('action')
        payment = get_object_or_404(ManualPayment, id=payment_id)

        if action == 'approve':
            payment.status = 'approved'
            payment.save()
            AuditLog.log(request, AuditLog.ACTION_EDIT_USER,
                         target_label=f"دفع يدوي {payment.id}",
                         target_id=payment.id,
                         details={'status': 'approved'})
            messages.success(request, "تم قبول طلب الدفع بنجاح وتفعيل الاشتراك/الحزمة.")
        elif action == 'reject':
            payment.status = 'rejected'
            payment.save()
            messages.warning(request, "تم رفض طلب الدفع.")

        return redirect('admin_panel:manual_payments')

    ctx['payments'] = payments
    return render(request, 'admin_panel/manual_payments.html', ctx)


# ==========================================================
# 13. إدارة المناهج (الوحدات والدروس)
# ==========================================================
from core.models import CurriculumUnit
from .forms import CurriculumUnitForm, CurriculumLessonFormSet

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


# ==========================================================
# 14. خدمة العملاء والبريد (Zoho Mail REST API - OAuth 2.0)
# ==========================================================
from services.zoho_mail_service import ZohoMailService
from django.urls import reverse
import logging
logger = logging.getLogger(__name__)


@admin_required
def support_inbox(request):
    """صندوق البريد الوارد لإيميلات الدعم الفني support@ta3alm.online"""
    ctx = _base_context(request)
    if not ctx['can_manage_support']:
        messages.error(request, "ليس لديك صلاحية الوصول لصندوق الدعم الفني.")
        return redirect('admin_panel:dashboard')

    service = ZohoMailService()
    ctx['is_configured'] = service.is_configured()
    ctx['is_connected'] = service.is_connected()
    ctx['support_email'] = service.support_email
    ctx['messages_list'] = []
    ctx['error_message'] = None
    ctx['search_query'] = request.GET.get('q', '').strip()

    if service.is_connected():
        try:
            res = service.list_messages(limit=30, search_key=ctx['search_query'] or None)
            raw_data = res.get('data', []) if isinstance(res, dict) else []
            ctx['messages_list'] = raw_data
        except Exception as e:
            ctx['error_message'] = str(e)
            logger.error("Zoho list messages view error: %s", e)

    return render(request, 'admin_panel/support_inbox.html', ctx)


@admin_required
def support_message_detail(request, message_id):
    """عرض تفاصيل البريد الإلكتروني مع نموذج الرد المباشر"""
    ctx = _base_context(request)
    if not ctx['can_manage_support']:
        messages.error(request, "ليس لديك صلاحية الوصول لصندوق الدعم الفني.")
        return redirect('admin_panel:dashboard')

    service = ZohoMailService()
    if not service.is_connected():
        messages.warning(request, "يرجى ربط حساب Zoho Mail أولاً.")
        return redirect('admin_panel:support_settings')

    folder_id = request.GET.get('folder_id')
    msg_metadata = {}
    try:
        raw_msgs = service.list_messages(limit=50).get('data', [])
        for m in raw_msgs:
            if str(m.get('messageId')) == str(message_id):
                msg_metadata = m
                if not folder_id:
                    folder_id = m.get('folderId')
                break
    except Exception as e:
        logger.warning("Could not pre-fetch message metadata: %s", e)

    try:
        msg_data = service.get_message_content(message_id, folder_id=folder_id)
        data = msg_data.get('data', {}) if isinstance(msg_data, dict) else {}
        
        # دمج الميتاداتا (الموضوع، المرسل، التاريخ) مع جسم الرسالة
        merged = dict(msg_metadata)
        if isinstance(data, dict):
            merged.update(data)

        ctx['message_data'] = merged
        ctx['message_id'] = message_id
        ctx['support_email'] = service.support_email
    except Exception as e:
        messages.error(request, f"فشل جلب تفاصيل الرسالة: {e}")
        return redirect('admin_panel:support_inbox')

    return render(request, 'admin_panel/support_message_detail.html', ctx)


@admin_required
def support_send_reply(request):
    """إرسال رد على رسالة عبر Zoho Mail API"""
    if request.method != 'POST':
        return redirect('admin_panel:support_inbox')

    ctx = _base_context(request)
    if not ctx['can_manage_support']:
        messages.error(request, "ليس لديك صلاحية الرد على إيميلات الدعم.")
        return redirect('admin_panel:dashboard')

    to_email = request.POST.get('to_email', '').strip()
    subject = request.POST.get('subject', '').strip()
    content = request.POST.get('content', '').strip()
    message_id = request.POST.get('message_id', '').strip()

    if not to_email or not content:
        messages.error(request, "يرجى كتابة البريد الإلكتروني ومحتوى الرد.")
        if message_id:
            return redirect('admin_panel:support_message_detail', message_id=message_id)
        return redirect('admin_panel:support_inbox')

    service = ZohoMailService()
    try:
        service.send_reply(to_email=to_email, subject=subject, content=content, message_id=message_id or None)
        AuditLog.log(
            request,
            AuditLog.ACTION_ZOHO_REPLY,
            target_label=f"إرسال رد إلى {to_email}",
            details={'to': to_email, 'subject': subject, 'message_id': message_id}
        )
        messages.success(request, f"تم إرسال الرد بنجاح إلى {to_email} من {service.support_email}!")
    except Exception as e:
        logger.error("Failed to send reply: %s", e)
        messages.error(request, f"فشل إرسال الرد عبر Zoho: {e}")

    if message_id:
        return redirect('admin_panel:support_message_detail', message_id=message_id)
    return redirect('admin_panel:support_inbox')


@admin_required
def support_compose(request):
    """إنشاء وإرسال رسالة جديدة لأي مستخدم من support@ta3alm.online"""
    if request.method == 'POST':
        to_email = request.POST.get('to_email', '').strip()
        subject = request.POST.get('subject', '').strip()
        content = request.POST.get('content', '').strip()

        if not to_email or not subject or not content:
            messages.error(request, "جميع الحقول (المستقبل، الموضوع، المحتوى) مطلوبة.")
            return redirect('admin_panel:support_inbox')

        service = ZohoMailService()
        try:
            service.compose_new_message(to_email=to_email, subject=subject, content=content)
            AuditLog.log(
                request,
                AuditLog.ACTION_ZOHO_COMPOSE,
                target_label=f"رسالة جديدة إلى {to_email}",
                details={'to': to_email, 'subject': subject}
            )
            messages.success(request, f"تم إرسال الرسالة بنجاح إلى {to_email}!")
        except Exception as e:
            messages.error(request, f"فشل إرسال الرسالة: {e}")

    return redirect('admin_panel:support_inbox')


@admin_required
def support_settings(request):
    """صفحة إعدادات وحالة اتصال Zoho Mail REST API"""
    ctx = _base_context(request)
    if not ctx['is_owner']:
        messages.error(request, "إعدادات الربط متاحة لمالك المنصة فقط.")
        return redirect('admin_panel:support_inbox')

    from .models import ZohoMailConfig
    config = ZohoMailConfig.load()
    service = ZohoMailService(config=config)

    redirect_uri = request.build_absolute_uri(reverse('admin_panel:support_oauth_callback'))
    ctx['redirect_uri'] = redirect_uri
    ctx['config'] = config
    ctx['service'] = service

    if request.method == 'POST':
        action = request.POST.get('action')
        if action == 'save_keys':
            config.client_id = request.POST.get('client_id', '').strip()
            config.client_secret = request.POST.get('client_secret', '').strip()
            config.support_email = request.POST.get('support_email', '').strip() or 'support@ta3alm.online'
            refresh_token = request.POST.get('refresh_token', '').strip()
            if refresh_token:
                config.refresh_token = refresh_token
            config.save()
            messages.success(request, "تم حفظ الإعدادات بنجاح.")
            return redirect('admin_panel:support_settings')
        elif action == 'disconnect':
            config.refresh_token = ''
            config.access_token = ''
            config.account_id = ''
            config.token_expires_at = None
            config.save()
            messages.info(request, "تم قطع الاتصال بـ Zoho Mail.")
            return redirect('admin_panel:support_settings')

    return render(request, 'admin_panel/support_settings.html', ctx)


@admin_required
def support_oauth_connect(request):
    """بدء جلسة المصادقة السريعة عبر OAuth 2.0 في Zoho"""
    service = ZohoMailService()
    if not service.client_id:
        messages.error(request, "يرجى إدخال Client ID أولاً في الإعدادات قبل بدء الربط.")
        return redirect('admin_panel:support_settings')

    redirect_uri = request.build_absolute_uri(reverse('admin_panel:support_oauth_callback'))
    auth_url = service.get_authorization_url(redirect_uri=redirect_uri)
    return redirect(auth_url)


@admin_required
def support_oauth_callback(request):
    """استقبال الكود من Zoho وحفظ التوكنات تلقائياً"""
    error = request.GET.get('error')
    if error:
        messages.error(request, f"تم رفض التخويل من Zoho أو حدث خطأ: {error}")
        return redirect('admin_panel:support_settings')

    code = request.GET.get('code')
    if not code:
        messages.error(request, "لم يتم استلام كود التخويل من Zoho.")
        return redirect('admin_panel:support_settings')

    service = ZohoMailService()
    redirect_uri = request.build_absolute_uri(reverse('admin_panel:support_oauth_callback'))
    try:
        service.exchange_code(code=code, redirect_uri=redirect_uri)
        messages.success(request, "تم ربط بريد Zoho Mail بنجاح! يمكنك الآن إدارة الرسائل والرد عليها مباشرة.")
        return redirect('admin_panel:support_inbox')
    except Exception as e:
        messages.error(request, str(e))
        return redirect('admin_panel:support_settings')


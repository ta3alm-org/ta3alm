"""dashboard_admin.views.users
Extracted from dashboard_admin/views.py.
"""

from django.shortcuts import (
    render,
    redirect,
    get_object_or_404,
)
from django.contrib import messages
from django.contrib.auth import get_user_model
from django.db.models import Q
from django.utils import timezone
from datetime import timedelta
from teachers.models import (
    TeacherProfile,
    SubscriptionPlan,
)
from accounts.models import StudentProfile
from assistants.models import AssistantProfile
from core.notifications_service import notify_user
from dashboard_admin.models import AuditLog
from dashboard_admin.decorators import moderator_required
from dashboard_admin.forms import (
    AdminUserEditForm,
    AdminTeacherEditForm,
    AdminStudentEditForm,
    AdminAssistantEditForm,
)

from dashboard_admin.views.base import _base_context

User = get_user_model()


# ==========================================================
# 3. إدارة المستخدمين
# ==========================================================
@moderator_required
def manage_users(request):
    ctx = _base_context(request)

    from api_v1.views.admin.dashboard import _backfill_missing_user_profiles
    _backfill_missing_user_profiles()

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

    elif action == 'approve_teacher':
        if hasattr(target, 'teacher_profile'):
            tp = target.teacher_profile
            tp.is_approved = True
            tp.approved_at = timezone.now()
            update_fields = ['is_approved', 'approved_at']
            if not tp.is_trial_used and not tp.subscription_end_date:
                default_plan = (
                    SubscriptionPlan.objects.filter(is_default=True).first()
                    or SubscriptionPlan.objects.order_by('price').first()
                )
                if default_plan:
                    tp.current_plan = default_plan
                    update_fields.append('current_plan')
                tp.subscription_end_date = timezone.now() + timedelta(days=30)
                tp.is_trial_used = True
                update_fields.extend(['subscription_end_date', 'is_trial_used'])
            tp.save(update_fields=update_fields)
            notify_user(target, 'تم اعتماد حسابك كمعلم', 'وافقت الإدارة على ظهور ملفك للطلاب وتفعيل لوحة المعلم الخاصة بك.', link='/teacher/')
            AuditLog.log(request, AuditLog.ACTION_EDIT_USER, target_label=f"اعتماد معلم: {target.get_full_name()}", target_id=target.id)
            messages.success(request, f"تم اعتماد المعلم {target.get_full_name()} وتفعيل حسابه.")

    elif action == 'unapprove_teacher':
        if hasattr(target, 'teacher_profile'):
            tp = target.teacher_profile
            tp.is_approved = False
            tp.approved_at = None
            tp.save(update_fields=['is_approved', 'approved_at'])
            AuditLog.log(request, AuditLog.ACTION_EDIT_USER, target_label=f"إلغاء اعتماد معلم: {target.get_full_name()}", target_id=target.id)
            messages.warning(request, f"تم سحب اعتماد المعلم {target.get_full_name()}.")

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
            notify_user(
                target,
                'تم تجديد اشتراكك من قِبل الإدارة',
                f"جددت إدارة المنصة اشتراكك لمدة 30 يوماً{f' على باقة {teacher.current_plan.name}' if teacher.current_plan else ''} حتى {teacher.subscription_end_date.strftime('%Y-%m-%d')}.",
                link='/teacher/subscription/',
            )
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
                AuditLog.log(request, AuditLog.ACTION_EDIT_USER,
                             target_label=f"تغيير كلمة مرور {target.get_full_name()}",
                             target_id=target.id)
                messages.success(request, "تم تغيير كلمة المرور بنجاح.")
            else:
                messages.error(request, "يرجى إدخال كلمة مرور جديدة.")
            return redirect('admin_panel:edit_user', user_id=target.id)

        user_form = AdminUserEditForm(request.POST, instance=target)

        if target.role == 'teacher' and hasattr(target, 'teacher_profile'):
            teacher_form = AdminTeacherEditForm(request.POST, request.FILES, instance=target.teacher_profile)
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

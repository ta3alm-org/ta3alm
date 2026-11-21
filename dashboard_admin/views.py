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
from core.notifications_service import maybe_notify_zoho_inbox, notify_user

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


@owner_required
def update_platform_commission(request):
    if request.method == 'POST':
        raw_val = request.POST.get('platform_commission_percentage')
        try:
            commission = int(raw_val)
        except (TypeError, ValueError):
            messages.error(request, "يرجى إدخال نسبة عمولة صحيحة بين 0 و 100.")
            return redirect(request.META.get('HTTP_REFERER') or 'admin_panel:dashboard')

        if commission < 0 or commission > 100:
            messages.error(request, "يجب أن تكون نسبة العمولة بين 0% و 100%.")
            return redirect(request.META.get('HTTP_REFERER') or 'admin_panel:dashboard')

        site_settings = SiteSetting.load()
        site_settings.platform_commission_percentage = commission
        site_settings.save()
        AuditLog.log(
            request,
            AuditLog.ACTION_EDIT_USER,
            target_label='تحديث عمولة المنصة',
            details={'platform_commission_percentage': commission},
        )
        messages.success(request, f"تم تحديث نسبة عمولة المنصة إلى {commission}%.")
    return redirect(request.META.get('HTTP_REFERER') or 'admin_panel:dashboard')


def _apply_app_release_post(request, site_settings):
    """منطق موحّد لحفظ إعدادات إصدار التطبيق ورابط GitHub APK وبصمة App Links."""
    import hashlib

    try:
        latest_code = max(
            1,
            int(request.POST.get('android_latest_version_code', site_settings.android_latest_version_code or 1)),
        )
    except (TypeError, ValueError):
        return False, "يرجى إدخال رقم بناء أحدث صحيح."

    try:
        min_code = max(
            1,
            int(request.POST.get('android_min_required_version_code', site_settings.android_min_required_version_code or 1)),
        )
    except (TypeError, ValueError):
        return False, "يرجى إدخال أقل رقم بناء مسموح صحيح."

    apk_url = str(request.POST.get('android_apk_url', '')).strip()[:500]
    if apk_url and not apk_url.lower().startswith(('https://', 'http://')):
        return False, "يجب أن يبدأ رابط ملف APK بـ https:// أو http://."

    site_settings.android_latest_version_code = latest_code
    site_settings.android_min_required_version_code = min_code
    site_settings.android_latest_version_name = str(
        request.POST.get('android_latest_version_name', site_settings.android_latest_version_name or '1.0.0')
    ).strip()[:32]
    site_settings.android_apk_url = apk_url
    site_settings.android_update_release_notes = str(
        request.POST.get('android_update_release_notes', '')
    ).strip()
    site_settings.android_force_update = request.POST.get('android_force_update') in ('1', 'true', 'on', 'yes')
    raw_manual_sha = str(request.POST.get('android_apk_sha256', '')).strip()
    manual_sha = SiteSetting.normalize_file_sha256(raw_manual_sha) if raw_manual_sha else ''
    if raw_manual_sha and not manual_sha:
        return False, "صيغة بصمة SHA-256 لملف APK غير صالحة (يجب أن تكون 64 حرفاً Hex، ويمكن نسخها من GitHub حتى لو بدأت بـ sha256:)."

    if 'android_assetlinks_sha256' in request.POST:
        site_settings.android_assetlinks_sha256 = str(
            request.POST.get('android_assetlinks_sha256', '')
        ).strip()

    if request.POST.get('clear_uploaded_apk') in ('1', 'true', 'on', 'yes') and site_settings.android_apk_file:
        try:
            site_settings.android_apk_file.delete(save=False)
        except Exception:
            pass
        site_settings.android_apk_file = None

    uploaded_apk = request.FILES.get('android_apk_file')
    if uploaded_apk is not None:
        sha256 = hashlib.sha256()
        for chunk in uploaded_apk.chunks():
            sha256.update(chunk)
        uploaded_apk.seek(0)
        site_settings.android_apk_file = uploaded_apk
        if not manual_sha:
            manual_sha = sha256.hexdigest().lower()

    site_settings.android_apk_sha256 = manual_sha
    site_settings.save()
    AuditLog.log(
        request,
        AuditLog.ACTION_EDIT_USER,
        target_label='تحديث إصدار تطبيق الأندرويد',
        details={
            'latest_version_code': site_settings.android_latest_version_code,
            'min_required_version_code': site_settings.android_min_required_version_code,
            'latest_version_name': site_settings.android_latest_version_name,
            'force_update': site_settings.android_force_update,
            'has_external_apk_url': bool(site_settings.android_apk_url),
        },
    )
    return True, (
        f"تم حفظ إعدادات تحديث تطبيق الأندرويد (الإصدار {site_settings.android_latest_version_name}"
        f" · بناء {site_settings.android_latest_version_code})."
    )


@owner_required
def app_release_settings(request):
    """صفحة مخصصة لإدارة رابط APK الخارجي (GitHub Releases) وإصدارات التطبيق وروابط App Links."""
    import json
    import os

    site_settings = SiteSetting.load()
    if request.method == 'POST':
        ok, msg = _apply_app_release_post(request, site_settings)
        if ok:
            messages.success(request, msg)
        else:
            messages.error(request, msg)
        return redirect('admin_panel:app_release_settings')

    package_name = os.environ.get('PLAY_INTEGRITY_PACKAGE_NAME', 'online.ta3alm.ta3alm_flutter').strip() or 'online.ta3alm.ta3alm_flutter'
    fingerprints = site_settings.get_assetlinks_fingerprints()
    packages = [package_name]
    if not package_name.endswith('.debug'):
        packages.append(f'{package_name}.debug')
    assetlinks_preview = json.dumps(
        [
            {
                'relation': ['delegate_permission/common.handle_all_urls'],
                'target': {
                    'namespace': 'android_app',
                    'package_name': pkg,
                    'sha256_cert_fingerprints': fingerprints,
                },
            }
            for pkg in packages
        ],
        ensure_ascii=False,
        indent=2,
    )
    context = _base_context(request)
    context.update({
        'effective_apk_url': site_settings.get_effective_apk_url(request=request),
        'assetlinks_fingerprints': fingerprints,
        'assetlinks_preview': assetlinks_preview,
        'env_sha256_configured': bool(
            os.environ.get('ANDROID_ASSETLINKS_SHA256', '').strip()
            or os.environ.get('ANDROID_RELEASE_CERT_SHA256', '').strip()
        ),
    })
    return render(request, 'admin_panel/app_release.html', context)


@owner_required
def update_app_release_settings(request):
    """تحديث إعدادات أحدث إصدار لتطبيق الأندرويد ورابط/ملف APK والتحديث الإجباري."""
    if request.method == 'POST':
        site_settings = SiteSetting.load()
        ok, msg = _apply_app_release_post(request, site_settings)
        if ok:
            messages.success(request, msg)
        else:
            messages.error(request, msg)
        next_target = request.POST.get('next', '').strip()
        if next_target == 'app_release':
            return redirect('admin_panel:app_release_settings')
    return redirect('admin_panel:dashboard')



# ==========================================================
# 3. إدارة المستخدمين
# ==========================================================
@moderator_required
def manage_users(request):
    ctx = _base_context(request)

    for u in User.objects.filter(role='teacher', teacher_profile__isnull=True).exclude(
        Q(custom_id__isnull=True) | Q(custom_id='')
    ):
        TeacherProfile.objects.get_or_create(user=u, defaults={'is_approved': False})
    for u in User.objects.filter(role='student', student_profile__isnull=True):
        StudentProfile.objects.get_or_create(user=u, defaults={'parent_phone': ''})
    for u in User.objects.filter(role='assistant', assistant_profile__isnull=True):
        AssistantProfile.objects.get_or_create(user=u, defaults={'phone': u.phone or ''})

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
    from decimal import Decimal
    from django.db import transaction
    from teachers.models import Wallet

    ctx = _base_context(request)

    withdraw_requests = WithdrawRequest.objects.select_related(
        'wallet__teacher__user'
    ).order_by('-created_at')

    if request.method == 'POST':
        req_id = request.POST.get('req_id')
        req_action = (request.POST.get('action') or 'approve').strip().lower()
        reason = (request.POST.get('rejection_reason') or '').strip()

        with transaction.atomic():
            req = get_object_or_404(WithdrawRequest.objects.select_for_update(), id=req_id)
            if req.status != WithdrawRequest.STATUS_PENDING:
                messages.warning(request, "تمت معالجة طلب السحب هذا مسبقاً.")
                return redirect('admin_panel:withdrawals')

            if req_action == 'reject':
                wallet = Wallet.objects.select_for_update().get(pk=req.wallet_id)
                wallet.balance = (wallet.balance or Decimal('0.00')) + req.amount
                wallet.save(update_fields=['balance'])
                req.status = WithdrawRequest.STATUS_REJECTED
                req.is_paid = False
                req.rejection_reason = reason
                req.reviewed_at = timezone.now()
                req.save(update_fields=['status', 'is_paid', 'rejection_reason', 'reviewed_at'])
                AuditLog.log(
                    request,
                    AuditLog.ACTION_REJECT_WITHDRAW,
                    target_label=f"{req} (مرفوض)",
                    target_id=req.id,
                    details={'amount': str(req.amount), 'reason': reason},
                )
                messages.info(request, f"تم رفض طلب السحب وإعادة {req.amount} EGP إلى محفظة المعلم.")
            else:
                req.status = WithdrawRequest.STATUS_PAID
                req.is_paid = True
                req.reviewed_at = timezone.now()
                req.save(update_fields=['status', 'is_paid', 'reviewed_at'])
                AuditLog.log(
                    request,
                    AuditLog.ACTION_PAY_WITHDRAW,
                    target_label=str(req),
                    target_id=req.id,
                    details={'amount': str(req.amount)},
                )
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
    commission_pct = int(ctx['site_settings'].platform_commission_percentage or 0)
    platform_commission_revenue = round(float(total_revenue) * commission_pct / 100.0, 2)
    teachers_net_revenue = round(float(total_revenue) - platform_commission_revenue, 2)

    ctx.update({
        'payments': payments,
        'total_revenue': total_revenue,
        'commission_percentage': commission_pct,
        'platform_commission_revenue': platform_commission_revenue,
        'teachers_net_revenue': teachers_net_revenue,
    })
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
            maybe_notify_zoho_inbox(raw_data)
        except Exception as e:
            ctx['error_message'] = str(e)
            logger.error("Zoho list messages view error: %s", e)

    return render(request, 'admin_panel/support_inbox.html', ctx)


def _sanitize_email_html(raw_html: str) -> str:
    """ينقّي محتوى البريد الإلكتروني HTML من الوسوم والخصائص التنفيذية الخطرة قبل العرض المعزول."""
    import re as _re

    if not raw_html:
        return ''
    cleaned = str(raw_html)
    for tag in ('script', 'iframe', 'object', 'embed', 'form'):
        cleaned = _re.sub(
            rf'<{tag}\b[^>]*>.*?</{tag}>',
            '',
            cleaned,
            flags=_re.IGNORECASE | _re.DOTALL,
        )
        cleaned = _re.sub(
            rf'</?{tag}\b[^>]*>',
            '',
            cleaned,
            flags=_re.IGNORECASE,
        )
    cleaned = _re.sub(r'</?(?:meta|base)\b[^>]*>', '', cleaned, flags=_re.IGNORECASE)
    cleaned = _re.sub(
        r'\s+on[a-z]+\s*=\s*(?:"[^"]*"|\'[^\']*\'|[^\s>]+)',
        '',
        cleaned,
        flags=_re.IGNORECASE,
    )
    cleaned = _re.sub(
        r'(href|src|action|formaction|xlink:href)\s*=\s*(["\']?)\s*(?:javascript|vbscript|data:text/html):[^\2\s>]*\2',
        r'\1=\2#\2',
        cleaned,
        flags=_re.IGNORECASE,
    )
    return cleaned


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
        
        # دمج الميتاداتا (الموضوع، المرسل، التاريخ) مع جسم الرسالة وتنقيته
        merged = dict(msg_metadata)
        if isinstance(data, dict):
            merged.update(data)
        merged['sanitized_content'] = _sanitize_email_html(merged.get('content', ''))

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


# ==========================================================
# 10. مركز أمان الأجهزة ومكافحة الحسابات المشتركة والعبث
# ==========================================================
@moderator_required
def security_dashboard(request):
    """لوحة مراقبة الأجهزة، المخاطر السلوكية، الحظر، والجلسات النشطة."""
    import ipaddress
    from api_v1.models import (
        DeviceBlock,
        DeviceSecurityEvent,
        DeviceSession,
        DeviceTrustStatus,
        RegisteredDevice,
        SecurityPolicyConfig,
    )

    ctx = _base_context(request)
    policy = SecurityPolicyConfig.load()
    now = timezone.now()

    q = (request.GET.get('q') or '').strip()
    trust_filter = (request.GET.get('trust') or '').strip()
    severity_filter = (request.GET.get('severity') or '').strip()
    event_status_filter = (request.GET.get('event_status') or '').strip()

    devices_qs = RegisteredDevice.objects.select_related('user').order_by('-risk_score', '-last_active_at')
    if q:
        search_q = (
            Q(user__username__icontains=q)
            | Q(user__email__icontains=q)
            | Q(device_name__icontains=q)
            | Q(model__icontains=q)
            | Q(installation_id__icontains=q)
        )
        try:
            ipaddress.ip_address(q)
            search_q |= Q(last_ip=q)
        except ValueError:
            pass
        devices_qs = devices_qs.filter(search_q)
    if trust_filter:
        devices_qs = devices_qs.filter(trust_status=trust_filter)

    events_qs = DeviceSecurityEvent.objects.select_related('user', 'device').order_by('-created_at')
    if severity_filter:
        events_qs = events_qs.filter(severity=severity_filter)
    if event_status_filter:
        events_qs = events_qs.filter(investigation_status=event_status_filter)

    active_sessions_qs = DeviceSession.objects.select_related('user', 'device').filter(
        status='active',
        expires_at__gt=now,
    ).order_by('-last_seen_at')

    active_blocks_qs = DeviceBlock.objects.select_related('user', 'device', 'blocked_by').filter(
        is_active=True
    ).order_by('-created_at')

    sharing_alerts = DeviceSecurityEvent.objects.select_related('user', 'device').filter(
        event_type__in=(
            'account_sharing_suspected',
            'excessive_simultaneous_sessions',
            'distant_simultaneous_locations',
            'concurrent_playback_multiple_devices',
            'unfamiliar_device_reported',
        )
    ).order_by('-created_at')[:20]

    unified_devices = []
    try:
        from api_v1.device_security_service import build_unified_devices_registry
        unified_devices = build_unified_devices_registry(
            search_query=q,
            trust_filter=trust_filter,
            limit=120,
        )
    except Exception:
        unified_devices = []

    ctx.update({
        'policy': policy,
        'devices': devices_qs[:60],
        'unified_devices': unified_devices,
        'events': events_qs[:60],
        'active_sessions': active_sessions_qs[:40],
        'active_blocks': active_blocks_qs[:40],
        'sharing_alerts': sharing_alerts,
        'q': q,
        'trust_filter': trust_filter,
        'severity_filter': severity_filter,
        'event_status_filter': event_status_filter,
        'trust_choices': DeviceTrustStatus.choices,
        'stats': {
            'total_devices': len(unified_devices) if not (q or trust_filter) else RegisteredDevice.objects.count(),
            'unique_physical_devices': len(unified_devices),
            'active_devices': RegisteredDevice.objects.filter(is_active=True).count(),
            'suspicious_devices': RegisteredDevice.objects.filter(
                trust_status__in=[DeviceTrustStatus.SUSPICIOUS, DeviceTrustStatus.RESTRICTED]
            ).count(),
            'blocked_devices': DeviceBlock.objects.filter(is_active=True).count(),
            'active_sessions': active_sessions_qs.count(),
            'open_events': DeviceSecurityEvent.objects.filter(investigation_status='open').count(),
            'critical_events': DeviceSecurityEvent.objects.filter(
                severity='critical',
                investigation_status='open',
            ).count(),
        },
    })
    return render(request, 'admin_panel/security_dashboard.html', ctx)


@moderator_required
def security_device_detail(request, device_id):
    """تفاصيل جهاز مسجّل: البصمات، تاريخ IP، الجلسات، النشاط، والأحداث الأمنية."""
    from api_v1.models import DeviceBlock, RegisteredDevice

    ctx = _base_context(request)
    device = get_object_or_404(RegisteredDevice.objects.select_related('user'), id=device_id)
    ctx.update({
        'device': device,
        'fingerprints': device.fingerprints.order_by('-created_at')[:20],
        'sessions': device.sessions.order_by('-last_seen_at')[:30],
        'activities': device.activities.order_by('-created_at')[:40],
        'events': device.security_events.order_by('-created_at')[:40],
        'blocks': DeviceBlock.objects.filter(
            Q(device=device) | Q(installation_id=device.installation_id)
        ).order_by('-created_at')[:15],
        'user_other_devices': RegisteredDevice.objects.filter(user=device.user).exclude(pk=device.pk)[:10],
    })
    return render(request, 'admin_panel/security_device_detail.html', ctx)


@moderator_required
def security_admin_action(request):
    """تنفيذ إجراءات الأمان الإدارية من لوحة التحكم (حظر، فك حظر، إبطال جلسة، سياسات، تحقيق)."""
    if request.method != 'POST':
        return redirect('admin_panel:security_dashboard')

    from api_v1.device_security_service import (
        block_device_admin,
        prune_expired_telemetry,
        revoke_user_device,
        unblock_device_admin,
    )
    from api_v1.models import (
        DeviceBlock,
        DeviceSecurityEvent,
        DeviceSession,
        DeviceTrustStatus,
        PlaybackSession,
        RegisteredDevice,
        SecurityPolicyConfig,
    )

    from django.utils.http import url_has_allowed_host_and_scheme

    action = (request.POST.get('action') or '').strip()
    raw_next = (request.POST.get('next') or '').strip()
    if raw_next and url_has_allowed_host_and_scheme(
        raw_next,
        allowed_hosts={request.get_host()},
        require_https=request.is_secure(),
    ):
        next_url = raw_next
    else:
        next_url = reverse('admin_panel:security_dashboard')

    if action == 'block_device':
        device_id = request.POST.get('device_id')
        inst_id = (request.POST.get('installation_id') or '').strip()
        hw_id = (request.POST.get('hardware_id') or '').strip()
        device = RegisteredDevice.objects.filter(id=device_id).first() if device_id else None
        if not device and inst_id:
            device = RegisteredDevice.objects.filter(installation_id=inst_id).first()
        block_type = 'temporary' if request.POST.get('block_type') == 'temporary' else 'permanent'
        try:
            duration_hours = max(int(request.POST.get('duration_hours') or 24), 1)
        except ValueError:
            duration_hours = 24
        reason = (request.POST.get('reason') or 'حظر إداري من لوحة التحكم (تطبيق + متصفح)').strip()
        if device or inst_id or hw_id:
            blk = block_device_admin(
                device=device,
                installation_id=inst_id or (device.installation_id if device else hw_id),
                hardware_id=hw_id,
                admin_user=request.user,
                block_type=block_type,
                reason=reason,
                duration_hours=duration_hours,
                request=request,
            )
            AuditLog.log(
                request,
                AuditLog.ACTION_BLOCK_DEVICE,
                target_label=hw_id or blk.fingerprint_hash or blk.installation_id,
                target_id=device.id if device else None,
                details={'block_type': block_type, 'hardware_id': hw_id or blk.fingerprint_hash, 'reason': reason, 'duration_hours': duration_hours},
            )
            messages.success(request, f"تم حظر الجهاز ({hw_id or blk.fingerprint_hash or blk.installation_id}) على التطبيق والمتصفح وإبطال جلساته.")
        else:
            messages.error(request, "تعذر العثور على الجهاز المطلوب حظره.")

    elif action == 'unblock_device':
        block_id = request.POST.get('block_id')
        device_id = request.POST.get('device_id')
        inst_id = (request.POST.get('installation_id') or '').strip()
        hw_id = (request.POST.get('hardware_id') or '').strip()
        device = RegisteredDevice.objects.filter(id=device_id).first() if device_id else None
        if block_id and not inst_id and not hw_id:
            blk = get_object_or_404(DeviceBlock, id=block_id)
            inst_id = blk.installation_id
            if str(blk.fingerprint_hash or '').startswith('DEV-'):
                hw_id = blk.fingerprint_hash
            device = device or blk.device
        reason = (request.POST.get('reason') or 'رفع الحظر بواسطة الإدارة').strip()
        if inst_id or device or hw_id:
            count = unblock_device_admin(
                device=device,
                installation_id=inst_id,
                hardware_id=hw_id,
                admin_user=request.user,
                reason=reason,
                request=request,
            )
            AuditLog.log(
                request,
                AuditLog.ACTION_UNBLOCK_DEVICE,
                target_label=hw_id or inst_id or (device.installation_id if device else ''),
                target_id=device.id if device else None,
                details={'unblocked_count': count, 'hardware_id': hw_id, 'reason': reason},
            )
            messages.success(request, "تم فك حظر الجهاز (التطبيق والمتصفح) بنجاح.")
        else:
            messages.error(request, "بيانات الجهاز غير كافية لفك الحظر.")

    elif action == 'revoke_device':
        device = get_object_or_404(RegisteredDevice, id=request.POST.get('device_id'))
        revoke_user_device(
            device=device,
            actor=request.user,
            request=request,
            mode='revoke',
            reason=request.POST.get('reason') or 'revoked_by_admin_panel',
        )
        AuditLog.log(
            request,
            AuditLog.ACTION_REVOKE_SESSION,
            target_label=device.installation_id,
            target_id=device.id,
            details={'action': 'revoke_device'},
        )
        messages.success(request, "تم إلغاء تفويض الجهاز وإنهاء جلساته.")

    elif action == 'force_reauth':
        device = get_object_or_404(RegisteredDevice, id=request.POST.get('device_id'))
        device.requires_reauth = True
        if device.trust_status != DeviceTrustStatus.BLOCKED:
            device.trust_status = DeviceTrustStatus.PENDING
        device.save(update_fields=['requires_reauth', 'trust_status'])
        DeviceSession.objects.filter(device=device, status='active').update(
            status='revoked',
            ended_at=timezone.now(),
            revoked_reason='force_reauth_admin_panel',
        )
        messages.info(request, "تم إلزام الجهاز بإعادة التحقق.")

    elif action == 'revoke_session':
        sess = get_object_or_404(DeviceSession, id=request.POST.get('session_id'))
        sess.status = 'revoked'
        sess.ended_at = timezone.now()
        sess.revoked_reason = 'revoked_by_admin_panel'
        sess.save(update_fields=['status', 'ended_at', 'revoked_reason'])
        AuditLog.log(
            request,
            AuditLog.ACTION_REVOKE_SESSION,
            target_label=str(sess.session_uuid),
            target_id=sess.user_id,
            details={'installation_id': sess.installation_id},
        )
        messages.success(request, "تم إنهاء الجلسة بنجاح.")

    elif action == 'revoke_all_user_sessions':
        target_user = get_object_or_404(User, id=request.POST.get('user_id'))
        now = timezone.now()
        DeviceSession.objects.filter(user=target_user, status='active').update(
            status='revoked',
            ended_at=now,
            revoked_reason='revoked_all_admin_panel',
        )
        PlaybackSession.objects.filter(user=target_user, status='active').update(
            status='revoked',
            revoked_reason='revoked_all_admin_panel',
        )
        messages.success(request, f"تم إنهاء جميع الجلسات النشطة للمستخدم {target_user.username}.")

    elif action == 'resolve_event':
        evt = get_object_or_404(DeviceSecurityEvent, id=request.POST.get('event_id'))
        inv_status = (request.POST.get('investigation_status') or 'resolved').strip()
        notes = (request.POST.get('investigation_notes') or '').strip()
        if inv_status in ('open', 'investigating', 'resolved', 'false_positive'):
            evt.investigation_status = inv_status
            if notes:
                evt.investigation_notes = notes
            evt.reviewed_by = request.user
            evt.reviewed_at = timezone.now()
            evt.save(update_fields=['investigation_status', 'investigation_notes', 'reviewed_by', 'reviewed_at'])
            if inv_status == 'false_positive' and evt.device and evt.device.trust_status != DeviceTrustStatus.BLOCKED:
                dev = evt.device
                dev.trust_status = DeviceTrustStatus.TRUSTED
                dev.requires_reauth = False
                dev.risk_score = max(dev.risk_score - 40, 0)
                dev.risk_level = 'low' if dev.risk_score < 30 else 'medium'
                dev.save(update_fields=['trust_status', 'requires_reauth', 'risk_score', 'risk_level'])
            messages.success(request, "تم تحديث حالة الحدث الأمني.")

    elif action == 'update_policy':
        policy = SecurityPolicyConfig.load()
        for field in (
            'student_device_limit',
            'teacher_device_limit',
            'assistant_device_limit',
            'max_concurrent_sessions',
            'max_concurrent_playback',
            'risk_threshold_medium',
            'risk_threshold_high',
            'risk_threshold_critical',
            'rapid_login_threshold_5m',
            'rapid_geo_kmh_threshold',
            'event_retention_days',
        ):
            raw_v = request.POST.get(field)
            if raw_v is not None and str(raw_v).isdigit():
                setattr(policy, field, max(int(raw_v), 1))
        policy.enforce_device_limits = request.POST.get('enforce_device_limits') == 'on'
        policy.enforce_screen_capture_policy = request.POST.get('enforce_screen_capture_policy') == 'on'
        policy.set_boot_guard_flags(
            block_vpn=request.POST.get('block_vpn_connections') == 'on',
            block_dev_options=request.POST.get('block_developer_options') == 'on',
            block_abnormal_net=request.POST.get('block_abnormal_dns_or_ports') == 'on',
        )
        policy.save()
        AuditLog.log(
            request,
            AuditLog.ACTION_SECURITY_POLICY,
            target_label='SecurityPolicyConfig',
            target_id=policy.id,
            details={'student_device_limit': policy.student_device_limit},
        )
        messages.success(request, "تم حفظ إعدادات سياسة الأمان وحدود الأجهزة.")

    elif action == 'toggle_maintenance_device':
        hw_id = (request.POST.get('hardware_id') or '').strip()
        inst_id = (request.POST.get('installation_id') or '').strip()
        device_id = request.POST.get('device_id')
        if not hw_id and device_id:
            dev = RegisteredDevice.objects.filter(id=device_id).first()
            if dev is not None:
                from api_v1.device_security_service import get_device_hardware_id
                hw_id = get_device_hardware_id(dev)
        if not hw_id and inst_id:
            dev = RegisteredDevice.objects.filter(installation_id=inst_id).first()
            if dev is not None:
                from api_v1.device_security_service import get_device_hardware_id
                hw_id = get_device_hardware_id(dev)
        target_ident = hw_id or inst_id
        if not target_ident:
            messages.error(request, "يجب تحديد معرّف الجهاز المادي DEV-XXXX.")
        else:
            policy = SecurityPolicyConfig.load()
            raw_approved = request.POST.get('approved')
            if raw_approved is not None:
                approved = str(raw_approved).lower() in ('1', 'true', 'yes', 'on')
            else:
                approved = not policy.is_device_maintenance_approved(target_ident)
            policy.set_device_maintenance_approval(target_ident, approved=approved)
            policy.save()
            AuditLog.log(
                request,
                AuditLog.ACTION_SECURITY_POLICY,
                target_label=target_ident,
                details={'action': 'toggle_maintenance_device', 'approved': approved},
            )
            messages.success(
                request,
                f"تم {'اعتماد' if approved else 'إلغاء اعتماد'} الجهاز ({target_ident}) لظهور زر دخول الإدارة في وضع الصيانة.",
            )

    elif action == 'prune_telemetry':
        res = prune_expired_telemetry()
        messages.success(
            request,
            f"تم تنظيف السجلات المنتهية: {res['activities_deleted']} نشاط، {res['events_deleted']} حدث.",
        )

    return redirect(next_url)


# ==========================================================
# 15. إرسال الإشعارات المخصصة (لمستخدمين معينين / فئة / الكل)
# ==========================================================
@moderator_required
def send_notifications(request):
    """صفحة إرسال إشعار مخصص لمستخدمين محددين أو فئة أو جميع المستخدمين."""
    from core.notifications_service import (
        CUSTOM_TARGET_ALL,
        CUSTOM_TARGET_USERS,
        get_custom_notification_metadata,
        parse_user_ids_input,
        preview_custom_notification_audience,
        search_custom_notification_users,
        send_custom_notification,
    )

    ctx = _base_context(request)
    metadata = get_custom_notification_metadata()

    target_mode = (request.GET.get('mode') or CUSTOM_TARGET_ALL).strip()
    segment = (request.GET.get('segment') or 'students').strip()
    grade = (request.GET.get('grade') or '').strip()
    teacher_id = (request.GET.get('teacher_id') or '').strip()
    plan_id = (request.GET.get('plan_id') or '').strip()
    subject_id = (request.GET.get('subject_id') or '').strip()
    exclude_banned = True
    title_val = ''
    message_val = ''
    link_val = ''

    preselected_ids = parse_user_ids_input(
        request.GET.getlist('user_id') or request.GET.get('user_ids')
    )
    if preselected_ids and not request.GET.get('mode'):
        target_mode = CUSTOM_TARGET_USERS

    if request.method == 'POST':
        target_mode = (request.POST.get('target_mode') or CUSTOM_TARGET_ALL).strip()
        segment = (request.POST.get('segment') or '').strip()
        grade = (request.POST.get('grade') or '').strip()
        teacher_id = (request.POST.get('teacher_id') or '').strip()
        plan_id = (request.POST.get('plan_id') or '').strip()
        subject_id = (request.POST.get('subject_id') or '').strip()
        exclude_banned = request.POST.get('exclude_banned') == '1'
        title_val = (request.POST.get('title') or '').strip()
        message_val = (request.POST.get('message') or '').strip()
        link_val = (request.POST.get('link') or '').strip()
        preselected_ids = parse_user_ids_input(request.POST.getlist('user_ids'))

        res = send_custom_notification(
            title=title_val,
            message=message_val,
            link=link_val,
            target_mode=target_mode,
            segment=segment,
            user_ids=preselected_ids,
            grade=grade,
            teacher_id=teacher_id,
            plan_id=plan_id,
            subject_id=subject_id,
            exclude_banned=exclude_banned,
        )
        if res.get('ok'):
            AuditLog.log_custom_notification(request, res)
            fcm_note = (
                f" (منهم {res['fcm_user_count']} لديهم إشعارات فورية FCM مفعّلة)"
                if res.get('fcm_configured')
                else " (ملاحظة: إشعارات FCM الفورية غير مهيأة على الخادم حالياً)"
            )
            messages.success(
                request,
                f"تم إرسال الإشعار بنجاح إلى {res['recipient_count']} مستخدم ضمن «{res['audience_label']}»{fcm_note}.",
            )
            return redirect('admin_panel:send_notifications')
        messages.error(request, res.get('error') or 'تعذّر إرسال الإشعار.')

    selected_users = []
    if preselected_ids:
        selected_qs = User.objects.filter(id__in=preselected_ids).order_by('-id')
        fcm_ids = set(
            selected_qs.filter(fcm_tokens__is_active=True).values_list('id', flat=True)
        )
        for u in selected_qs:
            selected_users.append({
                'id': u.pk,
                'full_name': (u.get_full_name() or '').strip() or u.username or u.email,
                'email': u.email or '',
                'phone': getattr(u, 'phone', '') or '',
                'custom_id': getattr(u, 'custom_id', '') or '',
                'role': u.role,
                'role_display': u.get_role_display(),
                'has_fcm': u.pk in fcm_ids,
            })

    preview = preview_custom_notification_audience(
        target_mode=target_mode,
        segment=segment,
        user_ids=preselected_ids,
        grade=grade,
        teacher_id=teacher_id,
        plan_id=plan_id,
        subject_id=subject_id,
        exclude_banned=exclude_banned,
    )
    recent_dispatches = AuditLog.objects.filter(
        action=AuditLog.ACTION_SEND_NOTIFICATION
    ).select_related('admin').order_by('-created_at')[:15]

    ctx.update({
        'notif_meta': metadata,
        'target_mode': target_mode,
        'segment': segment,
        'grade': grade,
        'teacher_id': teacher_id,
        'plan_id': plan_id,
        'subject_id': subject_id,
        'exclude_banned': exclude_banned,
        'title_val': title_val,
        'message_val': message_val,
        'link_val': link_val,
        'selected_users': selected_users,
        'initial_users': search_custom_notification_users(limit=15),
        'preview': preview,
        'recent_dispatches': recent_dispatches,
    })
    return render(request, 'admin_panel/send_notifications.html', ctx)


@moderator_required
def notifications_recipient_preview(request):
    """نقطة JSON للمعاينة الحية والبحث عن المستخدمين في صفحة إرسال الإشعارات."""
    from django.http import JsonResponse
    from core.notifications_service import (
        CUSTOM_TARGET_ALL,
        preview_custom_notification_audience,
        search_custom_notification_users,
    )

    if 'q' in request.GET or request.GET.get('action') == 'search_users':
        q = (request.GET.get('q') or '').strip()
        role = (request.GET.get('role') or '').strip()
        return JsonResponse({
            'users': search_custom_notification_users(query=q, role=role, limit=25),
        })

    user_ids = request.GET.getlist('user_ids') or request.GET.get('user_ids', '')
    exclude_banned = str(request.GET.get('exclude_banned', '1')).lower() not in ('0', 'false', 'no')
    preview = preview_custom_notification_audience(
        target_mode=(request.GET.get('target_mode') or CUSTOM_TARGET_ALL).strip(),
        segment=(request.GET.get('segment') or '').strip(),
        user_ids=user_ids,
        grade=(request.GET.get('grade') or '').strip(),
        teacher_id=(request.GET.get('teacher_id') or '').strip(),
        plan_id=(request.GET.get('plan_id') or '').strip(),
        subject_id=(request.GET.get('subject_id') or '').strip(),
        exclude_banned=exclude_banned,
    )
    return JsonResponse(preview)



"""
accounts/views.py — إدارة إكمال الملفات الشخصية والتوجيه
"""
from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth.decorators import login_required
from django.contrib import messages
from django.utils import timezone
from django.utils.translation import gettext as _
from datetime import timedelta
import random
import secrets
import string
from django.contrib.auth import login, update_session_auth_hash

from .email_verification import issue_email_verification, send_verification_email
from .forms import CompleteStudentProfileForm, CompleteTeacherProfileForm, CompleteAssistantProfileForm
from .models import EmailVerification, StudentProfile, User
from teachers.models import TeacherProfile, SubscriptionPlan
from assistants.models import AssistantProfile

RESEND_COOLDOWN_SECONDS = 60


@login_required
def complete_profile(request):
    user = request.user

    # ✅ المالك أو الأدمن لا يحتاج إكمال بيانات — يُعاد توجيهه مباشرة
    if user.is_superuser or user.role == 'admin':
        return redirect('admin_panel:dashboard')

    if user.requires_email_verification():
        request.session['pending_verification_user_id'] = user.id
        return redirect('verify_email_page')

    # 1. التحقق من اكتمال البيانات
    is_complete = False
    if user.role == 'student':
        is_complete = hasattr(user, 'student_profile') and bool(user.student_profile.parent_phone)
    elif user.role == 'teacher':
        is_complete = hasattr(user, 'teacher_profile') and bool(user.teacher_profile.subject_id)
    elif user.role == 'assistant':
        is_complete = hasattr(user, 'assistant_profile') and bool(user.assistant_profile.phone)

    if is_complete and user.custom_id:
        return redirect('custom_login_redirect')

    # 2. تحديد الفورم المناسب
    form_map = {
        'student':   CompleteStudentProfileForm,
        'teacher':   CompleteTeacherProfileForm,
        'assistant': CompleteAssistantProfileForm,
    }
    FormClass = form_map.get(user.role)
    if not FormClass:
        # دور غير معروف — يُعاد للـ home بعد تسجيل تحذير
        messages.error(request, _("دورك غير محدد. تواصل مع الدعم."))
        return redirect('home')

    # 3. معالجة الحفظ
    if request.method == 'POST':
        form = FormClass(request.POST, instance=user)
        if form.is_valid():
            saved_user = form.save(commit=False)

            # الاسم الكامل
            full_name = form.cleaned_data.get('full_name', '').strip()
            if full_name:
                parts = full_name.split(' ', 1)
                saved_user.first_name = parts[0]
                saved_user.last_name  = parts[1] if len(parts) > 1 else ''

            # توليد الكود لو لم يوجد
            if not saved_user.custom_id:
                chars  = string.ascii_uppercase + string.digits
                prefix = {'assistant': 'A', 'teacher': 'T', 'student': 'S'}.get(user.role, 'U')
                saved_user.custom_id = prefix + ''.join(random.choices(chars, k=6))

            # كلمة المرور
            password = form.cleaned_data.get('password')
            if password:
                saved_user.set_password(password)

            saved_user.save()

            # تحديث الجلسة عند تغيير الباسورد
            if password and user.role in ['teacher', 'assistant', 'student']:
                update_session_auth_hash(request, saved_user)

            # حفظ البروفايل الفرعي
            if user.role == 'student':
                StudentProfile.objects.update_or_create(
                    user=saved_user,
                    defaults={'parent_phone': form.cleaned_data['parent_phone']},
                )

            elif user.role == 'teacher':
                default_plan = (
                    SubscriptionPlan.objects.filter(is_default=True).first()
                    or SubscriptionPlan.objects.order_by('price').first()
                )
                TeacherProfile.objects.update_or_create(
                    user=saved_user,
                    defaults={
                        'bio':                  form.cleaned_data.get('bio', ''),
                        'subject':              form.cleaned_data['subject'],
                        'subscription_end_date': timezone.now() + timedelta(days=30),
                        'is_trial_used':        True,
                        'current_plan':         default_plan,
                    },
                )

            elif user.role == 'assistant':
                phone_val = request.POST.get('phone', '').strip()
                if phone_val:
                    AssistantProfile.objects.update_or_create(
                        user=saved_user,
                        defaults={'phone': phone_val},
                    )

            messages.success(request, _("تم التسجيل بنجاح! أهلاً بك يا %(name)s 🎉") % {'name': saved_user.first_name})
            return redirect('custom_login_redirect')
    else:
        initial = {'full_name': f'{user.first_name} {user.last_name}'.strip(), 'phone': user.phone}
        form = FormClass(instance=user, initial=initial)

    return render(request, 'accounts/complete_profile.html', {
        'form': form,
        'role': user.role,
    })
def _resolve_pending_verification_user(request):
    if request.user.is_authenticated:
        return request.user
    pending_id = request.session.get('pending_verification_user_id')
    if pending_id:
        return User.objects.filter(pk=pending_id).first()
    return None


def _remaining_resend_seconds(verification) -> int:
    if not verification or not verification.last_sent_at:
        return 0
    elapsed = (timezone.now() - verification.last_sent_at).total_seconds()
    remaining = int(RESEND_COOLDOWN_SECONDS - elapsed)
    return max(0, remaining)


def manual_signup(request):
    if request.method == 'POST':
        full_name = request.POST.get('full_name', '').strip()
        email = request.POST.get('email', '').strip().lower()
        phone = request.POST.get('phone', '').strip()
        password = request.POST.get('password', '')
        confirm_password = request.POST.get('confirm_password', '')
        role = request.POST.get('role', request.session.get('selected_role', 'student'))
        if role not in ('student', 'teacher', 'assistant'):
            role = 'student'

        if not email:
            messages.error(request, _("يرجى إدخال البريد الإلكتروني."))
            return redirect('signup_redirect', role=role)

        if password != confirm_password:
            messages.error(request, _("كلمتا المرور غير متطابقتين."))
            return redirect('signup_redirect', role=role)

        existing_email_user = User.objects.filter(email__iexact=email).first()
        if existing_email_user:
            if existing_email_user.requires_email_verification():
                verification = issue_email_verification(existing_email_user, update_sent_time=True)
                sent, err_msg = send_verification_email(request, existing_email_user, verification)
                login(request, existing_email_user, backend='accounts.backends.MultiFieldAuthBackend')
                request.session['pending_verification_user_id'] = existing_email_user.id
                if sent:
                    messages.info(request, _("تم إرسال رابط وكود تفعيل جديد إلى بريدك الإلكتروني."))
                else:
                    messages.warning(request, err_msg)
                return redirect('verify_email_page')
            messages.error(request, _("هذا البريد الإلكتروني مستخدم بالفعل."))
            return redirect('signup_redirect', role=role)

        if phone and User.objects.filter(phone=phone).exists():
            messages.error(request, _("رقم الهاتف هذا مستخدم بالفعل."))
            return redirect('signup_redirect', role=role)

        # إنشاء الحساب (استخدام البريد كاسم مستخدم)
        user = User.objects.create_user(
            username=email,
            email=email,
            password=password,
            phone=phone,
            role=role,
        )
        if full_name:
            parts = full_name.split(' ', 1)
            user.first_name = parts[0]
            if len(parts) > 1:
                user.last_name = parts[1]
            user.save(update_fields=['first_name', 'last_name'])

        verification = issue_email_verification(user, update_sent_time=True)
        sent, err_msg = send_verification_email(request, user, verification)

        # تسجيل الدخول وتوجيه لصفحة تفعيل البريد الإلكتروني
        login(request, user, backend='accounts.backends.MultiFieldAuthBackend')
        request.session['pending_verification_user_id'] = user.id
        if sent:
            messages.info(
                request,
                _("تم إرسال رسالة إلى %(email)s تحتوي على رابط التفعيل وكود مكون من 6 أرقام.") % {'email': user.email},
            )
        else:
            messages.warning(request, err_msg)
        return redirect('verify_email_page')

    return redirect('home')


def verify_email_page(request):
    user = _resolve_pending_verification_user(request)
    if user is None:
        messages.info(request, _("يرجى تسجيل الدخول أو إنشاء حساب أولاً."))
        return redirect('account_login')

    if not user.requires_email_verification():
        request.session.pop('pending_verification_user_id', None)
        if user.is_authenticated:
            return redirect('complete_profile')
        return redirect('account_login')

    verification = user.email_verification
    cooldown_remaining = _remaining_resend_seconds(verification)

    if request.method == 'POST':
        code = request.POST.get('code', '').strip()
        if verification.is_expired():
            messages.error(request, _("انتهت صلاحية كود التفعيل. اضغط على إعادة إرسال الكود والرابط."))
        elif not code or not secrets.compare_digest(code, verification.code):
            messages.error(request, _("كود التفعيل غير صحيح. تأكد من الأرقام الستة وحاول مرة أخرى."))
        else:
            verification.is_verified = True
            verification.save(update_fields=['is_verified'])
            if not request.user.is_authenticated or request.user.pk != user.pk:
                login(request, user, backend='accounts.backends.MultiFieldAuthBackend')
            request.session.pop('pending_verification_user_id', None)
            messages.success(request, _("تم تفعيل بريدك الإلكتروني بنجاح!"))
            return redirect('complete_profile')

    return render(request, 'accounts/verify_email.html', {
        'target_email': user.email,
        'cooldown_remaining': cooldown_remaining,
        'is_expired': verification.is_expired(),
    })


def verify_email_link(request, token):
    verification = get_object_or_404(
        EmailVerification.objects.select_related('user'),
        token=token,
    )
    user = verification.user

    if not verification.is_verified and verification.is_expired():
        request.session['pending_verification_user_id'] = user.id
        messages.error(request, _("انتهت صلاحية رابط التفعيل. يمكنك طلب رابط وكود جديد من هنا."))
        return redirect('verify_email_page')

    if not verification.is_verified:
        verification.is_verified = True
        verification.save(update_fields=['is_verified'])

    login(request, user, backend='accounts.backends.MultiFieldAuthBackend')
    request.session.pop('pending_verification_user_id', None)
    messages.success(request, _("تم تفعيل حسابك بنجاح عبر الرابط المباشر!"))
    return redirect('complete_profile')


def resend_verification_email(request):
    if request.method != 'POST':
        return redirect('verify_email_page')

    user = _resolve_pending_verification_user(request)
    if user is None:
        messages.info(request, _("يرجى تسجيل الدخول أولاً."))
        return redirect('account_login')

    if not user.requires_email_verification():
        return redirect('complete_profile')

    verification = getattr(user, 'email_verification', None)
    remaining = _remaining_resend_seconds(verification)
    if remaining > 0:
        messages.warning(
            request,
            _("يرجى الانتظار %(sec)s ثانية قبل إعادة إرسال البريد.") % {'sec': remaining},
        )
        return redirect('verify_email_page')

    verification = issue_email_verification(user, update_sent_time=True)
    sent, err_msg = send_verification_email(request, user, verification)
    if sent:
        messages.success(request, _("تم إعادة إرسال رابط وكود التفعيل إلى بريدك الإلكتروني."))
    else:
        messages.warning(request, err_msg)
    return redirect('verify_email_page')

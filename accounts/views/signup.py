"""accounts.views.signup
Extracted from accounts/views.py.
"""

from django.shortcuts import (
    render,
    redirect,
    get_object_or_404,
)
from django.contrib import messages
from django.utils import timezone
from django.utils.translation import gettext as _
import secrets
from django.contrib.auth import login
from accounts.email_verification import (
    issue_email_verification,
    send_verification_email,
)
from accounts.models import (
    EmailVerification,
    User,
)


RESEND_COOLDOWN_SECONDS = 60


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

    if user.is_superuser or user.role == 'admin':
        request.session.pop('pending_verification_user_id', None)
        return redirect('custom_login_redirect')

    if not user.requires_email_verification():
        request.session.pop('pending_verification_user_id', None)
        if user.is_authenticated:
            return redirect('custom_login_redirect')
        return redirect('account_login')

    try:
        verification = user.email_verification
    except EmailVerification.DoesNotExist:
        verification = None

    if verification is None or not verification.code or verification.is_expired():
        if verification is None or _remaining_resend_seconds(verification) == 0:
            verification = issue_email_verification(user, update_sent_time=True)
            if user.email:
                sent, err_msg = send_verification_email(request, user, verification)
                if not sent:
                    messages.warning(request, err_msg)

    cooldown_remaining = _remaining_resend_seconds(verification)

    if request.method == 'POST':
        action = request.POST.get('action', 'verify_code').strip()
        if action == 'update_email':
            new_email = request.POST.get('email', '').strip().lower()
            if not new_email or '@' not in new_email or '.' not in new_email.split('@')[-1]:
                messages.error(request, _("يرجى إدخال بريد إلكتروني صحيح."))
            elif User.objects.filter(email__iexact=new_email).exclude(pk=user.pk).exists():
                messages.error(request, _("هذا البريد الإلكتروني مستخدم لحساب آخر بالفعل."))
            else:
                old_email = (user.email or '').strip().lower()
                user.email = new_email
                update_fields = ['email']
                if (user.username or '').strip().lower() == old_email and not User.objects.filter(username__iexact=new_email).exclude(pk=user.pk).exists():
                    user.username = new_email
                    update_fields.append('username')
                user.save(update_fields=update_fields)
                verification = issue_email_verification(user, update_sent_time=True)
                sent, err_msg = send_verification_email(request, user, verification)
                if sent:
                    messages.success(request, _("تم تحديث البريد وإرسال كود التحقق الجديد."))
                else:
                    messages.warning(request, err_msg)
            return redirect('verify_email_page')

        code = request.POST.get('code', '').strip()
        if verification.is_expired():
            messages.error(request, _("انتهت صلاحية كود التفعيل. اضغط على إعادة إرسال الكود والرابط."))
        elif not code or not secrets.compare_digest(code, verification.code):
            messages.error(request, _("كود التفعيل غير صحيح. تأكد من الأرقام الستة وحاول مرة أخرى."))
        else:
            verification.mark_verified()
            if not request.user.is_authenticated or request.user.pk != user.pk:
                login(request, user, backend='accounts.backends.MultiFieldAuthBackend')
            request.session.pop('pending_verification_user_id', None)
            messages.success(request, _("تم تفعيل بريدك الإلكتروني بنجاح!"))
            return redirect('complete_profile')

    return render(request, 'accounts/verify_email.html', {
        'target_email': user.email,
        'cooldown_remaining': cooldown_remaining,
        'is_expired': verification.is_expired() if verification else False,
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

    verification.mark_verified()

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

    try:
        verification = user.email_verification
    except EmailVerification.DoesNotExist:
        verification = None

    remaining = _remaining_resend_seconds(verification)
    if remaining > 0:
        messages.warning(
            request,
            _("يرجى الانتظار %(sec)s ثانية قبل إعادة إرسال البريد.") % {'sec': remaining},
        )
        return redirect('verify_email_page')

    if not user.email:
        messages.error(request, _("يرجى إضافة بريد إلكتروني صحيح أولاً لتتمكن من استلام كود التفعيل."))
        return redirect('verify_email_page')

    verification = issue_email_verification(user, update_sent_time=True)
    sent, err_msg = send_verification_email(request, user, verification)
    if sent:
        messages.success(request, _("تم إعادة إرسال رابط وكود التفعيل إلى بريدك الإلكتروني."))
    else:
        messages.warning(request, err_msg)
    return redirect('verify_email_page')

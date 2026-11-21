"""
accounts/views.py — إدارة إكمال الملفات الشخصية والتوجيه
"""
from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth.decorators import login_required
from django.contrib import messages
from django.http import JsonResponse
from django.utils import timezone
from django.utils.translation import gettext as _
from django.views.decorators.http import require_POST
from datetime import timedelta
import json
import random
import secrets
import string
from django.contrib.auth import login, logout, update_session_auth_hash

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
                tp, created = TeacherProfile.objects.get_or_create(
                    user=saved_user,
                    defaults={
                        'bio': form.cleaned_data.get('bio', ''),
                        'subject': form.cleaned_data['subject'],
                        'is_approved': False,
                        'subscription_end_date': None,
                        'is_trial_used': False,
                        'current_plan': None,
                    },
                )
                if not created:
                    tp.bio = form.cleaned_data.get('bio', '')
                    tp.subject = form.cleaned_data['subject']
                    tp.save(update_fields=['bio', 'subject'])
                try:
                    from core.notifications_service import notify_users_bulk
                    admins = User.objects.filter(Q(is_superuser=True) | Q(role='admin'), is_active=True)
                    notify_users_bulk(
                        admins,
                        'طلب اعتماد معلم جديد',
                        f"سجّل المعلم {saved_user.get_full_name() or saved_user.email} وهو بانتظار موافقتك للظهور وتفعيل الحساب.",
                        link='/admin-panel/users/',
                    )
                except Exception:
                    pass

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


@login_required
def web_trusted_devices(request):
    """
    شاشة إدارة الأجهزة المتصلة (تطبيق الأندرويد ومتصفحات الويب) على موقع المنصة،
    تتيح عرض حد الأجهزة، إنهاء جلسة، إلغاء تفويض جهاز، أو الإبلاغ عن جهاز غير مألوف.
    """
    from api_v1.device_security_service import (
        WEB_PACKAGE_NAME,
        build_web_device_info,
        check_device_allowed,
        get_or_create_web_installation_id,
        get_user_device_limit,
        record_security_event,
        register_or_update_device,
        revoke_user_device,
        serialize_device_summary,
    )
    from api_v1.models import DeviceTrustStatus, RegisteredDevice

    user = request.user
    installation_id = get_or_create_web_installation_id(request)
    if not request.session.session_key:
        request.session.save()

    def _try_activate_current_browser() -> bool:
        reg = register_or_update_device(
            request=request,
            user=user,
            installation_id=installation_id,
            device_info=build_web_device_info(request),
            token_jti=f"web:{request.session.session_key or installation_id[:24]}",
        )
        if reg.get('allowed'):
            request.session['web_device_registered_id'] = installation_id
            request.session['web_device_session_uuid'] = reg.get('session_uuid', '')
            request.session.pop('web_device_limit_error', None)
            return True
        if reg.get('error'):
            request.session['web_device_limit_error'] = reg['error']
        return False

    if request.method == 'POST':
        action = (request.POST.get('action') or '').strip()

        if action == 'activate_current':
            if _try_activate_current_browser():
                messages.success(request, _("تم تفعيل وتسجيل هذا المتصفح بنجاح."))
            else:
                err = request.session.get('web_device_limit_error') or _(
                    "تعذر تسجيل هذا المتصفح. يرجى إزالة أحد الأجهزة القديمة أولاً."
                )
                messages.error(request, err)
            return redirect('web_trusted_devices')

        device_uuid = (request.POST.get('device_uuid') or '').strip()
        device = None
        if device_uuid:
            try:
                device = RegisteredDevice.objects.filter(user=user, device_uuid=device_uuid).first()
            except Exception:
                device = None

        if device is None:
            messages.error(request, _("الجهاز المطلوب غير موجود أو لا ينتمي لحسابك."))
            return redirect('web_trusted_devices')

        is_same_browser = device.installation_id == installation_id

        if action == 'revoke':
            revoke_user_device(
                device=device,
                actor=user,
                request=request,
                mode='revoke',
                reason='Revoked by user from web trusted devices panel',
            )
            if is_same_browser:
                request.session.pop('web_device_registered_id', None)
                request.session.pop('web_device_session_uuid', None)
                logout(request)
                messages.info(request, _("تم إلغاء تفويض هذا المتصفح وتسجيل الخروج منه."))
                return redirect('account_login')

            if request.session.get('web_device_limit_error') and _try_activate_current_browser():
                messages.success(request, _("تم إلغاء تفويض الجهاز المحدد وتفعيل متصفحك الحالي تلقائيًا."))
            else:
                messages.success(request, _("تم إلغاء تفويض الجهاز وإنهاء كافة جلساته بنجاح."))
            return redirect('web_trusted_devices')

        if action == 'logout':
            revoke_user_device(
                device=device,
                actor=user,
                request=request,
                mode='logout',
                reason='Logged out remotely from web trusted devices panel',
            )
            if is_same_browser:
                request.session.pop('web_device_registered_id', None)
                request.session.pop('web_device_session_uuid', None)
                logout(request)
                messages.info(request, _("تم تسجيل الخروج من هذا المتصفح."))
                return redirect('account_login')

            messages.success(request, _("تم إنهاء الجلسة النشطة على الجهاز المحدد."))
            return redirect('web_trusted_devices')

        if action == 'report_unfamiliar':
            reason = (request.POST.get('reason') or '').strip()[:255] or _(
                "أبلغ المستخدم أن هذا الجهاز غير مألوف له عبر لوحة الويب"
            )
            revoke_user_device(
                device=device,
                actor=user,
                request=request,
                mode='revoke',
                reason=str(reason),
            )
            device.unfamiliar_reported = True
            device.save(update_fields=['unfamiliar_reported', 'updated_at'])
            record_security_event(
                event_type='unfamiliar_device_reported',
                severity='high',
                risk_score=35,
                user=user,
                device=device,
                installation_id=device.installation_id,
                request=request,
                action_taken='device_revoked_and_flagged',
                details={'reason': str(reason), 'source': 'web'},
            )
            if is_same_browser:
                request.session.pop('web_device_registered_id', None)
                request.session.pop('web_device_session_uuid', None)
                logout(request)
                messages.warning(request, _("تم تسجيل الخروج وحظر الجلسة وتوثيق بلاغ الجهاز غير المألوف."))
                return redirect('account_login')

            if request.session.get('web_device_limit_error'):
                _try_activate_current_browser()
            messages.warning(request, _("تم تسجيل البلاغ وإلغاء تفويض الجهاز المريب فورًا."))
            return redirect('web_trusted_devices')

        messages.warning(request, _("إجراء غير معروف."))
        return redirect('web_trusted_devices')

    devices_qs = RegisteredDevice.objects.filter(user=user).order_by('-is_active', '-last_active_at')
    device_limit = get_user_device_limit(user)
    active_count = devices_qs.filter(is_active=True).exclude(
        trust_status__in=[DeviceTrustStatus.REVOKED, DeviceTrustStatus.BLOCKED]
    ).count()
    current_allowed, current_code, current_err = check_device_allowed(user, installation_id)

    if current_allowed:
        request.session.pop('web_device_limit_error', None)
        limit_error = ''
    else:
        limit_error = request.session.get('web_device_limit_error') or current_err or ''

    device_rows = []
    for dev in devices_qs:
        summary = serialize_device_summary(dev, current_installation_id=installation_id)
        device_rows.append({
            'device': dev,
            'summary': summary,
            'is_web': dev.package_name == WEB_PACKAGE_NAME,
            'is_current': summary['is_current_device'],
            'current_session_active': summary['current_session_active'],
        })

    return render(request, 'accounts/devices.html', {
        'device_rows': device_rows,
        'device_limit': device_limit,
        'active_count': active_count,
        'current_installation_id': installation_id,
        'current_allowed': current_allowed,
        'current_code': current_code,
        'limit_error': limit_error,
    })


@login_required
@require_POST
def web_device_traits_sync(request):
    """
    يستقبل خصائص المتصفح غير الحساسة (الدقة، معالج الرسوميات WebGL، المنطقة الزمنية، إشارات WebDriver)
    ليدمجها مع ترويسات الطلب في الخادم وتحديث بصمة fp_v1 وتقييم المخاطر.
    """
    user = request.user
    if getattr(user, 'is_superuser', False) or getattr(user, 'role', '') == 'admin':
        return JsonResponse({'ok': True, 'skipped': 'admin'})

    from api_v1.device_security_service import (
        build_web_device_info,
        check_web_ios_only_lecture_access,
        get_or_create_web_installation_id,
        register_or_update_device,
    )

    payload: dict = {}
    if request.content_type and 'application/json' in request.content_type:
        try:
            loaded = json.loads((request.body or b'{}').decode('utf-8'))
            if isinstance(loaded, dict):
                payload = loaded
        except Exception:
            payload = {}
    else:
        payload = request.POST.dict()

    client_traits = {
        'cpu_arch': payload.get('cpu_arch', ''),
        'cpu_info': payload.get('cpu_info', ''),
        'gpu_renderer': payload.get('gpu_renderer', ''),
        'gpu_vendor': payload.get('gpu_vendor', ''),
        'screen_resolution': payload.get('screen_resolution', ''),
        'timezone': payload.get('timezone', ''),
        'webdriver_detected': bool(payload.get('webdriver_detected')),
        'canvas_hash': payload.get('canvas_hash', ''),
        'webgl_hash': payload.get('webgl_hash', ''),
        'audio_hash': payload.get('audio_hash', ''),
        'navigator_platform': payload.get('navigator_platform', ''),
        'max_touch_points': payload.get('max_touch_points'),
        'touch_support': payload.get('touch_support'),
        'color_depth': payload.get('color_depth', ''),
        'languages': payload.get('languages', ''),
    }

    installation_id = get_or_create_web_installation_id(request)
    if not request.session.session_key:
        request.session.save()

    reg = register_or_update_device(
        request=request,
        user=user,
        installation_id=installation_id,
        device_info=build_web_device_info(request, client_traits=client_traits),
        token_jti=f"web:{request.session.session_key or installation_id[:24]}",
    )
    if reg.get('allowed'):
        request.session['web_device_registered_id'] = installation_id
        request.session['web_device_session_uuid'] = reg.get('session_uuid', '')
        request.session.pop('web_device_limit_error', None)
        dev_summary = reg.get('device') or {}
        dev_obj = reg.get('device_obj')
        ios_res = check_web_ios_only_lecture_access(
            request,
            user,
            client_traits=client_traits,
            force_web=True,
        )
        return JsonResponse({
            'ok': True,
            'fingerprint': getattr(dev_obj, 'current_fingerprint', '') if dev_obj else '',
            'trust_status': dev_summary.get('trust_status', ''),
            'risk_score': dev_summary.get('risk_score', 0),
            'risk_level': dev_summary.get('risk_level', 'low'),
            'ios_lecture_allowed': bool(ios_res.get('allowed')),
            'device_kind': ios_res.get('device_kind', ''),
        })

    if reg.get('code') == 'WEB_FINGERPRINT_MISMATCH':
        request.session.pop('web_device_registered_id', None)
        request.session.pop('web_device_session_uuid', None)

    return JsonResponse({
        'ok': False,
        'code': reg.get('code', 'DEVICE_NOT_ALLOWED'),
        'error': reg.get('error', ''),
    }, status=403)


"""
core/views.py — الصفحات العامة للمنصة
(تم نقل كل views الإدارة إلى dashboard_admin/views.py)
"""
from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth.decorators import login_required
from django.db.models import Q
from django.utils.translation import gettext as _

from teachers.models import TeacherProfile
from core.models import Subject, Notification


# ==========================================================
# 1. الصفحة الرئيسية
# ==========================================================
def home(request):
    teachers = TeacherProfile.ordered_for_home()
    subjects = Subject.objects.all()

    q_grade   = request.GET.get('grade', '')
    q_subject = request.GET.get('subject', '')

    if q_subject:
        teachers = teachers.filter(subject__id=q_subject)
    if q_grade:
        teachers = teachers.filter(groups__grade=q_grade).distinct()

    return render(request, 'home.html', {
        'teachers': teachers[:6],
        'subjects': subjects,
    })


# ==========================================================
# 2. توجيه صفحة التسجيل (اختيار الدور)
# ==========================================================
def signup_redirect(request, role):
    VALID_ROLES = {'student', 'teacher', 'assistant'}
    if role in VALID_ROLES:
        request.session['selected_role'] = role

    role_names = {
        'student':   _('طالب'),
        'teacher':   _('معلم'),
        'assistant': _('مساعد'),
    }
    return render(request, 'account/role_signup.html', {
        'role':      role,
        'role_name': role_names.get(role, _('مستخدم')),
    })


# ==========================================================
# 3. التوجيه الذكي بعد تسجيل الدخول
# ==========================================================
@login_required
def custom_login_redirect(request):
    user = request.user

    # ✅ المالك والأدمن → لوحة الإدارة
    if user.is_superuser or user.role == 'admin':
        return redirect('admin_panel:dashboard')

    if user.requires_email_verification():
        request.session['pending_verification_user_id'] = user.id
        return redirect('verify_email_page')

    # لو ما عندوش كود → يكمل بياناته
    if not user.custom_id:
        return redirect('complete_profile')

    # ✅ التوجيه حسب الدور
    ROLE_REDIRECTS = {
        'student':   'student_dashboard',
        'teacher':   'teacher_dashboard',
        'assistant': 'assistant_dashboard',
    }

    if user.role == 'assistant':
        if not hasattr(user, 'assistant_profile') or not user.assistant_profile.phone:
            return redirect('complete_profile')

    target = ROLE_REDIRECTS.get(user.role)
    if target:
        return redirect(target)

    # دور 'center' أو دور غير معروف → الرئيسية مع رسالة توضيح
    from django.contrib import messages
    messages.info(request, _("لوحة التحكم الخاصة بك قيد التطوير."))
    return redirect('home')


# ==========================================================
# 4. صفحة الحظر
# ==========================================================
def banned_page(request):
    return render(request, 'core/banned.html')


# ==========================================================
# 5. الإشعارات
# ==========================================================
@login_required
def read_notification(request, notif_id):
    from django.utils.http import url_has_allowed_host_and_scheme

    notif = get_object_or_404(Notification, id=notif_id, recipient=request.user)
    notif.is_read = True
    notif.save(update_fields=['is_read'])

    if notif.link and url_has_allowed_host_and_scheme(
        notif.link,
        allowed_hosts={request.get_host()},
        require_https=request.is_secure(),
    ):
        return redirect(notif.link)
    return redirect('all_notifications')


@login_required
def all_notifications(request):
    notifs = Notification.objects.filter(recipient=request.user).order_by('-created_at')
    notifs.filter(is_read=False).update(is_read=True)
    return render(request, 'core/notifications.html', {'notifs': notifs})


# ==========================================================
# 6. دليل المنصة والصفحات القانونية
# ==========================================================
def platform_guide(request):
    return render(request, 'core/guide.html')


def privacy_policy(request):
    return render(request, 'core/privacy.html')


def terms_of_service(request):
    return render(request, 'core/terms.html')

# ==========================================================
# 7. صفحة الدفع اليدوي
# ==========================================================
from django.contrib import messages
from .forms import ManualPaymentForm

@login_required
def manual_checkout_view(request):
    from teachers.models import CoursePackage, SubscriptionPlan

    payment_type = (request.GET.get('type') or '').strip()
    raw_target_id = (request.GET.get('id') or '').strip()

    try:
        target_id = int(raw_target_id)
    except (TypeError, ValueError):
        messages.error(request, _("بيانات الدفع غير مكتملة أو غير صالحة."))
        return redirect('home')

    # اعتماد السعر من قاعدة البيانات فقط وتجاهل أي مبلغ مُرسل في رابط GET
    authoritative_amount = None
    if payment_type == 'package':
        package = CoursePackage.objects.filter(id=target_id, is_active=True).first()
        if package:
            authoritative_amount = package.price
    elif payment_type == 'subscription':
        plan = SubscriptionPlan.objects.filter(id=target_id).first()
        if plan:
            authoritative_amount = plan.price
    else:
        messages.error(request, _("نوع الدفع غير صالح."))
        return redirect('home')

    if authoritative_amount is None:
        messages.error(request, _("العنصر المطلوب للدفع غير موجود أو غير متاح."))
        return redirect('home')

    if request.method == 'POST':
        form = ManualPaymentForm(request.POST, request.FILES)
        if form.is_valid():
            payment = form.save(commit=False)
            payment.user = request.user
            payment.payment_type = payment_type
            payment.target_id = target_id
            payment.amount = authoritative_amount
            payment.save()
            messages.success(request, _("تم إرسال طلب الدفع بنجاح. يرجى الانتظار حتى تتم مراجعته من قبل الإدارة."))
            if request.user.role == 'student':
                return redirect('student_dashboard')
            elif request.user.role == 'teacher':
                return redirect('teacher_dashboard')
            return redirect('home')
    else:
        form = ManualPaymentForm()

    return render(request, 'core/manual_checkout.html', {
        'amount': authoritative_amount,
        'payment_type': payment_type,
        'form': form,
    })

# ==========================================================
# 8. AJAX - جلب الدروس للمناهج
# ==========================================================
from django.http import JsonResponse
from .models import CurriculumUnit

@login_required
def ajax_get_lessons(request):
    grade = request.GET.get('grade')
    subject_id = request.GET.get('subject')
    term = request.GET.get('term')

    if not all([grade, subject_id, term]):
        return JsonResponse({'error': 'Missing parameters'}, status=400)

    units = CurriculumUnit.objects.filter(
        grade=grade, subject_id=subject_id, term=term
    ).prefetch_related('lessons').order_by('order')

    data = []
    for unit in units:
        unit_data = {
            'id': f"unit_{unit.id}",
            'title': unit.title,
            'lessons': [{'id': lesson.id, 'title': lesson.title} for lesson in unit.lessons.order_by('order')]
        }
        data.append(unit_data)

    return JsonResponse({'units': data})

# ==========================================================
# 9. صفحة الباقات العامة (Public Pricing Page)
# ==========================================================
from teachers.models import SubscriptionPlan

def public_plans(request):
    plans = SubscriptionPlan.objects.all().order_by('price')
    return render(request, 'core/public_plans.html', {'plans': plans})


# ==========================================================
# 10. رابط تسجيل الدخول المباشر لمرة واحدة (Auto Login Link)
# ==========================================================
def one_time_login_view(request, token):
    from accounts.models import OneTimeLoginLink
    from django.contrib.auth import login
    from django.shortcuts import get_object_or_404, redirect
    from django.contrib import messages

    link = get_object_or_404(OneTimeLoginLink, token=token)
    if link.is_used:
        messages.error(request, "عذراً، هذا الرابط تم استخدامه من قبل وانتهت صلاحيته.")
        return redirect('home')

    link.is_used = True
    link.save(update_fields=['is_used'])

    login(request, link.user, backend='accounts.backends.MultiFieldAuthBackend')
    messages.success(request, f"مرحباً بك {link.user.get_full_name() or link.user.email}، تم تسجيل الدخول بنجاح.")
    return redirect(link.user.get_dashboard_url())


# ==========================================================
# 11. شات الدعم الفني المباشر للمستخدمين على الويب
# ==========================================================
@login_required
def support_chat_page(request, thread_id=None):
    from django.contrib import messages
    from django.http import HttpResponseForbidden, JsonResponse
    from core.models import SupportMessage, SupportThread
    from api_v1.views_support import (
        _is_support_admin_user,
        append_support_message,
        serialize_support_message,
    )

    is_admin = _is_support_admin_user(request.user)
    if thread_id is not None:
        thread = get_object_or_404(SupportThread.objects.select_related('user'), pk=thread_id)
        if thread.user_id != request.user.id and not is_admin:
            return HttpResponseForbidden('ليس لديك صلاحية للوصول لهذه المحادثة.')
    else:
        thread = (
            SupportThread.objects.select_related('user')
            .filter(user=request.user)
            .order_by('-last_message_at', '-id')
            .first()
        )
        if thread is None:
            thread = SupportThread.objects.create(user=request.user)

    acting_as_admin = is_admin and thread.user_id != request.user.id

    if acting_as_admin:
        if thread.unread_for_admin:
            thread.unread_for_admin = 0
            thread.save(update_fields=['unread_for_admin'])
        SupportMessage.objects.filter(thread=thread, is_from_admin=False, is_read=False).update(is_read=True)
    else:
        if thread.unread_for_user:
            thread.unread_for_user = 0
            thread.save(update_fields=['unread_for_user'])
        SupportMessage.objects.filter(thread=thread, is_from_admin=True, is_read=False).update(is_read=True)

    if request.method == 'POST':
        body = str(request.POST.get('body') or '').strip()
        if not body:
            if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
                return JsonResponse({'error': 'يرجى كتابة نص الرسالة.'}, status=400)
            messages.error(request, 'يرجى كتابة نص الرسالة.')
        else:
            msg = append_support_message(
                thread=thread,
                sender=request.user,
                body=body[:4000],
                is_from_admin=acting_as_admin,
            )
            if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
                return JsonResponse({'message': serialize_support_message(msg)})
            return redirect('support_chat_thread', thread_id=thread.id)

    if request.GET.get('poll') == '1':
        raw_after = str(request.GET.get('after_id') or '').strip()
        qs = thread.messages.select_related('sender')
        if raw_after.isdigit():
            qs = qs.filter(id__gt=int(raw_after)).order_by('id')
        else:
            qs = qs.order_by('id')
        return JsonResponse({
            'messages': [serialize_support_message(m) for m in qs[:100]],
            'status': thread.status,
        })

    chat_messages = list(thread.messages.select_related('sender').order_by('created_at', 'id')[:150])
    return render(request, 'core/support_chat.html', {
        'thread': thread,
        'chat_messages': chat_messages,
        'acting_as_admin': acting_as_admin,
        'last_msg_id': chat_messages[-1].id if chat_messages else 0,
    })

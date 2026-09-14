"""
core/views.py — الصفحات العامة للمنصة
(تم نقل كل views الإدارة إلى dashboard_admin/views.py)
"""
from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth.decorators import login_required
from django.db.models import Q

from teachers.models import TeacherProfile
from core.models import Subject, Notification


# ==========================================================
# 1. الصفحة الرئيسية
# ==========================================================
def home(request):
    teachers = (
        TeacherProfile.objects
        .select_related('user', 'subject')
        .filter(user__is_banned=False)
        .order_by('-id')
    )
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
        'student':   'طالب',
        'teacher':   'معلم',
        'assistant': 'مساعد',
    }
    return render(request, 'account/role_signup.html', {
        'role':      role,
        'role_name': role_names.get(role, 'مستخدم'),
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
    messages.info(request, "لوحة التحكم الخاصة بك قيد التطوير.")
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
    notif = get_object_or_404(Notification, id=notif_id, recipient=request.user)
    notif.is_read = True
    notif.save(update_fields=['is_read'])

    if notif.link:
        return redirect(notif.link)
    return redirect('all_notifications')


@login_required
def all_notifications(request):
    notifs = Notification.objects.filter(recipient=request.user).order_by('-created_at')
    notifs.filter(is_read=False).update(is_read=True)
    return render(request, 'core/notifications.html', {'notifs': notifs})


# ==========================================================
# 6. دليل المنصة
# ==========================================================
def platform_guide(request):
    return render(request, 'core/guide.html')

# ==========================================================
# 7. صفحة الدفع اليدوي
# ==========================================================
from django.contrib import messages
from .forms import ManualPaymentForm

@login_required
def manual_checkout_view(request):
    # استقبال المتغيرات من الـ session أو GET
    payment_type = request.GET.get('type')
    target_id = request.GET.get('id')
    amount = request.GET.get('amount')

    if not payment_type or not target_id or not amount:
        messages.error(request, "بيانات الدفع غير مكتملة.")
        return redirect('home')

    if request.method == 'POST':
        form = ManualPaymentForm(request.POST, request.FILES)
        if form.is_valid():
            payment = form.save(commit=False)
            payment.user = request.user
            payment.payment_type = payment_type
            payment.target_id = target_id
            payment.amount = amount
            payment.save()
            messages.success(request, "تم إرسال طلب الدفع بنجاح. يرجى الانتظار حتى تتم مراجعته من قبل الإدارة.")
            if request.user.role == 'student':
                return redirect('student_dashboard')
            elif request.user.role == 'teacher':
                return redirect('teacher_dashboard')
            return redirect('home')
    else:
        form = ManualPaymentForm()

    return render(request, 'core/manual_checkout.html', {
        'amount': amount,
        'payment_type': payment_type,
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

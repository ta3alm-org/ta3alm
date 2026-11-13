"""
accounts/views.py — إدارة إكمال الملفات الشخصية والتوجيه
"""
from django.shortcuts import render, redirect
from django.contrib.auth.decorators import login_required
from django.contrib import messages
from django.utils import timezone
from django.utils.translation import gettext as _
from datetime import timedelta
import random
import string
from django.contrib.auth import update_session_auth_hash

from .forms import CompleteStudentProfileForm, CompleteTeacherProfileForm, CompleteAssistantProfileForm
from .models import StudentProfile
from teachers.models import TeacherProfile, SubscriptionPlan
from assistants.models import AssistantProfile


@login_required
def complete_profile(request):
    user = request.user

    # ✅ المالك أو الأدمن لا يحتاج إكمال بيانات — يُعاد توجيهه مباشرة
    if user.is_superuser or user.role == 'admin':
        return redirect('admin_panel:dashboard')

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
from django.contrib.auth import login
from .models import User

def manual_signup(request):
    if request.method == 'POST':
        full_name = request.POST.get('full_name', '').strip()
        email = request.POST.get('email', '').strip()
        phone = request.POST.get('phone', '').strip()
        password = request.POST.get('password', '')
        confirm_password = request.POST.get('confirm_password', '')
        role = request.POST.get('role', request.session.get('selected_role', 'student'))

        if password != confirm_password:
            messages.error(request, _("كلمتا المرور غير متطابقتين."))
            return redirect('signup_redirect', role=role)

        if User.objects.filter(email=email).exists():
            messages.error(request, _("هذا البريد الإلكتروني مستخدم بالفعل."))
            return redirect('signup_redirect', role=role)

        if User.objects.filter(phone=phone).exists():
            messages.error(request, _("رقم الهاتف هذا مستخدم بالفعل."))
            return redirect('signup_redirect', role=role)

        # إنشاء الحساب (استخدام البريد كاسم مستخدم)
        user = User.objects.create_user(
            username=email,
            email=email,
            password=password,
            phone=phone,
            role=role
        )
        if full_name:
            parts = full_name.split(' ', 1)
            user.first_name = parts[0]
            if len(parts) > 1:
                user.last_name = parts[1]
            user.save()

        # تسجيل الدخول وتوجيه لاستكمال البيانات
        login(request, user, backend='accounts.auth_backends.MultiFieldAuthBackend')
        return redirect('complete_profile')

    return redirect('home')

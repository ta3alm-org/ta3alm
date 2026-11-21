"""accounts.views.profile
Extracted from accounts/views.py.
"""

from django.shortcuts import (
    render,
    redirect,
)
from django.contrib.auth.decorators import login_required
from django.contrib import messages
from django.db.models import Q
from django.utils.translation import gettext as _
import random
import string
from django.contrib.auth import update_session_auth_hash
from accounts.forms import (
    CompleteStudentProfileForm,
    CompleteTeacherProfileForm,
    CompleteAssistantProfileForm,
)
from accounts.models import (
    StudentProfile,
    User,
)
from teachers.models import TeacherProfile
from assistants.models import AssistantProfile


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
        is_complete = (
            hasattr(user, 'teacher_profile')
            and bool(user.teacher_profile.subject_id)
            and bool(user.phone and len(user.phone.strip()) >= 11)
            and bool(user.teacher_profile.image)
        )
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
        form = FormClass(request.POST, request.FILES, instance=user)
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
                uploaded_image = form.cleaned_data.get('image')
                defaults = {
                    'bio': form.cleaned_data.get('bio', ''),
                    'subject': form.cleaned_data['subject'],
                    'is_approved': False,
                    'subscription_end_date': None,
                    'is_trial_used': False,
                    'current_plan': None,
                }
                if uploaded_image:
                    defaults['image'] = uploaded_image
                tp, created = TeacherProfile.objects.get_or_create(
                    user=saved_user,
                    defaults=defaults,
                )
                if not created:
                    tp.bio = form.cleaned_data.get('bio', '')
                    tp.subject = form.cleaned_data['subject']
                    update_fields = ['bio', 'subject']
                    if uploaded_image:
                        tp.image = uploaded_image
                        update_fields.append('image')
                    tp.save(update_fields=update_fields)
                if created or not tp.is_approved:
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

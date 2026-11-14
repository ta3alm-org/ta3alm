"""
accounts/signals.py — معالجة إشارات التسجيل والدخول
"""
from django.dispatch import receiver
from allauth.account.signals import user_signed_up, user_logged_in
from django.contrib import messages


@receiver(user_signed_up)
def set_role_on_signup(request, user, **kwargs):
    """
    يُعيّن الدور عند التسجيل الجديد.

    ⚠️ قواعد صارمة:
    - المالك (is_superuser) → لا يُلمَس أبداً.
    - دور 'admin' موجود → لا يُلمَس.
    - باقي الأدوار تأتي من الجلسة فقط.
    """
    # حماية المالك والأدمن — لا تُعدِّل دورهم أبداً
    if user.is_superuser or user.role == 'admin':
        return

    role = request.session.get('selected_role', '').strip()

    # قائمة الأدوار المسموح بتعيينها عبر التسجيل العادي
    ALLOWED_ROLES = {'student', 'teacher', 'assistant'}

    if role in ALLOWED_ROLES:
        user.role = role
        user.save(update_fields=['role'])

    # تنظيف الجلسة
    request.session.pop('selected_role', None)


@receiver(user_logged_in)
def check_role_on_login(request, user, **kwargs):
    """
    عند الدخول: لو في الجلسة دور مختلف عن دور الحساب، نُنبِّه المستخدم.
    ⚠️ لا نُعدِّل الدور هنا — فقط تنبيه.
    """
    # المالك والأدمن لا يحتاجان لأي تنبيه
    if user.is_superuser or user.role == 'admin':
        request.session.pop('selected_role', None)
        return

    if user.requires_email_verification():
        try:
            if user.socialaccount_set.exists():
                verification = user.email_verification
                verification.is_verified = True
                verification.save(update_fields=['is_verified'])
        except Exception:
            pass

    selected_role = request.session.get('selected_role', '')
    if selected_role and user.role and user.role != selected_role:
        messages.warning(
            request,
            f"حسابك مسجل بالفعل كـ «{user.get_role_display()}»، تم توجيهك للوحتك."
        )
    request.session.pop('selected_role', None)
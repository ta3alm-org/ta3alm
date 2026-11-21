"""api_v1.services.auth_service
Extracted from api_v1/views_auth.py.
"""

import json
import urllib.parse
import urllib.request
from django.contrib.auth import get_user_model
from django.db.models import Q
from accounts.email_verification import (
    issue_email_verification,
    send_verification_email,
)
from accounts.models import (
    EmailVerification,
    StudentProfile,
)
from assistants.models import AssistantProfile
from core.models import (
    SiteSetting,
    Subject,
)
from api_v1.device_security_service import register_or_update_device

User = get_user_model()


def _resolve_subject_input(raw_subject):
    if raw_subject in (None, ''):
        return None
    raw_str = str(raw_subject).strip()
    if not raw_str:
        return None
    if raw_str.isdigit():
        return Subject.objects.filter(id=int(raw_str)).first()
    subj = (
        Subject.objects.filter(name__iexact=raw_str).first()
        or Subject.objects.filter(name__icontains=raw_str).first()
    )
    if subj is None:
        subj = Subject.objects.create(name=raw_str[:100])
    return subj


def ensure_user_role_profile(user) -> None:
    """يضمن وجود ملف الدور للطالب والمساعد عند الإنشاء (بينما يُنشأ ملف المعلم فقط بعد استكمال البيانات ثم مراجعة الإدارة)."""
    if not user or not getattr(user, 'pk', None):
        return
    if user.role == 'student':
        StudentProfile.objects.get_or_create(user=user, defaults={'parent_phone': ''})
    elif user.role == 'assistant':
        AssistantProfile.objects.get_or_create(user=user, defaults={'phone': user.phone or ''})


def _notify_admins_teacher_pending(teacher_profile) -> None:
    try:
        from core.notifications_service import notify_users_bulk
        admins = User.objects.filter(Q(is_superuser=True) | Q(role='admin'), is_active=True)
        teacher_name = teacher_profile.user.get_full_name() or teacher_profile.user.email or teacher_profile.user.username
        notify_users_bulk(
            admins,
            'طلب اعتماد معلم جديد',
            f'قام المعلم {teacher_name} بالتسجيل وهو بانتظار موافقة الإدارة للظهور للطلاب.',
            link='/admin-panel/users/',
        )
    except Exception:
        pass


def _extract_installation_id(request) -> str:
    return str(
        request.data.get('installation_id')
        or request.data.get('device_id')
        or request.META.get('HTTP_X_DEVICE_ID')
        or request.META.get('HTTP_X_INSTALLATION_ID')
        or ''
    ).strip()


def _ensure_verification_otp_sent(request, user, force_new: bool = False) -> tuple[bool, bool, str]:
    """
    يتحقق مما إذا كان المستخدم غير مؤكد، ويُصدر/يُرسل كود OTP من 6 أرقام تلقائياً إذا لزم الأمر.
    يعيد: (requires_verification, otp_sent_now, message_or_error)
    """
    if not hasattr(user, 'requires_email_verification') or not user.requires_email_verification():
        return False, False, ''

    try:
        verification = user.email_verification
    except EmailVerification.DoesNotExist:
        verification = None

    should_issue = (
        force_new
        or verification is None
        or not verification.code
        or verification.is_expired()
    )
    if should_issue:
        if verification is None or force_new or verification.can_resend(cooldown_seconds=60):
            verification = issue_email_verification(user, update_sent_time=True)
            if user.email:
                sent, err = send_verification_email(request, user, verification)
                return True, sent, err
            return True, False, 'يرجى إضافة بريد إلكتروني صحيح لتأكيد الحساب.'
    return True, False, ''


def _handle_auth_device_registration(request, user, tokens: dict) -> tuple[bool, dict | None]:
    """يسجّل/يحدّث الجهاز بعد نجاح المصادقة عند توفر installation_id دون كسر العملاء القدامى."""
    installation_id = _extract_installation_id(request)
    raw_info = request.data.get('device_info')
    device_info = raw_info if isinstance(raw_info, dict) else {}
    if not installation_id and not device_info:
        return True, None

    raw_build = str(
        device_info.get('app_build_number')
        or request.META.get('HTTP_X_APP_BUILD')
        or ''
    ).strip()
    if raw_build.isdigit():
        try:
            site_settings = SiteSetting.load()
            client_build = int(raw_build)
            if client_build < site_settings.get_effective_min_version_code():
                return False, {
                    'error': 'يتوفر تحديث إجباري جديد للتطبيق. يرجى تحديث التطبيق لأحدث إصدار للمتابعة.',
                    'code': 'APP_UPDATE_REQUIRED',
                    'app_update': site_settings.build_app_update_payload(
                        request=request,
                        client_version_code=client_build,
                    ),
                }
        except Exception:
            pass

    outcome = register_or_update_device(
        request=request,
        user=user,
        installation_id=installation_id,
        device_info=device_info,
        token_jti=tokens.get('access_jti', ''),
        refresh_jti=tokens.get('refresh_jti', ''),
    )
    clean_outcome = {k: v for k, v in outcome.items() if k not in ('device_obj', 'session_obj')}
    return bool(clean_outcome.get('allowed')), clean_outcome


def _verify_google_tokens(id_token: str = '', access_token: str = '') -> dict | None:
    """
    يتحقق من صحة id_token أو access_token مع خوادم Google الرسمية
    ويعيد بيانات الحساب (email, given_name, family_name, sub).
    """
    if id_token:
        try:
            url = f"https://oauth2.googleapis.com/tokeninfo?id_token={urllib.parse.quote(id_token)}"
            req = urllib.request.Request(url, headers={'Accept': 'application/json'})
            with urllib.request.urlopen(req, timeout=8) as resp:
                data = json.loads(resp.read().decode('utf-8'))
                if data.get('email') and data.get('email_verified') in (True, 'true', '1'):
                    return {
                        'email': str(data['email']).strip().lower(),
                        'first_name': str(data.get('given_name') or data.get('name', '').split(' ')[0]).strip(),
                        'last_name': str(data.get('family_name') or '').strip(),
                        'sub': str(data.get('sub') or ''),
                    }
        except Exception:
            pass

    if access_token:
        try:
            url = "https://www.googleapis.com/oauth2/v3/userinfo"
            req = urllib.request.Request(
                url,
                headers={
                    'Authorization': f'Bearer {access_token}',
                    'Accept': 'application/json',
                },
            )
            with urllib.request.urlopen(req, timeout=8) as resp:
                data = json.loads(resp.read().decode('utf-8'))
                if data.get('email'):
                    return {
                        'email': str(data['email']).strip().lower(),
                        'first_name': str(data.get('given_name') or data.get('name', '').split(' ')[0]).strip(),
                        'last_name': str(data.get('family_name') or '').strip(),
                        'sub': str(data.get('sub') or ''),
                    }
        except Exception:
            pass

    return None

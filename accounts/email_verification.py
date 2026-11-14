"""
accounts/email_verification.py
توليد وإرسال رسالة تفعيل البريد الإلكتروني (رابط تفعيل مباشر + كود OTP من 6 أرقام)
عبر خدمة Zoho Mail المربوطة في المنصة، مع Fallback لبريد Django القياسي.
"""
from datetime import timedelta
import html
import logging
import secrets
import uuid

from django.conf import settings
from django.core.mail import send_mail
from django.urls import reverse
from django.utils import timezone

from .models import EmailVerification

logger = logging.getLogger(__name__)

VERIFICATION_TTL_MINUTES = 30


def _generate_otp_code() -> str:
    return f"{secrets.randbelow(900000) + 100000}"


def issue_email_verification(user, update_sent_time: bool = True) -> EmailVerification:
    """ينشئ أو يحدّث سجل تفعيل البريد للمستخدم برمز OTP ورابط مباشر جديدين."""
    now = timezone.now()
    expires_at = now + timedelta(minutes=VERIFICATION_TTL_MINUTES)
    code = _generate_otp_code()
    token = uuid.uuid4()

    defaults = {
        'token': token,
        'code': code,
        'is_verified': False,
        'expires_at': expires_at,
    }
    if update_sent_time:
        defaults['last_sent_at'] = now

    verification, created = EmailVerification.objects.update_or_create(
        user=user,
        defaults=defaults,
    )
    if not created and not update_sent_time and verification.last_sent_at is None:
        verification.last_sent_at = now
        verification.save(update_fields=['last_sent_at'])
    return verification


def build_verification_email_html(user, verify_url: str, code: str) -> str:
    """يبني قالب HTML متجاوب بألوان منصة تعلّم يحتوي على الرابط المباشر وكود التفعيل."""
    display_name = html.escape(user.first_name or user.get_full_name() or user.email or 'طالبنا العزيز')
    safe_url = html.escape(verify_url, quote=True)
    safe_code = html.escape(code)

    return f"""
<!DOCTYPE html>
<html lang="ar" dir="rtl">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <title>تفعيل حسابك في منصة تعلّم</title>
</head>
<body style="margin:0;padding:0;background-color:#f6f4f2;font-family:Tahoma,Arial,sans-serif;direction:rtl;text-align:right;color:#1f2937;">
  <table role="presentation" width="100%" cellspacing="0" cellpadding="0" style="padding:28px 12px;">
    <tr>
      <td align="center">
        <table role="presentation" width="100%" cellspacing="0" cellpadding="0" style="max-width:580px;background:#ffffff;border-radius:16px;overflow:hidden;box-shadow:0 8px 24px rgba(0,0,0,0.08);border:1px solid #ece7e2;">
          <tr>
            <td style="background:linear-gradient(135deg,#520000,#800000);padding:26px 24px;text-align:center;color:#ffffff;">
              <div style="font-size:24px;font-weight:bold;color:#FFD700;margin-bottom:6px;">منصة تعلّم | Ta3alm</div>
              <div style="font-size:15px;color:#f3e8e8;">تفعيل البريد الإلكتروني وتأكيد الحساب</div>
            </td>
          </tr>
          <tr>
            <td style="padding:28px 24px;line-height:1.8;font-size:15px;">
              <p style="margin:0 0 14px;">أهلاً بك يا <strong>{display_name}</strong>،</p>
              <p style="margin:0 0 22px;color:#4b5563;">
                لتفعيل حسابك في <strong>منصة تعلّم</strong> والوصول إلى لوحتك التعليمية، يمكنك الضغط مباشرة على الزر التالي (سيتم تحويلك إلى الموقع أو التطبيق مباشرة):
              </p>

              <div style="text-align:center;margin:24px 0;">
                <a href="{safe_url}"
                   style="display:inline-block;background-color:#800000;color:#ffffff;text-decoration:none;font-weight:bold;font-size:16px;padding:14px 32px;border-radius:10px;border:2px solid #FFD700;">
                  تفعيل الحساب الآن
                </a>
              </div>

              <div style="background-color:#fdf8ee;border:1px dashed #d4a017;border-radius:12px;padding:18px;margin:22px 0;text-align:center;">
                <div style="font-size:13px;color:#6b7280;margin-bottom:8px;">
                  أو أدخل كود التفعيل التالي في صفحة التأكيد على الموقع:
                </div>
                <div style="font-size:32px;font-weight:bold;letter-spacing:8px;color:#800000;direction:ltr;">
                  {safe_code}
                </div>
              </div>

              <p style="margin:0 0 10px;font-size:13px;color:#6b7280;">
                إذا لم يعمل الزر، يمكنك نسخ الرابط التالي وفتحه في المتصفح:
              </p>
              <p style="margin:0 0 18px;font-size:12px;word-break:break-all;direction:ltr;text-align:left;background:#f9fafb;padding:10px 12px;border-radius:8px;border:1px solid #e5e7eb;">
                <a href="{safe_url}" style="color:#800000;text-decoration:none;">{safe_url}</a>
              </p>
              <p style="margin:0;font-size:13px;color:#6b7280;">
                تنتهي صلاحية هذا الكود والرابط خلال {VERIFICATION_TTL_MINUTES} دقيقة. إذا لم تقم بإنشاء هذا الحساب يمكنك تجاهل هذه الرسالة.
              </p>
            </td>
          </tr>
          <tr>
            <td style="background:#f9fafb;padding:16px 24px;text-align:center;font-size:12px;color:#9ca3af;border-top:1px solid #f0ece8;">
              Ta3alm Educational Platform &bull; support@ta3alm.online
            </td>
          </tr>
        </table>
      </td>
    </tr>
  </table>
</body>
</html>
""".strip()


def send_verification_email(request, user, verification: EmailVerification = None):
    """
    يرسل رسالة تفعيل البريد للمستخدم.
    يُرجع tuple(sent: bool, error_message: str).
    """
    if not user.email:
        return False, 'لا يوجد بريد إلكتروني مسجل لهذا الحساب.'

    if verification is None:
        verification = issue_email_verification(user, update_sent_time=True)

    direct_path = reverse('verify_email_link_direct', kwargs={'token': verification.token})
    verify_url = request.build_absolute_uri(direct_path)
    subject = 'تفعيل حسابك في منصة تعلّم — كود ورابط التفعيل'
    html_body = build_verification_email_html(user, verify_url, verification.code)

    try:
        from services.zoho_mail_service import ZohoMailService
        zoho = ZohoMailService()
        if zoho.is_connected():
            zoho.compose_new_message(
                to_email=user.email,
                subject=subject,
                content=html_body,
            )
            return True, ''
    except Exception as exc:
        logger.error("Zoho verification email failed for %s: %s", user.email, exc)

    # Fallback عبر Django email backend (مفيد في الاختبارات أو عند عدم تفعيل Zoho)
    try:
        plain_body = (
            f"أهلاً بك في منصة تعلّم.\n\n"
            f"لتفعيل حسابك افتح الرابط التالي:\n{verify_url}\n\n"
            f"أو أدخل كود التفعيل المكون من 6 أرقام: {verification.code}\n"
        )
        from_email = getattr(settings, 'DEFAULT_FROM_EMAIL', 'support@ta3alm.online')
        send_mail(
            subject=subject,
            message=plain_body,
            from_email=from_email,
            recipient_list=[user.email],
            html_message=html_body,
            fail_silently=False,
        )
        return True, ''
    except Exception as exc:
        logger.warning("Django send_mail fallback failed for %s: %s", user.email, exc)
        return False, 'تعذر إرسال رسالة التفعيل حاليًا. تأكد من إعدادات خدمة البريد أو حاول إعادة الإرسال.'


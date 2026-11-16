"""
dashboard_admin/models.py
نماذج نظام الإدارة: أدوار المسؤولين وسجل الأحداث
"""
from django.db import models
from django.conf import settings
from django.utils.translation import gettext_lazy as _
from django.utils import timezone


# ==========================================================
# أدوار الإدارة
# ==========================================================
class AdminRole(models.TextChoices):
    OWNER     = 'owner',     _('مالك المنصة')
    MODERATOR = 'moderator', _('مشرف')
    SUPPORT   = 'support',   _('دعم فني')
    FINANCE   = 'finance',   _('مسؤول مالي')


# ==========================================================
# بروفايل المسؤول الإداري
# ==========================================================
class AdminProfile(models.Model):
    user = models.OneToOneField(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name='admin_profile',
        verbose_name=_('المستخدم'),
    )
    admin_role = models.CharField(
        max_length=20,
        choices=AdminRole.choices,
        default=AdminRole.MODERATOR,
        verbose_name=_('دور الإدارة'),
    )
    is_active_admin = models.BooleanField(
        default=True,
        verbose_name=_('نشط'),
    )
    notes = models.TextField(
        blank=True,
        verbose_name=_('ملاحظات'),
    )
    appointed_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True, blank=True,
        related_name='appointed_admins',
        verbose_name=_('عيَّنه'),
    )
    appointed_at = models.DateTimeField(
        auto_now_add=True,
        verbose_name=_('تاريخ التعيين'),
    )

    class Meta:
        verbose_name = _('بروفايل مسؤول')
        verbose_name_plural = _('بروفايلات المسؤولين')
        ordering = ['admin_role', 'appointed_at']

    def __str__(self):
        return f"{self.user.get_full_name() or self.user.email} ({self.get_admin_role_display()})"

    # --- صلاحيات مُحسَّنة ---
    @property
    def is_owner(self):
        return self.admin_role == AdminRole.OWNER or self.user.is_superuser

    @property
    def can_manage_users(self):
        return self.admin_role in (AdminRole.OWNER, AdminRole.MODERATOR)

    @property
    def can_delete_users(self):
        return self.admin_role == AdminRole.OWNER or self.user.is_superuser

    @property
    def can_view_finance(self):
        return self.admin_role in (AdminRole.OWNER, AdminRole.FINANCE)

    @property
    def can_manage_plans(self):
        return self.admin_role == AdminRole.OWNER or self.user.is_superuser

    @property
    def can_view_audit_log(self):
        return self.admin_role == AdminRole.OWNER or self.user.is_superuser


# ==========================================================
# سجل الأحداث الإدارية (Audit Log)
# ==========================================================
class AuditLog(models.Model):
    # أنواع الأحداث
    ACTION_BAN           = 'ban_user'
    ACTION_UNBAN         = 'unban_user'
    ACTION_DELETE        = 'delete_user'
    ACTION_RENEW_SUB     = 'renew_subscription'
    ACTION_EDIT_USER     = 'edit_user'
    ACTION_ADD_PLAN      = 'add_plan'
    ACTION_EDIT_PLAN     = 'edit_plan'
    ACTION_DELETE_PLAN   = 'delete_plan'
    ACTION_PAY_WITHDRAW    = 'pay_withdrawal'
    ACTION_REJECT_WITHDRAW = 'reject_withdrawal'
    ACTION_TOGGLE_MAINT    = 'toggle_maintenance'
    ACTION_TOGGLE_AI     = 'toggle_ai'
    ACTION_APPOINT_ADMIN = 'appoint_admin'
    ACTION_REMOVE_ADMIN  = 'remove_admin'
    ACTION_ZOHO_REPLY    = 'zoho_reply'
    ACTION_ZOHO_COMPOSE  = 'zoho_compose'
    ACTION_BLOCK_DEVICE  = 'block_device'
    ACTION_UNBLOCK_DEVICE = 'unblock_device'
    ACTION_REVOKE_SESSION = 'revoke_session'
    ACTION_SECURITY_POLICY = 'security_policy'
    ACTION_SEND_NOTIFICATION = 'send_notification'

    ACTION_CHOICES = [
        (ACTION_BAN,           _('حظر مستخدم')),
        (ACTION_UNBAN,         _('رفع حظر')),
        (ACTION_DELETE,        _('حذف مستخدم')),
        (ACTION_RENEW_SUB,     _('تجديد اشتراك')),
        (ACTION_EDIT_USER,     _('تعديل بيانات مستخدم')),
        (ACTION_ADD_PLAN,      _('إضافة باقة')),
        (ACTION_EDIT_PLAN,     _('تعديل باقة')),
        (ACTION_DELETE_PLAN,   _('حذف باقة')),
        (ACTION_PAY_WITHDRAW,    _('تسديد طلب سحب')),
        (ACTION_REJECT_WITHDRAW, _('رفض طلب سحب')),
        (ACTION_TOGGLE_MAINT,    _('تغيير وضع الصيانة')),
        (ACTION_TOGGLE_AI,     _('تشغيل/إيقاف الذكاء الاصطناعي')),
        (ACTION_APPOINT_ADMIN, _('تعيين مسؤول')),
        (ACTION_REMOVE_ADMIN,  _('إزالة مسؤول')),
        (ACTION_ZOHO_REPLY,    _('رد على بريد إلكتروني (Zoho)')),
        (ACTION_ZOHO_COMPOSE,  _('إرسال بريد جديد (Zoho)')),
        (ACTION_BLOCK_DEVICE,  _('حظر جهاز')),
        (ACTION_UNBLOCK_DEVICE,_('فك حظر جهاز')),
        (ACTION_REVOKE_SESSION,_('إنهاء جلسة جهاز')),
        (ACTION_SECURITY_POLICY,_('تحديث سياسات الأمان')),
        (ACTION_SEND_NOTIFICATION, _('إرسال إشعار مخصص')),
    ]

    admin = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        related_name='audit_logs',
        verbose_name=_('المسؤول المنفِّذ'),
    )
    action = models.CharField(
        max_length=50,
        choices=ACTION_CHOICES,
        verbose_name=_('الحدث'),
    )
    target_label = models.CharField(
        max_length=200,
        blank=True,
        verbose_name=_('المستهدف (وصف)'),
    )
    target_id = models.PositiveIntegerField(
        null=True, blank=True,
        verbose_name=_('ID المستهدف'),
    )
    details = models.JSONField(
        default=dict,
        blank=True,
        verbose_name=_('التفاصيل'),
    )
    ip_address = models.GenericIPAddressField(
        null=True, blank=True,
        verbose_name=_('عنوان IP'),
    )
    created_at = models.DateTimeField(
        auto_now_add=True,
        verbose_name=_('وقت الحدث'),
    )

    class Meta:
        verbose_name = _('سجل حدث')
        verbose_name_plural = _('سجل الأحداث الإدارية')
        ordering = ['-created_at']
        indexes = [
            models.Index(fields=['admin', 'created_at'], name='auditlog_admin_time_idx'),
            models.Index(fields=['action'], name='auditlog_action_idx'),
        ]

    def __str__(self):
        admin_name = self.admin.get_full_name() if self.admin else 'محذوف'
        return f"[{self.created_at:%Y-%m-%d %H:%M}] {admin_name} — {self.get_action_display()}"

    @classmethod
    def log(cls, request, action, target_label='', target_id=None, details=None):
        """Helper سريع لتسجيل حدث إداري."""
        ip = (
            request.META.get('HTTP_X_FORWARDED_FOR', '').split(',')[0].strip()
            or request.META.get('REMOTE_ADDR')
        )
        return cls.objects.create(
            admin=request.user,
            action=action,
            target_label=target_label,
            target_id=target_id,
            details=details or {},
            ip_address=ip or None,
        )

    @classmethod
    def log_custom_notification(cls, request, result: dict):
        """يسجل عملية إرسال إشعار إداري مخصص بشكل موحّد بين الويب والـ API."""
        return cls.log(
            request,
            cls.ACTION_SEND_NOTIFICATION,
            target_label=result.get('audience_label', ''),
            details={
                'target_mode': result.get('target_mode', ''),
                'segment': result.get('segment', ''),
                'recipient_count': result.get('recipient_count', 0),
                'fcm_user_count': result.get('fcm_user_count', 0),
                'title': result.get('title', ''),
                'link': result.get('link', ''),
            },
        )


# ==========================================================
# إعدادات Zoho Mail REST API (OAuth 2.0)
# ==========================================================
class ZohoMailConfig(models.Model):
    """
    إعدادات وحساب الربط مع Zoho Mail REST API (OAuth 2.0)
    تعتمد على Singleton Pattern بحيث يكون هناك سجل واحد دائمًا (pk=1)
    مع إمكانية القراءة من متغيرات البيئة (.env) كقيم افتراضية.
    """
    client_id = models.CharField(
        max_length=255, blank=True,
        verbose_name=_('Client ID'),
        help_text=_('معرف العميل من Zoho Developer Console')
    )
    client_secret = models.CharField(
        max_length=255, blank=True,
        verbose_name=_('Client Secret'),
        help_text=_('الرمز السري للعميل من Zoho Developer Console')
    )
    refresh_token = models.TextField(
        blank=True,
        verbose_name=_('Refresh Token'),
        help_text=_('توكن التجديد الدائم المستلم عبر OAuth 2.0')
    )
    access_token = models.TextField(
        blank=True,
        verbose_name=_('Access Token الحالي'),
        help_text=_('التوكن المؤقت المستخدم حالياً في استدعاءات REST API')
    )
    token_expires_at = models.DateTimeField(
        null=True, blank=True,
        verbose_name=_('تاريخ انتهاء Access Token')
    )
    account_id = models.CharField(
        max_length=100, blank=True,
        verbose_name=_('Account ID'),
        help_text=_('معرف حساب البريد في Zoho (يتم جلبه تلقائياً)')
    )
    support_email = models.EmailField(
        default='support@ta3alm.online',
        verbose_name=_('البريد المعتمد للدعم'),
        help_text=_('البريد المستخدم للإرسال والاستقبال')
    )
    zoho_accounts_url = models.CharField(
        max_length=255,
        default='https://accounts.zoho.com',
        verbose_name=_('رابط المصادقة لـ Zoho Accounts'),
        help_text=_('حسب نطاق السيرفر الجغرافي (مثل https://accounts.zoho.com أو .eu)')
    )
    zoho_api_url = models.CharField(
        max_length=255,
        default='https://mail.zoho.com/api',
        verbose_name=_('رابط الـ API الأساسي لـ Zoho Mail'),
    )
    is_active = models.BooleanField(
        default=True,
        verbose_name=_('مفعل')
    )
    last_synced_at = models.DateTimeField(
        null=True, blank=True,
        verbose_name=_('آخر وقت مزامنة')
    )
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        verbose_name = _('إعدادات Zoho Mail')
        verbose_name_plural = _('إعدادات Zoho Mail')

    def __str__(self):
        return f"إعدادات Zoho Mail ({self.get_effective_support_email()})"

    def save(self, *args, **kwargs):
        self.pk = 1
        super().save(*args, **kwargs)

    @classmethod
    def load(cls):
        import os
        obj, _ = cls.objects.get_or_create(pk=1)
        return obj

    def get_effective_client_id(self):
        import os
        return (self.client_id or os.environ.get('ZOHO_CLIENT_ID', '')).strip()

    def get_effective_client_secret(self):
        import os
        return (self.client_secret or os.environ.get('ZOHO_CLIENT_SECRET', '')).strip()

    def get_effective_refresh_token(self):
        import os
        return (self.refresh_token or os.environ.get('ZOHO_REFRESH_TOKEN', '')).strip()

    def get_effective_account_id(self):
        import os
        return (self.account_id or os.environ.get('ZOHO_ACCOUNT_ID', '')).strip()

    def get_effective_support_email(self):
        import os
        return (self.support_email or os.environ.get('ZOHO_SUPPORT_EMAIL', 'support@ta3alm.online')).strip()

    def is_configured(self):
        return bool(self.get_effective_client_id() and self.get_effective_client_secret())

    def is_connected(self):
        return bool(self.is_configured() and self.get_effective_refresh_token())


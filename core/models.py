from decimal import Decimal, ROUND_HALF_UP
import os
import re
from django.core.validators import MinValueValidator, MaxValueValidator
from django.db import models, transaction
from django.utils.translation import gettext_lazy as _


class SiteSetting(models.Model):
    is_maintenance_mode = models.BooleanField(default=False, verbose_name=_("وضع الصيانة"))
    platform_commission_percentage = models.PositiveIntegerField(
        default=20,
        validators=[MinValueValidator(0), MaxValueValidator(100)],
        verbose_name=_("نسبة عمولة المنصة (%)"),
    )
    android_latest_version_code = models.PositiveIntegerField(
        default=1,
        verbose_name=_("رقم البناء الأحدث لتطبيق أندرويد (Version Code)"),
    )
    android_min_required_version_code = models.PositiveIntegerField(
        default=1,
        verbose_name=_("أقل رقم بناء مسموح بفتحه (Min Required Build)"),
    )
    android_latest_version_name = models.CharField(
        max_length=32,
        default='1.0.0',
        verbose_name=_("رقم الإصدار الظاهر (Version Name)"),
    )
    android_apk_url = models.URLField(
        max_length=500,
        blank=True,
        default='',
        verbose_name=_("رابط تحميل ملف التحديث المباشر (APK URL)"),
    )
    android_apk_file = models.FileField(
        upload_to='app_releases/',
        blank=True,
        null=True,
        verbose_name=_("ملف تحديث التطبيق (APK)"),
    )
    android_update_release_notes = models.TextField(
        blank=True,
        default='',
        verbose_name=_("ملاحظات التحديث الجديد"),
    )
    android_force_update = models.BooleanField(
        default=True,
        verbose_name=_("إجبار التحديث لأعلى إصدار"),
    )
    android_apk_sha256 = models.CharField(
        max_length=64,
        blank=True,
        default='',
        verbose_name=_("بصمة SHA-256 لملف التحديث"),
    )
    android_assetlinks_sha256 = models.TextField(
        blank=True,
        default='',
        verbose_name=_("بصمات SHA-256 لشهادات توقيع التطبيق (App Links)"),
    )

    @staticmethod
    def format_sha256_colons(raw: str) -> str:
        cleaned = ''.join(ch for ch in str(raw or '').upper() if ch in '0123456789ABCDEF')
        if len(cleaned) != 64:
            return ''
        return ':'.join(cleaned[i:i + 2] for i in range(0, 64, 2))

    @staticmethod
    def normalize_file_sha256(raw: str) -> str:
        """تنظيف بصمة SHA-256 لملف APK (يدعم إزالة بادئة sha256: والنقطتين والمسافات)."""
        text = str(raw or '').strip()
        if text.lower().startswith('sha256:'):
            text = text[7:].strip()
        cleaned = ''.join(ch for ch in text.lower() if ch in '0123456789abcdef')
        return cleaned if len(cleaned) == 64 else ''

    @staticmethod
    def normalize_apk_download_url(raw: str) -> str:
        """تحويل روابط GitHub /blob/ إلى رابط raw المباشر لتفادي تنزيل صفحات HTML بدلاً من ملف الـ APK."""
        url = str(raw or '').strip()
        if not url:
            return ''
        match = re.match(
            r'^https?://(?:www\.)?github\.com/([^/]+)/([^/]+)/blob/(.+)$',
            url,
            flags=re.IGNORECASE,
        )
        if match:
            owner, repo, rest = match.groups()
            return f'https://raw.githubusercontent.com/{owner}/{repo}/{rest}'
        return url

    def get_assetlinks_fingerprints(self) -> list:
        """دمج بصمات SHA-256 من لوحة الإدارة ومن متغيرات البيئة لملف assetlinks.json."""
        sources = [
            self.android_assetlinks_sha256 or '',
            os.environ.get('ANDROID_ASSETLINKS_SHA256', ''),
            os.environ.get('ANDROID_RELEASE_CERT_SHA256', ''),
            os.environ.get('ANDROID_DEBUG_CERT_SHA256', ''),
        ]
        fingerprints = []
        for src in sources:
            for token in re.split(r'[\s,;]+', str(src).strip().strip('"\'')):
                formatted = self.format_sha256_colons(token)
                if formatted and formatted not in fingerprints:
                    fingerprints.append(formatted)
        return fingerprints

    @property
    def teacher_share_ratio(self):
        commission = max(0, min(100, int(self.platform_commission_percentage or 0)))
        return Decimal(100 - commission) / Decimal('100')

    def get_effective_min_version_code(self) -> int:
        latest = max(1, int(self.android_latest_version_code or 1))
        min_req = max(1, int(self.android_min_required_version_code or 1))
        if self.android_force_update:
            return max(min_req, latest)
        return min_req

    def get_effective_apk_url(self, request=None) -> str:
        external_url = self.normalize_apk_download_url(self.android_apk_url)
        if external_url:
            return external_url
        if self.android_apk_file:
            path = '/api/v1/public/app-update/download/'
            return request.build_absolute_uri(path) if request is not None else path
        return ''

    def build_app_update_payload(self, request=None, client_version_code=None) -> dict:
        latest_code = max(1, int(self.android_latest_version_code or 1))
        min_code = self.get_effective_min_version_code()
        update_required = False
        update_available = False
        if client_version_code is not None:
            try:
                build_num = int(client_version_code)
                update_required = build_num < min_code
                update_available = build_num < latest_code
            except (TypeError, ValueError):
                pass
        return {
            'latest_version_code': latest_code,
            'min_required_version_code': min_code,
            'latest_version_name': (self.android_latest_version_name or '1.0.0').strip(),
            'force_update': bool(self.android_force_update),
            'update_required': update_required,
            'update_available': update_available,
            'apk_download_url': self.get_effective_apk_url(request=request),
            'apk_sha256': self.normalize_file_sha256(self.android_apk_sha256),
            'release_notes': (self.android_update_release_notes or '').strip(),
        }

    CACHE_KEY = 'ta3alm:singleton:site_setting_v1'

    def save(self, *args, **kwargs):
        from django.core.cache import cache
        self.pk = 1
        self.platform_commission_percentage = max(
            0, min(100, int(self.platform_commission_percentage or 0))
        )
        self.android_latest_version_code = max(1, int(self.android_latest_version_code or 1))
        self.android_min_required_version_code = max(
            1, int(self.android_min_required_version_code or 1)
        )
        if self.android_apk_url:
            self.android_apk_url = self.normalize_apk_download_url(self.android_apk_url)[:500]
        if self.android_apk_sha256:
            normalized = self.normalize_file_sha256(self.android_apk_sha256)
            self.android_apk_sha256 = normalized
        super().save(*args, **kwargs)
        cache.set(self.CACHE_KEY, self, timeout=60)

    @classmethod
    def load(cls):
        from django.core.cache import cache
        cached = cache.get(cls.CACHE_KEY)
        if cached is not None:
            return cached
        obj, _ = cls.objects.get_or_create(pk=1)
        cache.set(cls.CACHE_KEY, obj, timeout=60)
        return obj


from core.services.wallet import credit_teacher_wallet_for_sale, reconcile_teacher_wallet
    

# core/models.py
from django.db import models
from django.conf import settings
from django.utils import timezone
from django.utils.translation import gettext_lazy as _

class Notification(models.Model):
    recipient = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name='notifications', verbose_name=_("المستقبل"))
    title = models.CharField(max_length=255, verbose_name=_("العنوان"))
    message = models.TextField(verbose_name=_("الرسالة"))
    link = models.CharField(max_length=255, blank=True, null=True, verbose_name=_("الرابط"))
    is_read = models.BooleanField(default=False, verbose_name=_("مقروءة"))
    created_at = models.DateTimeField(auto_now_add=True, verbose_name=_("وقت الإنشاء"))

    class Meta:
        ordering = ['-created_at']

    def __str__(self):
        return f"{self.recipient} - {self.title}"


class FCMDeviceToken(models.Model):
    PLATFORM_CHOICES = (
        ('android', _('أندرويد')),
        ('ios', _('آيفون / آيباد')),
        ('web', _('متصفح الويب')),
    )
    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name='fcm_tokens',
        verbose_name=_("المستخدم"),
    )
    token = models.CharField(max_length=512, unique=True, verbose_name=_("رمز FCM"))
    installation_id = models.CharField(
        max_length=128,
        blank=True,
        default='',
        db_index=True,
        verbose_name=_("معرف التثبيت"),
    )
    platform = models.CharField(
        max_length=20,
        choices=PLATFORM_CHOICES,
        default='android',
        verbose_name=_("المنصة"),
    )
    app_version = models.CharField(max_length=32, blank=True, default='', verbose_name=_("إصدار التطبيق"))
    is_active = models.BooleanField(default=True, db_index=True, verbose_name=_("نشط"))
    last_seen_at = models.DateTimeField(auto_now=True, verbose_name=_("آخر نشاط"))
    created_at = models.DateTimeField(auto_now_add=True, verbose_name=_("تاريخ التسجيل"))

    class Meta:
        verbose_name = _("رمز إشعارات جهاز (FCM)")
        verbose_name_plural = _("رموز إشعارات الأجهزة (FCM)")
        indexes = [
            models.Index(fields=['user', 'is_active']),
        ]

    def __str__(self):
        return f"{self.user_id} ({self.platform}) - {self.token[:18]}..."
    
# قائمة الصفوف (للاستخدام في الفلترة)
GRADE_CHOICES = (
    ('1_primary', _('أولى ابتدائي')), ('2_primary', _('ثانية ابتدائي')), ('3_primary', _('ثالثة ابتدائي')),
    ('4_primary', _('رابعة ابتدائي')), ('5_primary', _('خامسة ابتدائي')), ('6_primary', _('سادسة ابتدائي')),
    ('1_prep', _('أولى إعدادي')), ('2_prep', _('ثانية إعدادي')), ('3_prep', _('ثالثة إعدادي')),
    ('1_sec', _('أولى ثانوي')), ('2_sec', _('ثانية ثانوي')), ('3_sec', _('ثالثة ثانوي')),
)

class Subject(models.Model):
    name = models.CharField(max_length=50, verbose_name="اسم المادة")
    # الصفوف التي تدرس فيها هذه المادة (يمكن اختيار أكثر من صف)
    # سنستخدم حقل نصي بسيط أو JSON، لكن للأسهل سنستخدم MultiselectField (مكتبة خارجية)
    # أو ببساطة: نجعل المادة عامة، ونفلتر بالمعلم.
    # الحل الأبسط: لا نربط المادة بالصف في الداتا بيز، بل نربط المعلم بالمادة.
    
    class Meta:
        verbose_name = "المادة"
        verbose_name_plural = "المواد الدراسية"

    def __str__(self):
        return self.name

class ManualPayment(models.Model):
    STATUS_CHOICES = (
        ('pending', _('قيد المراجعة')),
        ('approved', _('مقبول')),
        ('rejected', _('مرفوض')),
    )
    TYPE_CHOICES = (
        ('teacher_subscription', _('اشتراك معلم')),
        ('student_package', _('شراء حزمة طالب')),
    )
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, verbose_name="المستخدم")
    amount = models.PositiveIntegerField(verbose_name="المبلغ")
    payment_type = models.CharField(max_length=50, choices=TYPE_CHOICES, verbose_name="نوع العملية")
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='pending', verbose_name="الحالة")
    
    target_id = models.PositiveIntegerField(help_text="ID الباقة أو الحزمة", null=True, blank=True)
    
    phone_number = models.CharField(max_length=50, verbose_name="رقم المحفظة / انستا باي")
    receipt_image = models.ImageField(upload_to='receipts/', verbose_name="صورة الإيصال (سكرين شوت)")
    created_at = models.DateTimeField(auto_now_add=True, verbose_name="تاريخ الطلب")

    def __str__(self):
        return f"{self.user} - {self.get_payment_type_display()} - {self.get_status_display()}"

    def save(self, *args, **kwargs):
        # تنفيذ عند القبول فقط (التحويل من حالة غير مقبول إلى مقبول)
        should_activate = False
        if self.pk:
            old_payment = ManualPayment.objects.get(pk=self.pk)
            should_activate = old_payment.status != 'approved' and self.status == 'approved'
        elif self.status == 'approved':
            should_activate = True

        with transaction.atomic():
            super().save(*args, **kwargs)
            if should_activate:
                if self.payment_type == 'teacher_subscription':
                    self.activate_teacher_subscription()
                elif self.payment_type == 'student_package':
                    self.activate_student_package()

    def activate_teacher_subscription(self):
        from teachers.models import SubscriptionPlan, TeacherProfile
        from django.utils import timezone
        from datetime import timedelta
        try:
            teacher = self.user.teacher_profile
            plan = SubscriptionPlan.objects.get(id=self.target_id)
            teacher.current_plan = plan
            # إذا كان الاشتراك ساري نضيف 30 يوماً على المتبقي، وإلا من اليوم
            if teacher.subscription_end_date and teacher.subscription_end_date > timezone.now():
                teacher.subscription_end_date += timedelta(days=30)
            else:
                teacher.subscription_end_date = timezone.now() + timedelta(days=30)
            teacher.save()
        except Exception as e:
            print(f"Error activating teacher subscription: {e}")

    def activate_student_package(self):
        from students.models import PackageEnrollment
        from teachers.models import CoursePackage
        try:
            student = self.user.student_profile
            package = CoursePackage.objects.get(id=self.target_id)
            enrollment, _ = PackageEnrollment.objects.get_or_create(
                student=student,
                package=package,
                defaults={'is_paid': False},
            )
            if not enrollment.is_paid:
                enrollment.is_paid = True
                enrollment.save(update_fields=['is_paid'])
                gross_amount = package.price
                credit_teacher_wallet_for_sale(package.teacher, gross_amount)
        except Exception as e:
            print(f"Error activating student package: {e}")

TERM_CHOICES = (
    ('1', _('الترم الأول')),
    ('2', _('الترم الثاني')),
)

class CurriculumUnit(models.Model):
    title = models.CharField(max_length=200, verbose_name="اسم الوحدة / المحور")
    subject = models.ForeignKey(Subject, on_delete=models.CASCADE, related_name='units', verbose_name="المادة")
    grade = models.CharField(max_length=20, choices=GRADE_CHOICES, verbose_name="الصف الدراسي")
    term = models.CharField(max_length=1, choices=TERM_CHOICES, verbose_name="الترم")
    order = models.PositiveIntegerField(default=1, verbose_name="الترتيب")

    class Meta:
        ordering = ['grade', 'subject', 'term', 'order']
        verbose_name = "وحدة دراسية"
        verbose_name_plural = "الوحدات الدراسية"

    def __str__(self):
        return f"[{self.get_grade_display()} - {self.get_term_display()}] {self.subject.name} - {self.title}"


class CurriculumLesson(models.Model):
    unit = models.ForeignKey(CurriculumUnit, on_delete=models.CASCADE, related_name='lessons', verbose_name="الوحدة")
    title = models.CharField(max_length=200, verbose_name="اسم الدرس")
    order = models.PositiveIntegerField(default=1, verbose_name="الترتيب")

    class Meta:
        ordering = ['unit', 'order']
        verbose_name = "درس"
        verbose_name_plural = "الدروس"

    def __str__(self):
        return f"{self.unit.title} - {self.title}"


class SupportThread(models.Model):
    STATUS_OPEN = 'open'
    STATUS_PENDING = 'pending'
    STATUS_CLOSED = 'closed'
    STATUS_CHOICES = (
        (STATUS_OPEN, _('مفتوحة')),
        (STATUS_PENDING, _('بانتظار رد')),
        (STATUS_CLOSED, _('مغلقة')),
    )

    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name='support_threads',
        verbose_name=_("المستخدم"),
    )
    subject = models.CharField(
        max_length=200,
        default='محادثة الدعم الفني',
        verbose_name=_("عنوان المحادثة"),
    )
    status = models.CharField(
        max_length=20,
        choices=STATUS_CHOICES,
        default=STATUS_OPEN,
        db_index=True,
        verbose_name=_("الحالة"),
    )
    last_message_preview = models.CharField(
        max_length=280,
        blank=True,
        default='',
        verbose_name=_("مقتطف آخر رسالة"),
    )
    last_message_at = models.DateTimeField(
        default=timezone.now,
        db_index=True,
        verbose_name=_("تاريخ آخر رسالة"),
    )
    unread_for_admin = models.PositiveIntegerField(
        default=0,
        verbose_name=_("غير مقروء للإدارة"),
    )
    unread_for_user = models.PositiveIntegerField(
        default=0,
        verbose_name=_("غير مقروء للمستخدم"),
    )
    assigned_admin = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name='assigned_support_threads',
        verbose_name=_("المشرف المتابع"),
    )
    created_at = models.DateTimeField(auto_now_add=True, verbose_name=_("تاريخ الإنشاء"))
    updated_at = models.DateTimeField(auto_now=True, verbose_name=_("آخر تحديث"))

    class Meta:
        ordering = ['-last_message_at', '-id']
        verbose_name = _("محادثة دعم فني")
        verbose_name_plural = _("محادثات الدعم الفني")
        indexes = [
            models.Index(fields=['user', 'status'], name='core_sup_usr_st_idx'),
            models.Index(fields=['status', '-last_message_at'], name='core_sup_st_dt_idx'),
        ]

    def __str__(self):
        return f"Thread #{self.pk} - {self.user}"


class SupportMessage(models.Model):
    thread = models.ForeignKey(
        SupportThread,
        on_delete=models.CASCADE,
        related_name='messages',
        verbose_name=_("المحادثة"),
    )
    sender = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name='sent_support_messages',
        verbose_name=_("المرسل"),
    )
    is_from_admin = models.BooleanField(
        default=False,
        db_index=True,
        verbose_name=_("من الإدارة"),
    )
    body = models.TextField(verbose_name=_("نص الرسالة"))
    is_read = models.BooleanField(
        default=False,
        db_index=True,
        verbose_name=_("مقروءة"),
    )
    via_notification_reply = models.BooleanField(
        default=False,
        verbose_name=_("رد من الإشعارات"),
    )
    created_at = models.DateTimeField(
        auto_now_add=True,
        db_index=True,
        verbose_name=_("تاريخ الإرسال"),
    )

    class Meta:
        ordering = ['created_at', 'id']
        verbose_name = _("رسالة دعم فني")
        verbose_name_plural = _("رسائل الدعم الفني")
        indexes = [
            models.Index(fields=['thread', 'id'], name='core_smsg_thr_id_idx'),
            models.Index(fields=['thread', 'is_from_admin', 'is_read'], name='core_smsg_ad_rd_idx'),
        ]

    def __str__(self):
        sender_tag = 'Admin' if self.is_from_admin else 'User'
        return f"[{sender_tag}] Thread #{self.thread_id}: {self.body[:40]}"


class ClientErrorReport(models.Model):
    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name='client_error_reports',
        verbose_name=_("المستخدم"),
    )
    source = models.CharField(
        max_length=40,
        default='flutter_app',
        verbose_name=_("المصدر"),
    )
    screen = models.CharField(
        max_length=120,
        blank=True,
        default='',
        verbose_name=_("الشاشة"),
    )
    error_type = models.CharField(
        max_length=120,
        blank=True,
        default='',
        verbose_name=_("نوع الخطأ"),
    )
    error_message = models.TextField(verbose_name=_("رسالة الخطأ الكاملة"))
    stack_trace = models.TextField(
        blank=True,
        default='',
        verbose_name=_("تتبع المكدس (Stack Trace)"),
    )
    app_version = models.CharField(
        max_length=40,
        blank=True,
        default='',
        verbose_name=_("إصدار التطبيق"),
    )
    app_build = models.CharField(
        max_length=20,
        blank=True,
        default='',
        verbose_name=_("رقم البناء"),
    )
    platform = models.CharField(
        max_length=32,
        blank=True,
        default='android',
        verbose_name=_("المنصة"),
    )
    device_info = models.JSONField(
        default=dict,
        blank=True,
        verbose_name=_("بيانات الجهاز"),
    )
    extra_context = models.JSONField(
        default=dict,
        blank=True,
        verbose_name=_("سياق إضافي"),
    )
    fingerprint = models.CharField(
        max_length=64,
        blank=True,
        default='',
        db_index=True,
        verbose_name=_("بصمة الخطأ"),
    )
    occurrences = models.PositiveIntegerField(
        default=1,
        verbose_name=_("عدد مرات الحدوث"),
    )
    is_resolved = models.BooleanField(
        default=False,
        db_index=True,
        verbose_name=_("تم الحل"),
    )
    resolved_at = models.DateTimeField(
        null=True,
        blank=True,
        verbose_name=_("تاريخ الحل"),
    )
    resolved_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name='resolved_error_reports',
        verbose_name=_("تم الحل بواسطة"),
    )
    created_at = models.DateTimeField(auto_now_add=True, verbose_name=_("أول ظهور"))
    last_seen_at = models.DateTimeField(auto_now=True, verbose_name=_("آخر ظهور"))

    class Meta:
        ordering = ['-last_seen_at', '-id']
        verbose_name = _("تقرير خطأ تقني")
        verbose_name_plural = _("تقارير الأخطاء التقنية")
        indexes = [
            models.Index(fields=['is_resolved', '-last_seen_at'], name='core_cerr_res_dt_idx'),
            models.Index(fields=['fingerprint', '-last_seen_at'], name='core_cerr_fp_dt_idx'),
        ]

    def __str__(self):
        return f"[{self.source}] {self.error_type or 'Error'}: {self.error_message[:60]}"

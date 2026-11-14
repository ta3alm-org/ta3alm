"""
accounts/models.py — نموذج المستخدم المخصص
"""
from django.db import models
from django.contrib.auth.models import AbstractUser
from django.utils import timezone
from django.utils.translation import gettext_lazy as _
from core.constants import ROLE_CHOICES
import random
import string


class User(AbstractUser):
    role = models.CharField(
        max_length=20,
        choices=ROLE_CHOICES,
        default='student',
        verbose_name=_('نوع المستخدم'),
    )
    phone = models.CharField(
        max_length=15, blank=True, null=True,
        verbose_name=_('رقم الهاتف'),
    )
    national_id = models.CharField(
        max_length=14, blank=True, null=True, unique=True,
        verbose_name=_('الرقم القومي'),
    )
    custom_id = models.CharField(
        max_length=10, blank=True, null=True, unique=True,
        verbose_name=_('كود المستخدم'),
    )
    is_banned = models.BooleanField(default=False, verbose_name=_('محظور'))

    class Meta(AbstractUser.Meta):
        pass

    def save(self, *args, **kwargs):
        # ✅ السوبر يوزر / الأدمن لا يحتاج كود — نتجاهل توليده
        if self.is_superuser or self.role == 'admin':
            super().save(*args, **kwargs)
            return

        # توليد custom_id تلقائياً لو لم يوجد
        if not self.custom_id and self.role in ['student', 'teacher', 'assistant']:
            chars = string.ascii_uppercase + string.digits
            if self.national_id and len(self.national_id) >= 14:
                letters = ''.join(random.choices(string.ascii_uppercase, k=2))
                self.custom_id = f"{letters}{self.national_id[-3:]}"
            else:
                prefix = {'teacher': 'T', 'assistant': 'A', 'student': 'S'}.get(self.role, 'U')
                self.custom_id = prefix + ''.join(random.choices(chars, k=6))

        super().save(*args, **kwargs)

    def get_dashboard_url(self):
        """يُعيد رابط لوحة التحكم المناسبة للمستخدم."""
        from django.urls import reverse
        if self.is_superuser or self.role == 'admin':
            return reverse('admin_panel:dashboard')
        if self.role == 'teacher':
            return reverse('teacher_dashboard')
        if self.role == 'student':
            return reverse('student_dashboard')
        if self.role == 'assistant':
            return reverse('assistant_dashboard')
        return reverse('home')

    def is_platform_admin(self):
        """هل هذا المستخدم له صلاحيات إدارية على المنصة؟"""
        return self.is_superuser or self.role == 'admin'

    def requires_email_verification(self) -> bool:
        """
        يُعيد True فقط إذا كان للمستخدم سجل تحقق من البريد لم يُفعَّل بعد.
        (لا يؤثر على المستخدمين القدامى أو الأدمن).
        """
        if self.is_superuser or self.role == 'admin':
            return False
        verification = getattr(self, 'email_verification', None)
        if verification is None:
            return False
        return not verification.is_verified


class StudentProfile(models.Model):
    user = models.OneToOneField(
        User, on_delete=models.CASCADE, related_name='student_profile',
    )
    parent_phone = models.CharField(max_length=15, verbose_name=_('رقم ولي الأمر'))
    enrolled_teachers = models.ManyToManyField(
        'teachers.TeacherProfile', blank=True,
        related_name='students',
        verbose_name=_('المدرسين المشترك معهم'),
    )

    def __str__(self):
        return self.user.get_full_name() or self.user.username


import uuid


class OneTimeLoginLink(models.Model):
    user = models.ForeignKey(
        User,
        on_delete=models.CASCADE,
        related_name='one_time_links',
        verbose_name=_('المستخدم')
    )
    token = models.UUIDField(
        default=uuid.uuid4,
        unique=True,
        editable=False,
        verbose_name=_('رمز الدخول')
    )
    is_used = models.BooleanField(
        default=False,
        verbose_name=_('مستخدم')
    )
    created_at = models.DateTimeField(
        auto_now_add=True,
        verbose_name=_('تاريخ الإنشاء')
    )

    class Meta:
        verbose_name = _('رابط دخول لمرة واحدة')
        verbose_name_plural = _('روابط الدخول')

    def __str__(self):
        return f"{self.user.username} - {'مستخدم' if self.is_used else 'صالح'}"


class EmailVerification(models.Model):
    """سجل تفعيل البريد الإلكتروني عبر الرابط المباشر أو كود التحقق (6 أرقام)."""
    user = models.OneToOneField(
        User,
        on_delete=models.CASCADE,
        related_name='email_verification',
        verbose_name=_('المستخدم'),
    )
    token = models.UUIDField(
        default=uuid.uuid4,
        unique=True,
        editable=False,
        verbose_name=_('رمز التفعيل المباشر'),
    )
    code = models.CharField(
        max_length=6,
        verbose_name=_('كود التفعيل'),
    )
    is_verified = models.BooleanField(
        default=False,
        verbose_name=_('مُفعّل'),
    )
    expires_at = models.DateTimeField(
        verbose_name=_('تاريخ انتهاء الصلاحية'),
    )
    last_sent_at = models.DateTimeField(
        null=True,
        blank=True,
        verbose_name=_('آخر وقت إرسال'),
    )
    created_at = models.DateTimeField(
        auto_now_add=True,
        verbose_name=_('تاريخ الإنشاء'),
    )

    class Meta:
        verbose_name = _('تفعيل البريد الإلكتروني')
        verbose_name_plural = _('طلبات تفعيل البريد الإلكتروني')

    def is_expired(self) -> bool:
        return timezone.now() > self.expires_at

    def __str__(self):
        state = 'مفعل' if self.is_verified else 'بانتظار التفعيل'
        return f"{self.user.email} - {state}"

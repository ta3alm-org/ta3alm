"""core.services.notifications.constants
Extracted from core/notifications_service.py.
"""
from __future__ import annotations

from django.core import signing


_PULL_SIGNER = signing.Signer(salt='ta3alm.android.bg_notif_pull.v1')


MAX_TITLE_LEN = 200


# ==========================================================
# إرسال الإشعارات الإدارية المخصصة (مستخدمون معينون / فئة / الكل)
# ==========================================================
CUSTOM_TARGET_ALL = 'all'


CUSTOM_TARGET_SEGMENT = 'segment'


CUSTOM_TARGET_USERS = 'users'


CUSTOM_TARGET_MODE_CHOICES = (
    (CUSTOM_TARGET_ALL, 'كل المستخدمين'),
    (CUSTOM_TARGET_SEGMENT, 'فئة محددة من المستخدمين'),
    (CUSTOM_TARGET_USERS, 'مستخدمون معيّنون'),
)


CUSTOM_NOTIFICATION_SEGMENTS = (
    {
        'key': 'students',
        'label': 'جميع الطلاب',
        'description': 'كل الحسابات المسجّلة بدور طالب',
        'extra_param': None,
    },
    {
        'key': 'teachers',
        'label': 'جميع المعلمين',
        'description': 'كل الحسابات المسجّلة بدور معلم',
        'extra_param': None,
    },
    {
        'key': 'teachers_active',
        'label': 'المعلمون باشتراك سارٍ',
        'description': 'المعلمون الذين ما زال اشتراكهم نشطاً',
        'extra_param': None,
    },
    {
        'key': 'teachers_expired',
        'label': 'المعلمون المنتهي اشتراكهم',
        'description': 'المعلمون بدون اشتراك سارٍ حالياً',
        'extra_param': None,
    },
    {
        'key': 'assistants',
        'label': 'جميع المساعدين',
        'description': 'كل الحسابات المسجّلة بدور مساعد',
        'extra_param': None,
    },
    {
        'key': 'admins',
        'label': 'فريق الإدارة والمشرفون',
        'description': 'المالك والمشرفون والدعم الفني والمالية',
        'extra_param': None,
    },
    {
        'key': 'grade',
        'label': 'طلاب صف دراسي معين',
        'description': 'الطلاب المنضمون لمجموعات أو حزم صف دراسي محدد',
        'extra_param': 'grade',
    },
    {
        'key': 'teacher_students',
        'label': 'طلاب معلم معين',
        'description': 'الطلاب المشتركون مع معلم محدد في المجموعات أو الحزم',
        'extra_param': 'teacher_id',
    },
    {
        'key': 'teacher_plan',
        'label': 'معلمو باقة اشتراك معينة',
        'description': 'المعلمون المشتركون على الباقة المحددة',
        'extra_param': 'plan_id',
    },
    {
        'key': 'subject_teachers',
        'label': 'معلمو مادة دراسية معينة',
        'description': 'المعلمون المختصون بالمادة الدراسية المحددة',
        'extra_param': 'subject_id',
    },
    {
        'key': 'fcm_enabled',
        'label': 'مفعّلو إشعارات التطبيق الفورية (FCM)',
        'description': 'المستخدمون الذين يملكون جهازاً مرتبطاً بالإشعارات الفورية',
        'extra_param': None,
    },
    {
        'key': 'verified_users',
        'label': 'الحسابات المؤكَّدة',
        'description': 'المستخدمون الذين أتمّوا تأكيد البريد الإلكتروني / OTP',
        'extra_param': None,
    },
    {
        'key': 'unverified_users',
        'label': 'الحسابات غير المؤكَّدة',
        'description': 'المستخدمون الذين لم يكملوا تأكيد الحساب بعد',
        'extra_param': None,
    },
)


CUSTOM_SEGMENT_MAP = {item['key']: item for item in CUSTOM_NOTIFICATION_SEGMENTS}


CUSTOM_LINK_PRESETS = (
    {'label': 'صفحة الإشعارات', 'url': '/notifications/all/'},
    {'label': 'لوحة الطالب', 'url': '/student/dashboard/'},
    {'label': 'لوحة المعلم', 'url': '/teacher/dashboard/'},
    {'label': 'اشتراك المعلم', 'url': '/teacher/subscription/'},
    {'label': 'الباقات والأسعار', 'url': '/plans/'},
    {'label': 'الرئيسية', 'url': '/'},
)

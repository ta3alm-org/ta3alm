"""
core/notifications_service.py
خدمة الإشعارات الموحدة والشاملة لجميع أدوار المنصة + رموز السحب الآمنة بالخلفية لتطبيق الأندرويد.
"""
from __future__ import annotations

import hashlib
import logging
from datetime import timedelta
from typing import Iterable

from django.conf import settings
from django.contrib.auth import get_user_model
from django.core import signing
from django.core.cache import cache
from django.db.models import Q
from django.utils import timezone

from .models import Notification

logger = logging.getLogger(__name__)

_PULL_SIGNER = signing.Signer(salt='ta3alm.android.bg_notif_pull.v1')
MAX_TITLE_LEN = 200


def _clean_title(title: str) -> str:
    text = str(title or '').strip()
    if len(text) > MAX_TITLE_LEN:
        return text[: MAX_TITLE_LEN - 1] + '…'
    return text or 'إشعار جديد'


def _user_display_name(user) -> str:
    if not user:
        return 'مستخدم'
    full = ''
    try:
        full = (user.get_full_name() or '').strip()
    except Exception:
        pass
    return full or getattr(user, 'username', None) or getattr(user, 'email', None) or f'#{getattr(user, "pk", "")}'


def notify_user(user, title: str, message: str, link: str | None = None) -> Notification | None:
    """إنشاء إشعار واحد لمستخدم محدد بأمان دون مقاطعة العملية الأساسية."""
    if not user or not getattr(user, 'pk', None):
        return None
    if getattr(user, 'is_active', True) is False:
        return None
    try:
        return Notification.objects.create(
            recipient=user,
            title=_clean_title(title),
            message=str(message or '').strip(),
            link=(str(link).strip() if link else None),
        )
    except Exception:
        logger.exception("Failed creating notification for user_id=%s", getattr(user, 'pk', None))
        return None


def notify_users_bulk(
    recipients: Iterable,
    title: str,
    message: str,
    link: str | None = None,
    exclude_user_ids: Iterable[int] | None = None,
) -> int:
    """إنشاء إشعارات جماعية باستعلام إدراج واحد مع إزالة التكرار تلقائياً."""
    excluded = {int(uid) for uid in (exclude_user_ids or ()) if uid}
    seen_ids: set[int] = set()
    objs: list[Notification] = []
    clean_title = _clean_title(title)
    clean_msg = str(message or '').strip()
    clean_link = str(link).strip() if link else None

    for user in recipients:
        uid = getattr(user, 'pk', None)
        if not uid or uid in seen_ids or uid in excluded:
            continue
        if getattr(user, 'is_active', True) is False:
            continue
        seen_ids.add(uid)
        objs.append(
            Notification(
                recipient_id=uid,
                title=clean_title,
                message=clean_msg,
                link=clean_link,
            )
        )

    if not objs:
        return 0
    try:
        created_objs = Notification.objects.bulk_create(objs, batch_size=500)
        created_ids = [getattr(obj, 'pk', None) for obj in created_objs if getattr(obj, 'pk', None)]
        if created_ids:
            from .fcm_service import schedule_fcm_push_for_notifications
            schedule_fcm_push_for_notifications(created_ids)
        return len(objs)
    except Exception:
        logger.exception("Failed bulk creating %s notifications", len(objs))
        return 0


def notify_group_students(group, title: str, message: str, link: str | None = None) -> int:
    """إرسال إشعار لجميع الطلاب المقبولين والنشطين داخل مجموعة دراسية."""
    if not group or not getattr(group, 'pk', None):
        return 0
    from students.models import Enrollment

    users = [
        e.student.user
        for e in Enrollment.objects.filter(group=group, is_active=True).select_related('student__user')
        if e.student and e.student.user_id
    ]
    return notify_users_bulk(users, title, message, link=link)


def notify_package_students(package, title: str, message: str, link: str | None = None) -> int:
    """إرسال إشعار لجميع الطلاب المشتركين (المدفوعين) داخل حزمة تعليمية."""
    if not package or not getattr(package, 'pk', None):
        return 0
    from students.models import PackageEnrollment

    users = [
        e.student.user
        for e in PackageEnrollment.objects.filter(package=package, is_paid=True).select_related('student__user')
        if e.student and e.student.user_id
    ]
    return notify_users_bulk(users, title, message, link=link)


def notify_teacher_and_assistants(
    teacher,
    title: str,
    message: str,
    link: str | None = None,
    permission_field: str | None = None,
    include_teacher: bool = True,
) -> int:
    """إرسال إشعار للمعلم ومساعديه النشطين حسب الصلاحية المحددة."""
    if not teacher or not getattr(teacher, 'pk', None):
        return 0
    from assistants.models import AssistantJob

    recipients = []
    if include_teacher and getattr(teacher, 'user', None):
        recipients.append(teacher.user)

    jobs_qs = AssistantJob.objects.filter(teacher=teacher, is_active=True).select_related('assistant__user')
    if permission_field:
        jobs_qs = jobs_qs.filter(**{permission_field: True})

    for job in jobs_qs:
        if job.assistant and job.assistant.user_id:
            recipients.append(job.assistant.user)

    return notify_users_bulk(recipients, title, message, link=link)


def notify_platform_admins(
    title: str,
    message: str,
    link: str | None = None,
    roles: tuple[str, ...] | None = None,
    include_owners: bool = True,
) -> int:
    """إرسال إشعار لمسؤولي المنصة (المالكين والمشرفين والمالية والدعم) وفق الأدوار المطلوبة."""
    User = get_user_model()
    try:
        q = Q(is_superuser=True) if include_owners else Q()
        if roles:
            role_q = Q(admin_profile__is_active_admin=True, admin_profile__admin_role__in=list(roles))
        else:
            role_q = Q(admin_profile__is_active_admin=True) | Q(role='admin')
        final_q = (q | role_q) if include_owners else role_q
        admins = list(User.objects.filter(final_q, is_active=True, is_banned=False).distinct())
        return notify_users_bulk(admins, title, message, link=link)
    except Exception:
        logger.exception("Failed querying platform admins for notifications")
        return 0


def maybe_notify_teacher_subscription_expiry(teacher) -> bool:
    """تذكير المعلم مرة واحدة كل 24 ساعة عندما يقترب اشتراكه من الانتهاء (3 أيام أو أقل)."""
    if not teacher or not getattr(teacher, 'user_id', None):
        return False
    if not teacher.subscription_end_date:
        return False
    now = timezone.now()
    if teacher.subscription_end_date <= now:
        return False
    days_left = (teacher.subscription_end_date - now).days
    if days_left > 3:
        return False

    cache_key = f"ta3alm:sub_expiry_notif:{teacher.pk}:{days_left}"
    if cache.get(cache_key):
        return False

    since = now - timedelta(hours=24)
    recent_exists = Notification.objects.filter(
        recipient_id=teacher.user_id,
        title__startswith='تذكير بقرب انتهاء الاشتراك',
        created_at__gte=since,
    ).exists()
    if recent_exists:
        cache.set(cache_key, True, timeout=43200)
        return False

    days_text = 'اليوم' if days_left == 0 else f'خلال {days_left} {"يوم" if days_left == 1 else "أيام"}'
    notify_user(
        teacher.user,
        'تذكير بقرب انتهاء الاشتراك',
        f'ينتهي اشتراكك الحالي في المنصة {days_text}. بادر بالتجديد لضمان استمرار صلاحيات مجموعاتك دون انقطاع.',
        link='/teacher/subscription/',
    )
    cache.set(cache_key, True, timeout=43200)
    return True


def maybe_notify_zoho_inbox(messages_list: list[dict] | None) -> int:
    """
    ينشئ إشعاراً لفريق الدعم الفني والمالكين عند رصد رسائل واردة غير مقروءة حديثاً في بريد Zoho.
    """
    if not messages_list:
        return 0
    notified = 0
    for msg in messages_list[:5]:
        if not isinstance(msg, dict):
            continue
        is_read = bool(msg.get('isRead') or str(msg.get('status', '')) == '1')
        msg_id = str(msg.get('messageId') or '').strip()
        if is_read or not msg_id:
            continue
        cache_key = f"ta3alm:zoho_inbox_notified:{msg_id}"
        if cache.get(cache_key):
            continue
        sender = str(msg.get('fromAddress') or msg.get('sender') or 'مرسل خارجي').strip()
        subject = str(msg.get('subject') or 'رسالة دعم فني جديدة').strip()
        notified += notify_platform_admins(
            f'رسالة دعم فني جديدة: {subject[:80]}',
            f'وردت رسالة غير مقروءة من {sender} إلى بريد الدعم الفني.',
            link='/admin-panel/support/',
            roles=('owner', 'support'),
        )
        cache.set(cache_key, True, timeout=7 * 86400)
    return notified


def _password_epoch_digest(user) -> str:
    raw = str(getattr(user, 'password', '') or '').encode('utf-8')
    return hashlib.sha256(raw).hexdigest()[:12]


def generate_notif_pull_token(user) -> str:
    """
    يُصدر رمز سحب محدود الصلاحية (قراءة الإشعارات فقط في الخلفية لـ JobService على الأندرويد).
    يبطل تلقائياً عند تغيير كلمة المرور أو حظر الحساب أو إيقافه.
    """
    if not user or not getattr(user, 'pk', None):
        return ''
    payload = f"{user.pk}:{_password_epoch_digest(user)}"
    return _PULL_SIGNER.sign(payload)


def verify_notif_pull_token(token: str):
    """يتحقق من رمز السحب ويُعيد كائن المستخدم النشط غير المحظور أو None."""
    raw = str(token or '').strip()
    if not raw:
        return None
    try:
        unsigned = _PULL_SIGNER.unsign(raw)
        uid_str, pwd_sig = unsigned.split(':', 1)
        uid = int(uid_str)
    except Exception:
        return None

    User = get_user_model()
    user = User.objects.filter(pk=uid, is_active=True, is_banned=False).first()
    if not user:
        return None
    if _password_epoch_digest(user) != pwd_sig:
        return None
    return user


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


def parse_user_ids_input(raw_user_ids) -> list[int]:
    """يحوّل قائمة أو نصاً مفصولاً بفواصل إلى قائمة معرفات مستخدمين صحيحة وفريدة."""
    if raw_user_ids is None:
        return []
    if isinstance(raw_user_ids, (int, str)):
        candidates = [part.strip() for part in str(raw_user_ids).split(',')]
    elif isinstance(raw_user_ids, Iterable):
        candidates = list(raw_user_ids)
    else:
        return []

    parsed: list[int] = []
    seen: set[int] = set()
    for item in candidates:
        try:
            uid = int(str(item).strip())
        except (TypeError, ValueError):
            continue
        if uid > 0 and uid not in seen:
            seen.add(uid)
            parsed.append(uid)
    return parsed


def validate_custom_notification_link(link: str | None) -> str | None:
    """يتحقق من أمان رابط الإشعار (مسار داخلي آمن يبدأ بـ / أو رابط http/https)."""
    cleaned = str(link or '').strip()
    if not cleaned:
        return None
    lowered = cleaned.lower()
    is_internal = cleaned.startswith('/') and not cleaned.startswith('//')
    is_http = lowered.startswith(('https://', 'http://'))
    if not (is_internal or is_http):
        raise ValueError('يجب أن يكون الرابط مساراً داخلياً يبدأ بـ / أو رابطاً يبدأ بـ https:// أو http://.')
    if len(cleaned) > 255:
        raise ValueError('طول الرابط يجب ألا يتجاوز 255 حرفاً.')
    return cleaned


def _count_fcm_enabled_users(user_ids: Iterable[int]) -> int:
    from .models import FCMDeviceToken

    ids = list(user_ids)
    if not ids:
        return 0
    fcm_user_ids: set[int] = set()
    for start in range(0, len(ids), 450):
        chunk = ids[start : start + 450]
        fcm_user_ids.update(
            FCMDeviceToken.objects.filter(user_id__in=chunk, is_active=True)
            .values_list('user_id', flat=True)
        )
    return len(fcm_user_ids)


def _serialize_recipient_brief(user, fcm_user_ids: set[int] | None = None) -> dict:
    uid = user.pk
    has_fcm = (
        uid in fcm_user_ids
        if fcm_user_ids is not None
        else user.fcm_tokens.filter(is_active=True).exists()
    )
    return {
        'id': uid,
        'full_name': _user_display_name(user),
        'email': getattr(user, 'email', '') or '',
        'phone': getattr(user, 'phone', '') or '',
        'custom_id': getattr(user, 'custom_id', '') or '',
        'role': getattr(user, 'role', '') or '',
        'role_display': user.get_role_display() if hasattr(user, 'get_role_display') else '',
        'is_banned': bool(getattr(user, 'is_banned', False)),
        'has_fcm': bool(has_fcm),
    }


def search_custom_notification_users(query: str = '', role: str = '', limit: int = 25) -> list[dict]:
    """يبحث عن المستخدمين النشطين لاختيارهم في الإشعارات المخصصة مع حالة ربط FCM."""
    from .models import FCMDeviceToken

    User = get_user_model()
    qs = User.objects.filter(is_active=True).order_by('-id')
    cleaned_role = str(role or '').strip()
    if cleaned_role:
        qs = qs.filter(role=cleaned_role)
    cleaned_q = str(query or '').strip()
    if cleaned_q:
        qs = qs.filter(
            Q(first_name__icontains=cleaned_q)
            | Q(last_name__icontains=cleaned_q)
            | Q(username__icontains=cleaned_q)
            | Q(email__icontains=cleaned_q)
            | Q(phone__icontains=cleaned_q)
            | Q(custom_id__icontains=cleaned_q)
        )

    matched = list(qs[: max(1, min(int(limit or 25), 50))])
    if not matched:
        return []
    matched_ids = [u.pk for u in matched]
    fcm_ids = set(
        FCMDeviceToken.objects.filter(user_id__in=matched_ids, is_active=True)
        .values_list('user_id', flat=True)
    )
    return [_serialize_recipient_brief(u, fcm_user_ids=fcm_ids) for u in matched]


def resolve_custom_notification_recipients(
    *,
    target_mode: str = CUSTOM_TARGET_ALL,
    segment: str = '',
    user_ids: Iterable[int] | str | None = None,
    grade: str = '',
    teacher_id=None,
    plan_id=None,
    subject_id=None,
    exclude_banned: bool = True,
):
    """
    يحلل الفئة أو المستخدمين المستهدفين ويعيد:
    (QuerySet[User] مرتّب وفريد, وصف الجمهور المستهدف, رسالة خطأ التحقق أو None).
    """
    from .constants import GRADE_MAP
    from .models import Subject
    from teachers.models import SubscriptionPlan, TeacherProfile

    User = get_user_model()
    base_qs = User.objects.filter(is_active=True)
    if exclude_banned:
        base_qs = base_qs.filter(is_banned=False)

    mode = str(target_mode or CUSTOM_TARGET_ALL).strip()
    if mode not in {CUSTOM_TARGET_ALL, CUSTOM_TARGET_SEGMENT, CUSTOM_TARGET_USERS}:
        return base_qs.none(), '', 'نوع الاستهداف المحدد غير صالح.'

    if mode == CUSTOM_TARGET_ALL:
        return base_qs.distinct().order_by('-id'), 'كل المستخدمين', None

    if mode == CUSTOM_TARGET_USERS:
        parsed_ids = parse_user_ids_input(user_ids)
        if not parsed_ids:
            return base_qs.none(), '', 'يرجى اختيار مستخدم واحد على الأقل.'
        qs = base_qs.filter(id__in=parsed_ids).distinct().order_by('-id')
        return qs, f'مستخدمون محددون ({len(parsed_ids)})', None

    seg_key = str(segment or '').strip()
    seg_info = CUSTOM_SEGMENT_MAP.get(seg_key)
    if not seg_info:
        return base_qs.none(), '', 'يرجى اختيار فئة مستخدمين صالحة.'

    now = timezone.now()
    label = f"فئة: {seg_info['label']}"

    if seg_key == 'students':
        qs = base_qs.filter(role='student')
    elif seg_key == 'teachers':
        qs = base_qs.filter(role='teacher')
    elif seg_key == 'teachers_active':
        qs = base_qs.filter(role='teacher', teacher_profile__subscription_end_date__gt=now)
    elif seg_key == 'teachers_expired':
        qs = base_qs.filter(role='teacher').filter(
            Q(teacher_profile__subscription_end_date__isnull=True)
            | Q(teacher_profile__subscription_end_date__lte=now)
        )
    elif seg_key == 'assistants':
        qs = base_qs.filter(role='assistant')
    elif seg_key == 'admins':
        qs = base_qs.filter(
            Q(is_superuser=True) | Q(role='admin') | Q(admin_profile__is_active_admin=True)
        )
    elif seg_key == 'grade':
        clean_grade = str(grade or '').strip()
        if clean_grade not in GRADE_MAP:
            return base_qs.none(), '', 'يرجى اختيار الصف الدراسي المطلوب.'
        qs = base_qs.filter(role='student').filter(
            Q(
                student_profile__enrollments__is_active=True,
                student_profile__enrollments__group__grade=clean_grade,
            )
            | Q(
                student_profile__package_enrollments__is_paid=True,
                student_profile__package_enrollments__package__grade=clean_grade,
            )
        )
        label = f'طلاب {GRADE_MAP[clean_grade]}'
    elif seg_key == 'teacher_students':
        try:
            tid = int(str(teacher_id).strip())
        except (TypeError, ValueError):
            tid = 0
        teacher = TeacherProfile.objects.select_related('user').filter(pk=tid).first() if tid > 0 else None
        if not teacher:
            return base_qs.none(), '', 'يرجى اختيار المعلم المطلوب.'
        qs = base_qs.filter(role='student').filter(
            Q(
                student_profile__enrollments__is_active=True,
                student_profile__enrollments__group__teacher=teacher,
            )
            | Q(
                student_profile__package_enrollments__is_paid=True,
                student_profile__package_enrollments__package__teacher=teacher,
            )
            | Q(student_profile__enrolled_teachers=teacher)
        )
        label = f'طلاب المعلم: {_user_display_name(teacher.user)}'
    elif seg_key == 'teacher_plan':
        try:
            pid = int(str(plan_id).strip())
        except (TypeError, ValueError):
            pid = 0
        plan = SubscriptionPlan.objects.filter(pk=pid).first() if pid > 0 else None
        if not plan:
            return base_qs.none(), '', 'يرجى اختيار الباقة المطلوبة.'
        qs = base_qs.filter(role='teacher', teacher_profile__current_plan=plan)
        label = f'معلمو باقة: {plan.name}'
    elif seg_key == 'subject_teachers':
        try:
            sid = int(str(subject_id).strip())
        except (TypeError, ValueError):
            sid = 0
        subject = Subject.objects.filter(pk=sid).first() if sid > 0 else None
        if not subject:
            return base_qs.none(), '', 'يرجى اختيار المادة الدراسية المطلوبة.'
        qs = base_qs.filter(role='teacher', teacher_profile__subject=subject)
        label = f'معلمو مادة: {subject.name}'
    elif seg_key == 'fcm_enabled':
        qs = base_qs.filter(fcm_tokens__is_active=True)
    elif seg_key == 'verified_users':
        qs = base_qs.filter(
            Q(is_superuser=True)
            | Q(role='admin')
            | Q(admin_profile__is_active_admin=True)
            | Q(email_verification__is_verified=True)
        )
    elif seg_key == 'unverified_users':
        qs = (
            base_qs.exclude(is_superuser=True)
            .exclude(role='admin')
            .exclude(admin_profile__is_active_admin=True)
            .filter(Q(email_verification__isnull=True) | Q(email_verification__is_verified=False))
        )
    else:
        return base_qs.none(), '', 'فئة المستخدمين المحددة غير مدعومة.'

    return qs.distinct().order_by('-id'), label, None


def preview_custom_notification_audience(**kwargs) -> dict:
    """يعاين عدد المستهدفين وعدد من لديهم أجهزة FCM مفعّلة مع عيّنة من الأسماء."""
    from .fcm_service import is_fcm_configured
    from .models import FCMDeviceToken

    qs, audience_label, error = resolve_custom_notification_recipients(**kwargs)
    if error:
        return {
            'ok': False,
            'error': error,
            'audience_label': audience_label,
            'recipient_count': 0,
            'fcm_user_count': 0,
            'fcm_configured': is_fcm_configured(),
            'sample_recipients': [],
        }

    recipient_ids = list(qs.values_list('id', flat=True))
    fcm_count = _count_fcm_enabled_users(recipient_ids)
    sample_users = list(qs[:8])
    sample_ids = [u.pk for u in sample_users]
    sample_fcm_ids = (
        set(
            FCMDeviceToken.objects.filter(user_id__in=sample_ids, is_active=True)
            .values_list('user_id', flat=True)
        )
        if sample_ids
        else set()
    )
    return {
        'ok': True,
        'error': None,
        'audience_label': audience_label,
        'recipient_count': len(recipient_ids),
        'fcm_user_count': fcm_count,
        'fcm_configured': is_fcm_configured(),
        'sample_recipients': [
            _serialize_recipient_brief(u, fcm_user_ids=sample_fcm_ids) for u in sample_users
        ],
    }


def send_custom_notification(
    *,
    title: str,
    message: str,
    link: str | None = None,
    target_mode: str = CUSTOM_TARGET_ALL,
    segment: str = '',
    user_ids: Iterable[int] | str | None = None,
    grade: str = '',
    teacher_id=None,
    plan_id=None,
    subject_id=None,
    exclude_banned: bool = True,
) -> dict:
    """يرسل إشعاراً إدارياً مخصصاً داخل المنصة وعبر FCM للفئة أو المستخدمين المحددين."""
    from .fcm_service import is_fcm_configured

    clean_title = str(title or '').strip()
    clean_message = str(message or '').strip()
    if not clean_title:
        return {'ok': False, 'error': 'يرجى كتابة عنوان الإشعار.'}
    if len(clean_title) > MAX_TITLE_LEN:
        return {'ok': False, 'error': f'عنوان الإشعار يجب ألا يتجاوز {MAX_TITLE_LEN} حرفاً.'}
    if not clean_message:
        return {'ok': False, 'error': 'يرجى كتابة نص الإشعار.'}

    try:
        clean_link = validate_custom_notification_link(link)
    except ValueError as exc:
        return {'ok': False, 'error': str(exc)}

    qs, audience_label, error = resolve_custom_notification_recipients(
        target_mode=target_mode,
        segment=segment,
        user_ids=user_ids,
        grade=grade,
        teacher_id=teacher_id,
        plan_id=plan_id,
        subject_id=subject_id,
        exclude_banned=exclude_banned,
    )
    if error:
        return {'ok': False, 'error': error}

    recipients = list(qs)
    if not recipients:
        return {'ok': False, 'error': 'لا يوجد مستخدمون نشطون ضمن النطاق المحدد حالياً.'}

    recipient_ids = [u.pk for u in recipients]
    fcm_user_count = _count_fcm_enabled_users(recipient_ids)
    sent_count = notify_users_bulk(recipients, clean_title, clean_message, link=clean_link)
    if sent_count <= 0:
        return {'ok': False, 'error': 'تعذّر إنشاء الإشعارات للمستلمين المحددين.'}

    final_label = (
        f'مستخدمون محددون ({sent_count})'
        if target_mode == CUSTOM_TARGET_USERS
        else audience_label
    )
    return {
        'ok': True,
        'error': None,
        'target_mode': target_mode,
        'segment': segment if target_mode == CUSTOM_TARGET_SEGMENT else '',
        'audience_label': final_label,
        'recipient_count': sent_count,
        'fcm_user_count': fcm_user_count,
        'fcm_configured': is_fcm_configured(),
        'title': clean_title,
        'link': clean_link or '',
        'recipient_ids': recipient_ids,
    }


def get_custom_notification_metadata() -> dict:
    """يُعيد الفئات المتاحة والخيارات المساعدة لنموذج الإشعارات المخصصة (الويب والـ API)."""
    from .constants import GRADE_CHOICES
    from .fcm_service import is_fcm_configured
    from .models import Subject
    from teachers.models import SubscriptionPlan, TeacherProfile

    teachers_data = [
        {
            'id': t.pk,
            'user_id': t.user_id,
            'name': _user_display_name(t.user),
            'subject': t.subject.name if t.subject else '',
        }
        for t in TeacherProfile.objects.select_related('user', 'subject').order_by('user__first_name', 'id')
    ]
    plans_data = [
        {'id': p.pk, 'name': p.name, 'price': p.price}
        for p in SubscriptionPlan.objects.order_by('price', 'id')
    ]
    subjects_data = [
        {'id': s.pk, 'name': s.name}
        for s in Subject.objects.order_by('name', 'id')
    ]
    grades_data = [{'key': key, 'label': str(label)} for key, label in GRADE_CHOICES]

    return {
        'target_modes': [{'key': k, 'label': v} for k, v in CUSTOM_TARGET_MODE_CHOICES],
        'segments': list(CUSTOM_NOTIFICATION_SEGMENTS),
        'grades': grades_data,
        'teachers': teachers_data,
        'plans': plans_data,
        'subjects': subjects_data,
        'link_presets': list(CUSTOM_LINK_PRESETS),
        'fcm_configured': is_fcm_configured(),
    }

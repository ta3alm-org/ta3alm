"""core.services.notifications.delivery
Extracted from core/notifications_service.py.
"""
from __future__ import annotations

import logging
from datetime import timedelta
from typing import Iterable
from django.contrib.auth import get_user_model
from django.core.cache import cache
from django.db.models import Q
from django.utils import timezone
from core.models import Notification

from core.services.notifications.constants import MAX_TITLE_LEN

logger = logging.getLogger('core.notifications_service')


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
            from core.fcm_service import schedule_fcm_push_for_notifications
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

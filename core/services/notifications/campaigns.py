"""core.services.notifications.campaigns
Extracted from core/notifications_service.py.
"""
from __future__ import annotations

from typing import Iterable
from django.contrib.auth import get_user_model
from django.db.models import Q
from django.utils import timezone

from core.services.notifications.constants import (
    CUSTOM_LINK_PRESETS,
    CUSTOM_NOTIFICATION_SEGMENTS,
    CUSTOM_SEGMENT_MAP,
    CUSTOM_TARGET_ALL,
    CUSTOM_TARGET_MODE_CHOICES,
    CUSTOM_TARGET_SEGMENT,
    CUSTOM_TARGET_USERS,
    MAX_TITLE_LEN,
)
from core.services.notifications.delivery import (
    _user_display_name,
    notify_users_bulk,
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
    from core.constants import GRADE_MAP
    from core.models import Subject
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
    from core.selectors.notification_selectors import _count_fcm_enabled_users
    from core.fcm_service import is_fcm_configured

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
    from core.constants import GRADE_CHOICES
    from core.fcm_service import is_fcm_configured
    from core.models import Subject
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

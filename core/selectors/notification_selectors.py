"""core.selectors.notification_selectors
Extracted from core/notifications_service.py.
"""
from __future__ import annotations

from typing import Iterable
from django.contrib.auth import get_user_model
from django.db.models import Q

from core.services.notifications.campaigns import (
    _serialize_recipient_brief,
    resolve_custom_notification_recipients,
)


def _count_fcm_enabled_users(user_ids: Iterable[int]) -> int:
    from core.models import FCMDeviceToken

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


def search_custom_notification_users(query: str = '', role: str = '', limit: int = 25) -> list[dict]:
    """يبحث عن المستخدمين النشطين لاختيارهم في الإشعارات المخصصة مع حالة ربط FCM."""
    from core.models import FCMDeviceToken

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


def preview_custom_notification_audience(**kwargs) -> dict:
    """يعاين عدد المستهدفين وعدد من لديهم أجهزة FCM مفعّلة مع عيّنة من الأسماء."""
    from core.fcm_service import is_fcm_configured
    from core.models import FCMDeviceToken

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

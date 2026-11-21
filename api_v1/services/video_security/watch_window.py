"""api_v1.services.video_security.watch_window
Extracted from api_v1/video_security.py.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone as dt_timezone
from django.core.cache import cache
from django.utils import timezone
from api_v1.models import PlaybackSession

from api_v1.services.video_security.constants import VIEW_WINDOW_MINUTES


def watch_window_cache_key(user_id: int, lecture_id: int) -> str:
    return f"lec_watch_win:{user_id}:{lecture_id}"


def get_active_watch_window_expiry(
    user,
    lecture_id: int,
    *,
    package_id: int | None = None,
    now=None,
):
    """
    يُعيد وقت انتهاء نافذة المشاهدة الثابتة (غير المنزلقة) إن وُجدت وكانت صالحة، وإلا None.
    """
    if not user or not getattr(user, 'id', None) or not lecture_id:
        return None
    now = now or timezone.now()

    qs = PlaybackSession.objects.filter(
        user=user,
        lecture_id=lecture_id,
        status='active',
        view_window_expires_at__gt=now,
    )
    if package_id is not None:
        qs = qs.filter(course_package_id=package_id)
    session_exp = (
        qs.order_by('-view_window_expires_at')
        .values_list('view_window_expires_at', flat=True)
        .first()
    )
    if session_exp is not None:
        return session_exp

    raw = cache.get(watch_window_cache_key(user.id, lecture_id))
    if isinstance(raw, dict):
        try:
            granted_ts = float(raw.get('granted_at', 0))
            exp_ts = float(raw.get('expires_at', 0))
            cached_dt = datetime.fromtimestamp(exp_ts, tz=dt_timezone.utc)
            if cached_dt > now:
                latest_session = (
                    PlaybackSession.objects.filter(user=user, lecture_id=lecture_id)
                    .order_by('-created_at')
                    .values('status', 'created_at', 'view_window_expires_at')
                    .first()
                )
                if latest_session:
                    latest_created_ts = latest_session['created_at'].timestamp()
                    if latest_created_ts >= granted_ts - 0.5:
                        if latest_session['status'] != 'active':
                            return None
                        if (
                            latest_session['view_window_expires_at'] is not None
                            and latest_session['view_window_expires_at'] <= now
                        ):
                            return None
                return cached_dt
        except (TypeError, ValueError, OSError):
            pass
    return None


def has_active_watch_window(
    user,
    lecture_id: int,
    *,
    package_id: int | None = None,
    now=None,
) -> bool:
    return get_active_watch_window_expiry(
        user, lecture_id, package_id=package_id, now=now
    ) is not None


def grant_watch_window(
    user,
    lecture_id: int,
    *,
    minutes: int = VIEW_WINDOW_MINUTES,
    now=None,
):
    """
    يمنح نافذة مشاهدة ثابتة غير متجددة للمحاضرة الحالية، ويمسح أي نوافذ مفتوحة لمحاضرات أخرى.
    """
    now = now or timezone.now()
    if not user or not getattr(user, 'id', None) or not lecture_id:
        return now

    other_lec_ids = list(
        PlaybackSession.objects.filter(user=user, view_window_expires_at__gt=now)
        .exclude(lecture_id=lecture_id)
        .values_list('lecture_id', flat=True)
        .distinct()
    )
    for other_id in other_lec_ids:
        cache.delete(watch_window_cache_key(user.id, other_id))
    if other_lec_ids:
        PlaybackSession.objects.filter(
            user=user,
            lecture_id__in=other_lec_ids,
            view_window_expires_at__gt=now,
        ).update(view_window_expires_at=now)

    expires_at = now + timedelta(minutes=max(int(minutes), 1))
    ttl_seconds = max(int((expires_at - now).total_seconds()), 60)
    cache.set(
        watch_window_cache_key(user.id, lecture_id),
        {'granted_at': now.timestamp(), 'expires_at': expires_at.timestamp()},
        timeout=ttl_seconds,
    )
    return expires_at


def clear_watch_window(user, lecture_id: int | None = None, *, now=None) -> None:
    """يُنهي نافذة المشاهدة فوراً عند الخروج أو الرجوع أو تسجيل الخروج لمنع إعادة المشاهدة المجانية."""
    if not user or not getattr(user, 'id', None):
        return
    now = now or timezone.now()
    qs = PlaybackSession.objects.filter(user=user)
    if lecture_id is not None:
        qs = qs.filter(lecture_id=lecture_id)
        cache.delete(watch_window_cache_key(user.id, lecture_id))
    else:
        for lec_id in list(qs.values_list('lecture_id', flat=True).distinct()):
            if lec_id:
                cache.delete(watch_window_cache_key(user.id, lec_id))
    qs.filter(view_window_expires_at__gt=now).update(view_window_expires_at=now)
    qs.filter(status='active').update(status='ended', revoked_reason='watch_exited')

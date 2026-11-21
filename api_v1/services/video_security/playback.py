"""api_v1.services.video_security.playback
Extracted from api_v1/video_security.py.
"""
from __future__ import annotations

import hashlib
import os
import uuid
from datetime import datetime, timedelta, timezone as dt_timezone
from typing import Any
import jwt
from django.conf import settings
from django.core.cache import cache
from django.db import transaction
from django.utils import timezone
from api_v1.models import (
    PlaybackSession,
    VideoSecurityAuditLog,
)

from api_v1.services.video_security.constants import (
    ANOMALY_AUTH_THRESHOLD,
    ANOMALY_WINDOW_SECONDS,
    MAX_CONCURRENT_SESSIONS,
    PLAYBACK_TOKEN_TTL_SECONDS,
)


def get_client_ip(request) -> str | None:
    forwarded = request.META.get('HTTP_X_FORWARDED_FOR')
    if forwarded:
        return forwarded.split(',')[0].strip()
    return request.META.get('REMOTE_ADDR')


def _video_signing_secret() -> str:
    """مفتاح توقيع توكنات الفيديو — معزول بمجال مخصص عن SECRET_KEY في حال عدم ضبط متغير منفصل."""
    explicit = os.environ.get('VIDEO_SIGNING_SECRET', '').strip()
    if explicit:
        return explicit
    return hashlib.sha256(f"ta3alm-video-jwt-v1:{settings.SECRET_KEY}".encode('utf-8')).hexdigest()


def issue_playback_token(
    *,
    user_id: int,
    lecture_id: int,
    session: PlaybackSession,
    ttl_seconds: int = PLAYBACK_TOKEN_TTL_SECONDS,
) -> tuple[str, int]:
    """يصدر JWT قصير العمر مرتبطاً بالمستخدم والمحاضرة والجهاز ومعرّف الجلسة."""
    now = datetime.now(dt_timezone.utc)
    exp_dt = now + timedelta(seconds=ttl_seconds)
    payload = {
        'token_type': 'video_playback',
        'sub': str(user_id),
        'lec': lecture_id,
        'pkg': session.course_package_id,
        'sid': str(session.session_id),
        'dev': session.device_id,
        'jti': session.token_jti,
        'iat': int(now.timestamp()),
        'exp': int(exp_dt.timestamp()),
    }
    token = jwt.encode(payload, _video_signing_secret(), algorithm='HS256')
    return token, ttl_seconds


def decode_playback_token(raw_token: str) -> dict[str, Any]:
    """يتحقق من توقيع وصلاحية ونوع توكن تشغيل الفيديو."""
    payload = jwt.decode(raw_token, _video_signing_secret(), algorithms=['HS256'])
    if payload.get('token_type') != 'video_playback':
        raise jwt.InvalidTokenError('Invalid playback token type.')
    return payload


def build_watermark_payload(user, session: PlaybackSession) -> dict[str, Any]:
    """
    يبني بيانات علامة مائية غير حساسة (بدون بريد أو رقم قومي أو بيانات سرية).
    تظهر ككبسولة ديناميكية فوق الفيديو لتتبع التسريب مع حماية خصوصية الطالب.
    """
    code = getattr(user, 'custom_id', None) or f"U{user.id}"
    raw_phone = (getattr(user, 'phone', None) or '').strip()
    masked_phone = f"***{raw_phone[-4:]}" if len(raw_phone) >= 4 else ''
    session_tag = str(session.session_id)[:8].upper()
    display_text = f"{code} • {masked_phone} • {session_tag}" if masked_phone else f"{code} • {session_tag}"
    return {
        'brand': 'Ta3alm',
        'student_code': code,
        'masked_phone': masked_phone,
        'session_tag': session_tag,
        'display_text': display_text,
        'issued_at': timezone.now().isoformat(),
        'opacity': 0.28,
        'move_interval_seconds': 9,
    }


def log_security_event(
    *,
    event_type: str,
    user=None,
    lecture=None,
    session_id: str = '',
    severity: str = 'info',
    request=None,
    device_id: str = '',
    details: dict[str, Any] | None = None,
) -> VideoSecurityAuditLog:
    ip_address = get_client_ip(request) if request is not None else None
    return VideoSecurityAuditLog.objects.create(
        user=user if getattr(user, 'is_authenticated', False) else None,
        lecture=lecture,
        session_id=str(session_id or ''),
        event_type=event_type,
        severity=severity,
        ip_address=ip_address,
        device_id=device_id[:128] if device_id else '',
        details=details or {},
    )


def detect_and_record_anomaly(request, user, lecture, device_id: str = '') -> bool:
    """يكتشف تكرار طلبات التصريح المشبوهة خلال نافذة زمنية قصيرة."""
    ip = get_client_ip(request) or 'unknown'
    cache_key = f"ta3alm:vid_rate:{user.id}:{ip}"
    count = cache.get(cache_key, 0) + 1
    cache.set(cache_key, count, timeout=ANOMALY_WINDOW_SECONDS)
    if count > ANOMALY_AUTH_THRESHOLD:
        log_security_event(
            event_type='anomaly_rapid_requests',
            user=user,
            lecture=lecture,
            severity='high',
            request=request,
            device_id=device_id,
            details={'count_5min': count, 'threshold': ANOMALY_AUTH_THRESHOLD},
        )
        return True
    return False


@transaction.atomic
def create_or_rotate_playback_session(
    *,
    request,
    user,
    lecture,
    package=None,
    device_id: str,
    device_fingerprint: str = '',
    client_platform: str = 'android',
    app_version: str = '',
    integrity_verdict: str = 'unverified',
    view_window_expires_at=None,
) -> tuple[PlaybackSession, int]:
    """
    ينشئ جلسة تشغيل جديدة ويلغي أي جلسات متزامنة تتجاوز الحد المسموح به (MAX_CONCURRENT_SESSIONS).
    """
    now = timezone.now()
    active_sessions = list(
        PlaybackSession.objects.select_for_update()
        .filter(user=user, status='active', expires_at__gt=now)
        .order_by('-last_heartbeat_at', '-created_at')
    )

    revoked_count = 0
    keep_limit = max(MAX_CONCURRENT_SESSIONS - 1, 0)
    sessions_to_revoke = active_sessions[keep_limit:] if keep_limit > 0 else active_sessions
    for old in sessions_to_revoke:
        old.status = 'revoked'
        old.revoked_reason = 'superseded_by_new_session'
        old.save(update_fields=['status', 'revoked_reason'])
        revoked_count += 1
        log_security_event(
            event_type='concurrent_session_revoked',
            user=user,
            lecture=lecture,
            session_id=str(old.session_id),
            severity='warning',
            request=request,
            device_id=device_id,
            details={'revoked_device': old.device_id, 'new_device': device_id},
        )

    session = PlaybackSession.objects.create(
        user=user,
        lecture=lecture,
        course_package=package,
        device_id=device_id[:128],
        device_fingerprint=device_fingerprint[:128],
        client_platform=client_platform[:24],
        app_version=app_version[:32],
        integrity_verdict=integrity_verdict[:32],
        token_jti=uuid.uuid4().hex,
        status='active',
        last_heartbeat_at=now,
        expires_at=now + timedelta(seconds=max(PLAYBACK_TOKEN_TTL_SECONDS * 2, 300)),
        view_window_expires_at=view_window_expires_at,
        ip_address=get_client_ip(request),
        user_agent=(request.META.get('HTTP_USER_AGENT', '') or '')[:255],
    )
    return session, revoked_count

"""
api_v1/video_security.py
خدمات أمان الفيديو، التوقيع المؤقت، مزودي البث المحمي، إدارة الجلسات المتزامنة، كشف الشذوذ، والعلامة المائية الديناميكية.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import time
import urllib.parse
import uuid
from datetime import datetime, timedelta, timezone as dt_timezone
from typing import Any

import jwt
from django.conf import settings
from django.core.cache import cache
from django.db import transaction
from django.utils import timezone

from .models import (
    PlaybackSession,
    VideoAsset,
    VideoSecurityAuditLog,
)


PLAYBACK_TOKEN_TTL_SECONDS = int(os.environ.get('VIDEO_PLAYBACK_TOKEN_TTL', '180'))
HEARTBEAT_INTERVAL_SECONDS = int(os.environ.get('VIDEO_HEARTBEAT_INTERVAL', '25'))
MAX_CONCURRENT_SESSIONS = int(os.environ.get('VIDEO_MAX_CONCURRENT_SESSIONS', '1'))
ANOMALY_WINDOW_SECONDS = 300
ANOMALY_AUTH_THRESHOLD = int(os.environ.get('VIDEO_ANOMALY_THRESHOLD', '25'))


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
        ip_address=get_client_ip(request),
        user_agent=(request.META.get('HTTP_USER_AGENT', '') or '')[:255],
    )
    return session, revoked_count


def _b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b'=').decode('ascii')


def _b64url_decode(raw: str) -> bytes:
    padding = '=' * (-len(raw) % 4)
    return base64.urlsafe_b64decode(f"{raw}{padding}".encode('ascii'))


def _derive_seal_key(session_id: str, playback_token: str) -> bytes:
    return hmac.new(
        playback_token.encode('utf-8'),
        f"ta3alm-yt-seal|{session_id}".encode('utf-8'),
        hashlib.sha256,
    ).digest()


def _hmac_keystream(key: bytes, length: int) -> bytes:
    out = bytearray()
    counter = 0
    while len(out) < length:
        block = hmac.new(key, counter.to_bytes(4, 'big'), hashlib.sha256).digest()
        out.extend(block)
        counter += 1
    return bytes(out[:length])


def seal_video_reference(
    video_id: str,
    session_id: str,
    playback_token: str,
    ttl_seconds: int = PLAYBACK_TOKEN_TTL_SECONDS,
) -> str:
    """
    يشفّر ويوقّع مرجع الفيديو باستخدام مفتاح مشتق من جلسة التشغيل النشطة والتوكن قصير العمر
    حتى لا يظهر الرابط الأصلي أو المعرّف صراحةً في استجابة JSON.
    """
    if not video_id or not session_id or not playback_token:
        return ''
    key = _derive_seal_key(str(session_id), playback_token)
    exp = int(time.time()) + max(int(ttl_seconds), 60)
    plain = f"{video_id}|{exp}".encode('utf-8')
    stream = _hmac_keystream(key, len(plain))
    cipher = bytes(a ^ b for a, b in zip(plain, stream))
    tag = hmac.new(key, cipher, hashlib.sha256).digest()[:16]
    return f"{_b64url_encode(cipher)}.{_b64url_encode(tag)}"


def unseal_video_reference(sealed_ref: str, session_id: str, playback_token: str) -> str | None:
    """يفكّ ويتحقق من توقيع وصلاحية مرجع الفيديو المقفول بنفس الجلسة والتوكن."""
    if not sealed_ref or '.' not in sealed_ref or not session_id or not playback_token:
        return None
    try:
        cipher_b64, tag_b64 = sealed_ref.split('.', 1)
        cipher = _b64url_decode(cipher_b64)
        tag = _b64url_decode(tag_b64)
        key = _derive_seal_key(str(session_id), playback_token)
        expected_tag = hmac.new(key, cipher, hashlib.sha256).digest()[:16]
        if not hmac.compare_digest(tag, expected_tag):
            return None
        stream = _hmac_keystream(key, len(cipher))
        plain = bytes(a ^ b for a, b in zip(cipher, stream)).decode('utf-8')
        vid, exp_str = plain.rsplit('|', 1)
        if int(exp_str) < int(time.time()):
            return None
        return vid
    except Exception:
        return None


def _sign_cloudflare_stream_url(asset: VideoAsset, ttl_seconds: int) -> str | None:
    """
    يوقّع رابط HLS من Cloudflare Stream باستخدام RSA/JWK أو مفتاح موقّع إذا توفر في البيئة.
    """
    customer_code = os.environ.get('CLOUDFLARE_STREAM_CUSTOMER_CODE', '').strip()
    key_id = os.environ.get('CLOUDFLARE_STREAM_KEY_ID', '').strip()
    private_pem = os.environ.get('CLOUDFLARE_STREAM_PRIVATE_KEY_PEM', '').replace('\\n', '\n').strip()
    video_uid = asset.provider_asset_id.strip()
    if not (customer_code and key_id and private_pem and video_uid):
        return None
    exp = int(time.time()) + ttl_seconds
    token = jwt.encode(
        {
            'sub': video_uid,
            'kid': key_id,
            'exp': exp,
            'accessRules': [{'type': 'any', 'action': 'allow'}],
        },
        private_pem,
        algorithm='RS256',
        headers={'kid': key_id},
    )
    return f"https://{customer_code}.cloudflarestream.com/{token}/manifest/video.m3u8"


def _sign_bunny_stream_url(raw_url: str, asset: VideoAsset, ttl_seconds: int) -> str | None:
    """
    يوقّع رابط HLS من Bunny Stream Token Authentication (Directory Path Token).
    """
    security_key = os.environ.get('BUNNY_STREAM_SECURITY_KEY', '').strip()
    if not security_key or not raw_url:
        return None
    parsed = urllib.parse.urlparse(raw_url)
    expires = int(time.time()) + ttl_seconds
    token_path = os.path.dirname(parsed.path) or '/'
    hashable = f"{security_key}{token_path}{expires}token_path={token_path}"
    raw_digest = hashlib.sha256(hashable.encode('utf-8')).digest()
    token = base64.b64encode(raw_digest).decode('ascii').replace('+', '-').replace('/', '_').replace('=', '')
    query = urllib.parse.urlencode({
        'token': token,
        'token_path': token_path,
        'expires': expires,
    })
    return f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{query}"


def _sign_hmac_cdn_url(raw_url: str, playback_token: str, expires: int) -> str:
    """
    يضيف توقيع HMAC مؤقت للروابط الخاصة أو يوجّه عبر نقطة البث المحلية المحمية عند غياب مفاتيح CDN.
    """
    cdn_secret = os.environ.get('CDN_SIGNING_SECRET', '').strip()
    if not cdn_secret:
        return raw_url
    parsed = urllib.parse.urlparse(raw_url)
    payload = f"{parsed.path}:{expires}".encode('utf-8')
    sig = hmac.new(cdn_secret.encode('utf-8'), payload, hashlib.sha256).hexdigest()
    sep = '&' if parsed.query else '?'
    return f"{raw_url}{sep}expires={expires}&sig={sig}&sid={hmac.new(cdn_secret.encode('utf-8'), playback_token.encode('utf-8'), hashlib.sha256).hexdigest()[:16]}"


def resolve_signed_playback_source(
    *,
    request,
    lecture,
    session: PlaybackSession,
    playback_token: str,
    ttl_seconds: int = PLAYBACK_TOKEN_TTL_SECONDS,
) -> dict[str, Any]:
    """
    يحدّد نوع المصدر (منصة محمي أو YouTube قديم معزول) ويولّد روابط بث قصيرة العمر بدون تسريب الروابط الخام.
    """
    asset = getattr(lecture, 'video_asset', None)
    if asset and asset.is_native_protected:
        signed_url = ''
        if asset.provider == 'cloudflare_stream':
            signed_url = _sign_cloudflare_stream_url(asset, ttl_seconds) or ''
        elif asset.provider == 'bunny_stream' and asset.manifest_url:
            signed_url = _sign_bunny_stream_url(asset.manifest_url, asset, ttl_seconds) or ''

        expires_ts = int(time.time()) + ttl_seconds
        if not signed_url and asset.manifest_url:
            # استخدام HMAC على رابط CDN الخاص أو وكيل البث الداخلي الموقّع للمحاضرات المحلية
            if os.environ.get('CDN_SIGNING_SECRET', '').strip():
                signed_url = _sign_hmac_cdn_url(asset.manifest_url, playback_token, expires_ts)
            else:
                signed_url = request.build_absolute_uri(
                    f"/api/v1/videos/stream/{playback_token}/"
                )

        # توقيع مسارات الجودات إن وُجدت
        signed_variants = []
        for idx, var in enumerate(asset.quality_variants or []):
            if not isinstance(var, dict):
                continue
            label = str(var.get('label') or f"{var.get('height', '')}p").strip()
            var_url = str(var.get('url') or '').strip()
            if var_url:
                if asset.provider == 'bunny_stream':
                    signed_var_url = _sign_bunny_stream_url(var_url, asset, ttl_seconds) or var_url
                elif os.environ.get('CDN_SIGNING_SECRET', '').strip():
                    signed_var_url = _sign_hmac_cdn_url(var_url, playback_token, expires_ts)
                else:
                    signed_var_url = request.build_absolute_uri(
                        f"/api/v1/videos/stream/{playback_token}/?variant={idx}"
                    )
                signed_variants.append({
                    'label': label,
                    'height': int(var.get('height') or 0),
                    'bandwidth': int(var.get('bandwidth') or 0),
                    'url': signed_var_url,
                })

        return {
            'is_native_protected': True,
            'source_type': asset.source_type,
            'provider': asset.provider,
            'stream_url': signed_url,
            'quality_variants': signed_variants,
            'subtitle_tracks': asset.subtitle_tracks or [],
            'drm': {
                'enabled': asset.drm_enabled,
                'scheme': asset.drm_scheme,
                'license_url': asset.drm_license_url if asset.drm_enabled else '',
            },
            'intro_skip': (
                {
                    'start_seconds': asset.intro_start_seconds,
                    'end_seconds': asset.intro_end_seconds,
                }
                if asset.intro_end_seconds > asset.intro_start_seconds
                else None
            ),
            'duration_seconds': asset.duration_seconds,
            'youtube_video_id': None,
            'migration_status': asset.migration_status,
        }

    # روابط المحاضرات غير المرفوعة على CDN خارجي: تشفير وتوقيع المرجع بالجلسة وإخفاء الرابط الخام تماماً
    yt_id = lecture.get_video_id()
    sealed_ref = (
        seal_video_reference(yt_id, str(session.session_id), playback_token, ttl_seconds)
        if yt_id
        else ''
    )
    return {
        'is_native_protected': False,
        'source_type': 'ta3alm_shield' if yt_id else 'external_legacy',
        'provider': 'ta3alm_shield' if yt_id else 'external',
        'stream_url': '',
        'sealed_video_ref': sealed_ref,
        'quality_variants': [],
        'subtitle_tracks': [],
        'drm': {'enabled': False, 'scheme': 'none', 'license_url': ''},
        'intro_skip': None,
        'duration_seconds': asset.duration_seconds if asset else 0,
        'youtube_video_id': None,
        'legacy_external_url': '',
        'migration_status': asset.migration_status if asset else 'shielded',
        'migration_notice': '',
    }


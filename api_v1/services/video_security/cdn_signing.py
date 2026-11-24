"""api_v1.services.video_security.cdn_signing
Extracted from api_v1/video_security.py.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import os
import time
import urllib.parse
from typing import Any
import jwt
from api_v1.models import (
    PlaybackSession,
    VideoAsset,
)

from api_v1.services.video_security.constants import PLAYBACK_TOKEN_TTL_SECONDS
from api_v1.services.video_security.sealing import seal_video_reference


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

    # روابط المحاضرات غير المرفوعة على CDN خارجي: تصنيف المصدر وتشفيره وربطه بالجلسة دون تسريب الرابط الخام
    classified = lecture.classify_video_source(getattr(lecture, 'video_link', '') or '')
    kind = classified.get('kind', 'empty')

    if kind == 'youtube':
        yt_id = classified.get('youtube_id') or ''
        sealed_ref = (
            seal_video_reference(yt_id, str(session.session_id), playback_token, ttl_seconds)
            if yt_id
            else ''
        )
        return {
            'is_native_protected': False,
            'source_type': 'ta3alm_shield',
            'provider': 'ta3alm_shield',
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

    if kind == 'direct_stream':
        target_url = classified.get('url') or ''
        sealed_ref = (
            seal_video_reference(target_url, str(session.session_id), playback_token, ttl_seconds)
            if target_url
            else ''
        )
        stream_fmt = classified.get('stream_format') or 'mp4'
        return {
            'is_native_protected': True,
            'source_type': 'hls_protected' if stream_fmt == 'hls' else 'mp4_protected',
            'provider': 'direct_shield',
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

    if kind == 'embed':
        target_url = classified.get('url') or ''
        sealed_ref = (
            seal_video_reference(target_url, str(session.session_id), playback_token, ttl_seconds)
            if target_url
            else ''
        )
        return {
            'is_native_protected': False,
            'source_type': 'embedded_shield',
            'provider': 'embedded_shield',
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

    return {
        'is_native_protected': False,
        'source_type': 'external_legacy',
        'provider': 'external',
        'stream_url': '',
        'sealed_video_ref': '',
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

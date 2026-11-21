"""api_v1.services.security_engine.request_signing
Extracted from api_v1/security_engine.py.
"""
from __future__ import annotations

import hashlib
import hmac
import time
from typing import Any
from django.core.cache import cache
from api_v1.models import SecurityPolicyConfig

from api_v1.services.security_engine.constants import (
    MIN_SIGNED_NATIVE_BUILD,
    _MASK_SEQ,
    _SHARD_A,
    _SHARD_B,
    _SHARD_C,
    _SHARD_D,
)


def _derive_client_signing_key() -> bytes:
    """إعادة تجميع مفتاح HMAC-SHA256 المشتق من الشظايا المقنّعة مع دعم المتغير البيئي الاختياري."""
    import os

    override = os.environ.get('TA3ALM_CLIENT_SIGNING_SECRET', '').strip()
    if override:
        return hashlib.sha256(override.encode('utf-8')).digest()

    raw_bytes = bytearray()
    for shard_idx, shard in enumerate((_SHARD_A, _SHARD_B, _SHARD_C, _SHARD_D)):
        for i, val in enumerate(shard):
            raw_bytes.append((val ^ _MASK_SEQ[i] ^ ((shard_idx * 19 + i * 7) & 0xFF)) & 0xFF)
    salt = b'ta3alm.edge.hmac.v2'
    return hashlib.sha256(bytes(raw_bytes) + salt).digest()


def _empty_body_sha256() -> str:
    return hashlib.sha256(b'').hexdigest()


def _extract_raw_body_sha256(request) -> str:
    content_type = str(getattr(request, 'content_type', '') or request.META.get('CONTENT_TYPE', '') or '').lower()
    if 'multipart/form-data' in content_type:
        return _empty_body_sha256()
    try:
        raw = request.body or b''
    except Exception:
        raw = b''
    return hashlib.sha256(raw).hexdigest()


def verify_client_request_signature(request) -> dict[str, Any]:
    """
    يتحقق من صحة التوقيع التشفيري للطلب (HMAC-SHA256 + Anti-Replay Nonce + Timestamp Window).
    يُرجع قاموساً: {'valid': bool, 'present': bool, 'code': str, 'reason': str, 'tampered': bool}.
    """
    meta = getattr(request, 'META', {}) or {}
    sig = str(meta.get('HTTP_X_TA3ALM_SIG') or '').strip().lower()
    ts_raw = str(meta.get('HTTP_X_TA3ALM_TS') or '').strip()
    nonce = str(meta.get('HTTP_X_TA3ALM_NONCE') or '').strip()
    device_id = str(meta.get('HTTP_X_DEVICE_ID') or meta.get('HTTP_X_INSTALLATION_ID') or '').strip()
    platform = str(meta.get('HTTP_X_CLIENT_PLATFORM') or '').strip().lower()
    build_raw = str(meta.get('HTTP_X_APP_BUILD') or '').strip()

    present = bool(sig or ts_raw or nonce)
    policy = SecurityPolicyConfig.load()

    if not present:
        # إذا كان العميل يدّعي أنه إصدار التطبيق الجديد (build >= 6) ولكنه حذف ترويسات التوقيع عبر Proxy
        try:
            build_num = int(build_raw) if build_raw else 0
        except (TypeError, ValueError):
            build_num = 0
        must_sign = (
            policy.enforce_request_signatures
            and platform in ('android', 'ios')
            and build_num >= MIN_SIGNED_NATIVE_BUILD
        )
        if must_sign:
            return {
                'valid': False,
                'present': False,
                'tampered': True,
                'code': 'MISSING_REQUEST_SIGNATURE',
                'reason': 'تم حذف توقيع الأمان من الطلب أو اعتراضه عبر وسيط غير مصرح.',
            }
        return {'valid': True, 'present': False, 'tampered': False, 'code': 'NOT_REQUIRED', 'reason': ''}

    if not sig or not ts_raw or not nonce or len(nonce) < 12 or len(nonce) > 96:
        return {
            'valid': False,
            'present': True,
            'tampered': True,
            'code': 'MALFORMED_REQUEST_SIGNATURE',
            'reason': 'ترويسات التوقيع الأمني غير مكتملة أو تم العبث بها.',
        }

    try:
        req_ts = int(ts_raw)
    except (TypeError, ValueError):
        return {
            'valid': False,
            'present': True,
            'tampered': True,
            'code': 'INVALID_SIGNATURE_TIMESTAMP',
            'reason': 'طابع الوقت الأمني غير صالح.',
        }

    now_ts = int(time.time())
    max_skew = max(int(policy.request_signature_max_skew_seconds or 300), 60)
    if abs(now_ts - req_ts) > max_skew:
        return {
            'valid': False,
            'present': True,
            'tampered': True,
            'code': 'EXPIRED_REQUEST_SIGNATURE',
            'reason': 'انتهت صلاحية توقيع الطلب أو هناك فرق غير مقبول في التوقيت.',
        }

    body_hash = _extract_raw_body_sha256(request)
    canonical = f"{request.method.upper()}|{request.path}|{req_ts}|{nonce}|{body_hash}|{device_id}"
    expected_sig = hmac.new(
        _derive_client_signing_key(),
        canonical.encode('utf-8'),
        hashlib.sha256,
    ).hexdigest().lower()

    if not hmac.compare_digest(expected_sig, sig):
        return {
            'valid': False,
            'present': True,
            'tampered': True,
            'code': 'INVALID_REQUEST_SIGNATURE',
            'reason': 'فشل التحقق التشفيري من سلامة الطلب (محاولة تعديل أو MITM).',
        }

    nonce_cache_key = f"ta3alm:sig_nonce:{hashlib.sha256(f'{device_id}:{nonce}'.encode('utf-8')).hexdigest()}"
    added = cache.add(nonce_cache_key, 1, timeout=max_skew + 30)
    if not added:
        return {
            'valid': False,
            'present': True,
            'tampered': True,
            'code': 'REPLAY_ATTACK_DETECTED',
            'reason': 'تم رصد إعادة إرسال طلب مكرر (Replay Attack).',
        }

    return {'valid': True, 'present': True, 'tampered': False, 'code': 'OK', 'reason': ''}

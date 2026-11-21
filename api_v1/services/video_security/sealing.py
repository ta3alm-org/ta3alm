"""api_v1.services.video_security.sealing
Extracted from api_v1/video_security.py.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import time

from api_v1.services.video_security.constants import PLAYBACK_TOKEN_TTL_SECONDS


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

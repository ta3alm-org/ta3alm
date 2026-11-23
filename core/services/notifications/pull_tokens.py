"""core.services.notifications.pull_tokens
Extracted from core/notifications_service.py.
"""
from __future__ import annotations

import hashlib
import re
from django.contrib.auth import get_user_model
from django.core import signing

from core.services.notifications.constants import _PULL_SIGNER

_SUPPORT_REPLY_SIGNER = signing.TimestampSigner(salt='ta3alm.support.quick_reply.v1')
_SUPPORT_THREAD_LINK_RE = re.compile(r'/support/chat/(\d+)(?:/|$)', re.IGNORECASE)
SUPPORT_QUICK_REPLY_URL = 'https://www.ta3alm.online/api/v1/support/chat/quick-reply/'


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


def extract_support_thread_id(link: str | None) -> int | None:
    """يستخرج رقم محادثة الدعم من رابط الإشعار إذا كان يشير إلى /support/chat/<id>/."""
    raw = str(link or '').strip()
    if not raw:
        return None
    match = _SUPPORT_THREAD_LINK_RE.search(raw)
    if not match:
        return None
    try:
        tid = int(match.group(1))
        return tid if tid > 0 else None
    except (TypeError, ValueError):
        return None


def generate_support_reply_token(user, thread_id: int) -> str:
    """يُصدر رمزاً موقّعاً ومقيداً بالمستخدم والمحادثة للرد المباشر من إشعار أندرويد."""
    if not user or not getattr(user, 'pk', None):
        return ''
    try:
        tid = int(thread_id)
    except (TypeError, ValueError):
        return ''
    if tid <= 0:
        return ''
    payload = f"{user.pk}:{tid}:{_password_epoch_digest(user)}"
    return _SUPPORT_REPLY_SIGNER.sign(payload)


def verify_support_reply_token(token: str, max_age_seconds: int = 7 * 86400):
    """يتحقق من رمز الرد المباشر ويعيد (user, thread_id) أو None."""
    raw = str(token or '').strip()
    if not raw:
        return None
    try:
        unsigned = _SUPPORT_REPLY_SIGNER.unsign(raw, max_age=max_age_seconds)
        uid_str, tid_str, pwd_sig = unsigned.split(':', 2)
        uid = int(uid_str)
        tid = int(tid_str)
        if tid <= 0:
            return None
    except Exception:
        return None

    User = get_user_model()
    user = User.objects.filter(pk=uid, is_active=True, is_banned=False).first()
    if not user:
        return None
    if _password_epoch_digest(user) != pwd_sig:
        return None
    return user, tid


def extract_support_sender_label(title: str | None) -> str:
    clean = str(title or '').strip()
    prefix = 'رسالة دعم جديدة من '
    if clean.startswith(prefix) and len(clean) > len(prefix):
        return clean[len(prefix):].strip()[:80]
    if 'الدعم' in clean:
        return 'فريق الدعم الفني'
    return 'منصة تعلّم'


def build_support_reply_metadata(notification) -> dict[str, str] | None:
    """يبني حقول الرد المباشر للإشعارات المرتبطة بشات الدعم الفني."""
    recipient = getattr(notification, 'recipient', None)
    if not recipient or not getattr(recipient, 'pk', None):
        return None
    thread_id = extract_support_thread_id(getattr(notification, 'link', None))
    if not thread_id:
        return None
    reply_token = generate_support_reply_token(recipient, thread_id)
    if not reply_token:
        return None
    return {
        'reply_type': 'support_chat',
        'thread_id': str(thread_id),
        'reply_token': reply_token,
        'reply_url': SUPPORT_QUICK_REPLY_URL,
        'sender_name': extract_support_sender_label(getattr(notification, 'title', None)),
    }

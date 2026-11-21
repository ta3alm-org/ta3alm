"""core.services.notifications.pull_tokens
Extracted from core/notifications_service.py.
"""
from __future__ import annotations

import hashlib
from django.contrib.auth import get_user_model

from core.services.notifications.constants import _PULL_SIGNER


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

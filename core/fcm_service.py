"""
core/fcm_service.py
خدمة إرسال إشعارات الدفع اللحظية عبر واجهة Firebase Cloud Messaging HTTP v1 API.
تعمل اختيارياً عند ضبط FIREBASE_SERVICE_ACCOUNT_JSON أو FIREBASE_SERVICE_ACCOUNT_FILE،
وتتراجع بصمت وأمان دون التأثير على المنصة عند عدم التهيئة.
"""
from __future__ import annotations

import json
import logging
import os
import threading
from typing import Iterable

from django.conf import settings
from django.db import close_old_connections, transaction

logger = logging.getLogger(__name__)

FCM_SCOPE = ('https://www.googleapis.com/auth/firebase.messaging',)
FCM_SEND_TIMEOUT_SECONDS = 8

_CRED_LOCK = threading.Lock()
_CACHED_STATE: tuple[tuple[str, str], str, object] | None = None  # (key, project_id, credentials)


def resolve_android_channel(title: str, link: str | None = None) -> str:
    """يطابق منطق اختيار قناة الإشعارات داخل Ta3almNotificationHelper.kt."""
    text = f"{str(title or '').lower()} {str(link or '').lower()}"
    if '/support/chat' in str(link or '').lower():
        return 'ta3alm_support_chat'

    security_markers = (
        '/devices',
        '/security',
        '/banned',
        'أمني',
        'حظر',
        'كلمة المرور',
        'جهاز',
        'شاشة',
    )
    if any(marker in text for marker in security_markers):
        return 'ta3alm_security'

    finance_markers = (
        'wallet',
        'finance',
        'subscription',
        'الدفع',
        'محفظ',
        'سحب',
        'أرباح',
        'اشتراك',
        'مبيعة',
    )
    if any(marker in text for marker in finance_markers):
        return 'ta3alm_finance'

    return 'ta3alm_academic'


def _normalize_link_value(link: str | None) -> str:
    trimmed = str(link or '').strip()
    if not trimmed:
        return '/notifications/all/'
    return trimmed


def _get_fcm_setting_sources() -> tuple[str, str]:
    raw_json = (
        getattr(settings, 'FIREBASE_SERVICE_ACCOUNT_JSON', '')
        or os.environ.get('FIREBASE_SERVICE_ACCOUNT_JSON', '')
    ).strip()
    file_path = (
        getattr(settings, 'FIREBASE_SERVICE_ACCOUNT_FILE', '')
        or os.environ.get('FIREBASE_SERVICE_ACCOUNT_FILE', '')
        or os.environ.get('GOOGLE_APPLICATION_CREDENTIALS', '')
    ).strip()
    return raw_json, file_path


def _load_service_account_info() -> dict | None:
    raw_json, file_path = _get_fcm_setting_sources()

    # دعم وضع المسار مباشرة داخل FIREBASE_SERVICE_ACCOUNT_JSON أو نص JSON مباشر
    if raw_json:
        cleaned = raw_json.strip()
        if (cleaned.startswith("'") and cleaned.endswith("'")) or (
            cleaned.startswith('"') and cleaned.endswith('"')
        ):
            # إزالة علامات التنصيص الخارجية إذا وُضعت في .env
            if len(cleaned) >= 2 and cleaned[1:-1].lstrip().startswith('{'):
                cleaned = cleaned[1:-1]
        if cleaned.startswith('{'):
            try:
                data = json.loads(cleaned)
                if isinstance(data, dict):
                    return _sanitize_private_key(data)
            except Exception:
                logger.warning("Invalid FIREBASE_SERVICE_ACCOUNT_JSON payload; ignoring.")
                return None
        elif os.path.isfile(cleaned):
            file_path = cleaned

    if file_path and os.path.isfile(file_path):
        try:
            with open(file_path, 'r', encoding='utf-8') as fh:
                data = json.load(fh)
            if isinstance(data, dict):
                return _sanitize_private_key(data)
        except Exception:
            logger.warning("Failed reading FIREBASE_SERVICE_ACCOUNT_FILE at %s", file_path)
            return None

    return None


def _sanitize_private_key(data: dict) -> dict:
    pk = data.get('private_key')
    if isinstance(pk, str) and '\\n' in pk and '\n' not in pk:
        data = dict(data)
        data['private_key'] = pk.replace('\\n', '\n')
    return data


def is_fcm_configured() -> bool:
    """يتحقق من توفر بيانات اعتماد Firebase Service Account دون إنشاء شبكة."""
    info = _load_service_account_info()
    if not info:
        return False
    return bool(info.get('project_id') and info.get('client_email') and info.get('private_key'))


def _get_credentials_and_project():
    """يعيد (project_id, Credentials) مع التخزين المؤقت وتحديثه تلقائياً عند تغير الإعدادات."""
    global _CACHED_STATE
    cache_key = _get_fcm_setting_sources()
    with _CRED_LOCK:
        if _CACHED_STATE and _CACHED_STATE[0] == cache_key:
            return _CACHED_STATE[1], _CACHED_STATE[2]

        info = _load_service_account_info()
        if not info or not info.get('project_id'):
            _CACHED_STATE = None
            return None, None

        try:
            from google.oauth2 import service_account

            creds = service_account.Credentials.from_service_account_info(
                info,
                scopes=FCM_SCOPE,
            )
            project_id = str(info['project_id']).strip()
            _CACHED_STATE = (cache_key, project_id, creds)
            return project_id, creds
        except Exception:
            logger.exception("Failed building Firebase service account credentials")
            _CACHED_STATE = None
            return None, None


def _build_fcm_message(notification, device_token: str) -> dict:
    from core.services.notifications.pull_tokens import build_support_reply_metadata

    title = str(getattr(notification, 'title', '') or 'منصة تعلّم').strip() or 'منصة تعلّم'
    full_body = str(getattr(notification, 'message', '') or '').strip()
    body = (full_body[:499] + '…') if len(full_body) > 500 else full_body
    link = _normalize_link_value(getattr(notification, 'link', None))
    channel_id = resolve_android_channel(title, link)
    notif_id_str = str(getattr(notification, 'pk', '') or '')

    data_payload = {
        'notification_id': notif_id_str,
        'title': title,
        'message': body,
        'link': link,
        'channel_id': channel_id,
        'click_action': 'FLUTTER_NOTIFICATION_CLICK',
    }

    support_meta = build_support_reply_metadata(notification)
    if support_meta:
        data_payload.update(support_meta)
        # رسالة Data-Only عالية الأولوية لإظهار إشعار الرد المباشر (RemoteInput) حتى عند غلق التطبيق
        return {
            'message': {
                'token': device_token,
                'data': data_payload,
                'android': {
                    'priority': 'HIGH',
                },
            }
        }

    return {
        'message': {
            'token': device_token,
            'notification': {
                'title': title,
                'body': body,
            },
            'data': data_payload,
            'android': {
                'priority': 'HIGH',
                'notification': {
                    'channel_id': channel_id,
                    'sound': 'ta3alm_chime',
                    'tag': f'ta3alm_notif_{notif_id_str}' if notif_id_str else 'ta3alm_notif',
                    'click_action': 'FLUTTER_NOTIFICATION_CLICK',
                },
            },
        }
    }


def _should_deactivate_token(status_code: int, resp_json: dict | None) -> bool:
    if status_code in (404, 410):
        return True
    if not isinstance(resp_json, dict):
        return False
    err = resp_json.get('error')
    if not isinstance(err, dict):
        return False
    if str(err.get('status', '')).upper() == 'NOT_FOUND':
        return True
    details = err.get('details')
    if isinstance(details, list):
        for detail in details:
            if isinstance(detail, dict) and str(detail.get('errorCode', '')).upper() == 'UNREGISTERED':
                return True
    return False


def _post_fcm_message(session, project_id: str, payload: dict) -> tuple[bool, bool]:
    url = f"https://fcm.googleapis.com/v1/projects/{project_id}/messages:send"
    try:
        response = session.post(url, json=payload, timeout=FCM_SEND_TIMEOUT_SECONDS)
    except Exception:
        logger.warning("Network error while posting FCM message", exc_info=True)
        return False, False

    if 200 <= getattr(response, 'status_code', 500) < 300:
        return True, False

    resp_json = None
    try:
        resp_json = response.json()
    except Exception:
        resp_json = None

    deactivate = _should_deactivate_token(getattr(response, 'status_code', 500), resp_json)
    if not deactivate:
        logger.warning(
            "FCM v1 send rejected (status=%s): %s",
            getattr(response, 'status_code', None),
            getattr(response, 'text', '')[:300],
        )
    return False, deactivate


def send_fcm_push_for_notifications(notifications_or_ids: Iterable) -> dict:
    """
    يرسل إشعارات الدفع FCM لقائمة من الإشعارات أو معرفاتها.
    يعيد ملخصاً: {'configured': bool, 'sent': int, 'failed': int, 'deactivated': int}.
    """
    from .models import FCMDeviceToken, Notification

    items = list(notifications_or_ids or [])
    if not items:
        return {'configured': is_fcm_configured(), 'sent': 0, 'failed': 0, 'deactivated': 0}

    project_id, creds = _get_credentials_and_project()
    if not project_id or not creds:
        return {'configured': False, 'sent': 0, 'failed': 0, 'deactivated': 0}

    if all(isinstance(x, int) for x in items):
        notifications = []
        for start in range(0, len(items), 450):
            chunk_ids = items[start : start + 450]
            notifications.extend(Notification.objects.filter(id__in=chunk_ids, is_read=False))
    else:
        notifications = [x for x in items if getattr(x, 'recipient_id', None)]

    if not notifications:
        return {'configured': True, 'sent': 0, 'failed': 0, 'deactivated': 0}

    recipient_ids = sorted({n.recipient_id for n in notifications if getattr(n, 'recipient_id', None)})
    tokens_by_user: dict[int, list[FCMDeviceToken]] = {}
    for start in range(0, len(recipient_ids), 450):
        user_chunk = recipient_ids[start : start + 450]
        for dev_token in FCMDeviceToken.objects.filter(user_id__in=user_chunk, is_active=True):
            tokens_by_user.setdefault(dev_token.user_id, []).append(dev_token)

    if not tokens_by_user:
        return {'configured': True, 'sent': 0, 'failed': 0, 'deactivated': 0}

    try:
        from google.auth.transport.requests import AuthorizedSession

        session = AuthorizedSession(creds)
    except Exception:
        logger.exception("Failed creating Google AuthorizedSession for FCM")
        return {'configured': False, 'sent': 0, 'failed': 0, 'deactivated': 0}

    sent = 0
    failed = 0
    dead_token_ids: list[int] = []

    try:
        for notif in notifications:
            user_tokens = tokens_by_user.get(notif.recipient_id) or []
            for dev_token in user_tokens:
                if dev_token.pk in dead_token_ids:
                    continue
                payload = _build_fcm_message(notif, dev_token.token)
                ok, deactivate = _post_fcm_message(session, project_id, payload)
                if ok:
                    sent += 1
                else:
                    failed += 1
                    if deactivate:
                        dead_token_ids.append(dev_token.pk)
    finally:
        close_fn = getattr(session, 'close', None)
        if callable(close_fn):
            try:
                close_fn()
            except Exception:
                pass

    if dead_token_ids:
        FCMDeviceToken.objects.filter(id__in=dead_token_ids).update(is_active=False)

    return {
        'configured': True,
        'sent': sent,
        'failed': failed,
        'deactivated': len(dead_token_ids),
    }


def _run_background_fcm_dispatch(notification_ids: list[int]) -> None:
    try:
        close_old_connections()
        send_fcm_push_for_notifications(notification_ids)
    except Exception:
        logger.exception("Unhandled error inside background FCM dispatch thread")
    finally:
        close_old_connections()


def schedule_fcm_push_for_notifications(notifications_or_ids: Iterable) -> bool:
    """
    يجدول إرسال FCM في خيط خلفي بعد التزام معاملة قاعدة البيانات (transaction.on_commit).
    يعود فوراً دون حظر الطلب عند عدم ضبط إعدادات Firebase.
    """
    if not is_fcm_configured():
        return False

    ids: list[int] = []
    for item in notifications_or_ids or []:
        pk = item if isinstance(item, int) else getattr(item, 'pk', None)
        if isinstance(pk, int) and pk > 0:
            ids.append(pk)

    if not ids:
        return False

    def _enqueue():
        thread = threading.Thread(
            target=_run_background_fcm_dispatch,
            args=(ids,),
            daemon=True,
            name='ta3alm-fcm-dispatch',
        )
        thread.start()

    transaction.on_commit(_enqueue)
    return True


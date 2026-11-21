"""
Compatibility facade for core.notifications_service.
"""
from __future__ import annotations

import hashlib
import logging
from datetime import timedelta
from typing import Iterable
from django.conf import settings
from django.contrib.auth import get_user_model
from django.core import signing
from django.core.cache import cache
from django.db.models import Q
from django.utils import timezone
from core.models import Notification

import logging
logger = logging.getLogger('core.notifications_service')
from core.services.notifications.constants import (
    CUSTOM_LINK_PRESETS,
    CUSTOM_NOTIFICATION_SEGMENTS,
    CUSTOM_SEGMENT_MAP,
    CUSTOM_TARGET_ALL,
    CUSTOM_TARGET_MODE_CHOICES,
    CUSTOM_TARGET_SEGMENT,
    CUSTOM_TARGET_USERS,
    MAX_TITLE_LEN,
    _PULL_SIGNER,
)
from core.services.notifications.delivery import (
    _clean_title,
    _user_display_name,
    maybe_notify_teacher_subscription_expiry,
    maybe_notify_zoho_inbox,
    notify_group_students,
    notify_package_students,
    notify_platform_admins,
    notify_teacher_and_assistants,
    notify_user,
    notify_users_bulk,
)
from core.services.notifications.pull_tokens import (
    _password_epoch_digest,
    generate_notif_pull_token,
    verify_notif_pull_token,
)
from core.services.notifications.campaigns import (
    _serialize_recipient_brief,
    get_custom_notification_metadata,
    parse_user_ids_input,
    resolve_custom_notification_recipients,
    send_custom_notification,
    validate_custom_notification_link,
)
from core.selectors.notification_selectors import (
    _count_fcm_enabled_users,
    preview_custom_notification_audience,
    search_custom_notification_users,
)

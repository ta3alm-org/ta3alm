"""
core/services/notifications package.
"""
from __future__ import annotations

from .constants import (
    _PULL_SIGNER,
    MAX_TITLE_LEN,
    CUSTOM_TARGET_ALL,
    CUSTOM_TARGET_SEGMENT,
    CUSTOM_TARGET_USERS,
    CUSTOM_TARGET_MODE_CHOICES,
    CUSTOM_NOTIFICATION_SEGMENTS,
    CUSTOM_SEGMENT_MAP,
    CUSTOM_LINK_PRESETS,
)
from .delivery import (
    _clean_title,
    _user_display_name,
    notify_user,
    notify_users_bulk,
    notify_group_students,
    notify_package_students,
    notify_teacher_and_assistants,
    notify_platform_admins,
    maybe_notify_teacher_subscription_expiry,
    maybe_notify_zoho_inbox,
)
from .pull_tokens import (
    _password_epoch_digest,
    generate_notif_pull_token,
    verify_notif_pull_token,
)
from .campaigns import (
    parse_user_ids_input,
    validate_custom_notification_link,
    _serialize_recipient_brief,
    resolve_custom_notification_recipients,
    send_custom_notification,
    get_custom_notification_metadata,
)

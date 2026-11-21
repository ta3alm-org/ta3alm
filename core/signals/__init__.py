"""
core/signals package (preserves exact signal registration order).
"""
from __future__ import annotations

import logging
from django.contrib.auth import get_user_model
from django.db.models.signals import (
    m2m_changed,
    post_delete,
    post_save,
    pre_save,
)
from django.dispatch import receiver
from core.models import (
    ManualPayment,
    SiteSetting,
)
from core.notifications_service import (
    _user_display_name,
    notify_group_students,
    notify_package_students,
    notify_platform_admins,
    notify_teacher_and_assistants,
    notify_user,
)
from django.contrib.auth.signals import user_logged_out

import logging
logger = logging.getLogger('core.signals')
from core.signals.accounts import User
from core.signals.accounts import (
    _capture_email_verification_prev,
    _capture_user_prev_state,
    _notify_email_verified_welcome,
    _notify_one_time_login_link,
    _notify_user_security_changes,
)
from core.signals.academics import (
    _capture_enrollment_prev,
    _capture_exam_prev,
    _capture_lecture_prev,
    _capture_videocode_prev,
    _notify_enrollment_deleted,
    _notify_enrollment_events,
    _notify_exam_published,
    _notify_lecture_published,
    _notify_package_content_added,
    _notify_pdf_uploaded,
    _notify_videocode_events,
    connect_m2m_signals,
)
from core.signals.results import (
    _capture_video_tracking_prev,
    _notify_exam_result,
    _notify_package_exam_result,
    _notify_package_video_completed,
    _notify_performance_log,
)
from core.signals.packages_finance import (
    _capture_manual_payment_prev,
    _capture_pkg_enrollment_prev,
    _capture_withdraw_prev,
    _notify_manual_payment_events,
    _notify_package_purchased,
    _notify_subscription_payment_tx,
    _notify_withdraw_request_events,
)
from core.signals.staff import (
    _capture_admin_profile_prev,
    _capture_assistant_job_prev,
    _notify_admin_staff_assigned,
    _notify_admin_staff_removed,
    _notify_assistant_job_events,
    _notify_assistant_job_removed,
)
from core.signals.devices_security import (
    _capture_device_block_prev,
    _capture_registered_device_prev,
    _notify_admins_critical_security_event,
    _notify_device_block_events,
    _notify_registered_device_events,
)
from core.signals.site_settings import (
    _capture_site_setting_prev,
    _notify_site_setting_changes,
)
from core.signals.session_fcm import (
    _clear_video_watch_window_on_logout,
    _dispatch_fcm_on_notification_created,
)

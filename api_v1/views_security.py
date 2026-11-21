"""
Compatibility facade for api_v1.views_security.
"""
from __future__ import annotations

from django.contrib.auth import get_user_model
from django.db.models import Q
from django.shortcuts import get_object_or_404
from django.utils import timezone
from rest_framework import status
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView
from dashboard_admin.models import AuditLog
from api_v1.device_security_service import (
    block_device_admin,
    build_unified_devices_registry,
    extract_network_context,
    get_user_device_limit,
    prune_expired_telemetry,
    record_device_activity,
    record_security_event,
    register_or_update_device,
    revoke_user_device,
    serialize_device_summary,
    unblock_device_admin,
)
from api_v1.models import (
    DeviceActivity,
    DeviceBlock,
    DeviceSecurityEvent,
    DeviceSession,
    DeviceTrustStatus,
    PlaybackSession,
    RegisteredDevice,
    SecurityPolicyConfig,
    UserSecurityProfile,
)
from api_v1.permissions import (
    IsNotBanned,
    IsPlatformAdmin,
)
from api_v1.security_engine import (
    analyze_user_with_ai,
    compute_behavioral_risk,
    enforce_security_ban,
    get_effective_ai_config,
    record_behavioral_activity,
    run_hourly_ai_behavioral_audit,
    serialize_user_security_profile,
    unban_user_and_devices,
    verify_client_request_signature,
)

from api_v1.views.security.devices import User
from api_v1.views.security.helpers import (
    ALLOWED_CLIENT_REPORT_EVENTS,
    _extract_client_installation_id,
    _is_platform_admin,
    _serialize_event,
    _serialize_policy,
    _serialize_session,
)
from api_v1.views.security.devices import (
    SecurityDeviceListAPIView,
    SecurityDeviceRegisterAPIView,
    SecurityDeviceRevokeAPIView,
    SecurityDeviceVerifyAPIView,
)
from api_v1.views.security.monitoring import (
    SecurityEventReportAPIView,
    SecurityEventsListAPIView,
    SecuritySessionsListAPIView,
)
from api_v1.views.security.admin_actions import SecurityAdminActionAPIView

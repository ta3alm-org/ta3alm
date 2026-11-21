"""
Compatibility facade for api_v1.device_security_service (split into api_v1.services.device_security and api_v1.selectors.device_selectors).
"""
from __future__ import annotations

import hashlib
import hmac
import ipaddress
import os
import re
import uuid
from datetime import timedelta
from typing import Any
from django.conf import settings
from django.contrib.auth import get_user_model
from django.core import signing
from django.core.cache import cache
from django.db import transaction
from django.db.models import Count, Q
from django.utils import timezone
from core.models import Notification
from api_v1.models import (
    DeviceActivity,
    DeviceBlock,
    DeviceFingerprint,
    DeviceIntegrityRecord,
    DeviceSecurityEvent,
    DeviceSession,
    DeviceTrustStatus,
    PlaybackSession,
    RegisteredDevice,
    SecurityPolicyConfig,
    VideoSecurityAuditLog,
)

User = get_user_model()
from api_v1.services.device_security.constants import (
    BENIGN_DRIFT_FIELDS,
    CORE_FINGERPRINT_FIELDS,
    FINGERPRINT_ALGORITHM_VERSION,
    MAX_IP_HISTORY_ENTRIES,
    SUPPORTING_FINGERPRINT_FIELDS,
    WEB_COOKIE_NAME,
    WEB_COOKIE_SALT,
    WEB_IOS_ONLY_ERROR,
    WEB_PACKAGE_NAME,
    WEB_STRICT_CORE_FIELDS,
    _BROWSER_UA_MARKERS,
    _DESKTOP_OR_EMULATED_GPU_TOKENS,
    _VPN_ISP_KEYWORDS,
)
from api_v1.services.device_security.fingerprint import (
    _fingerprint_secret,
    generate_versioned_fingerprint,
    normalize_device_info,
    validate_installation_id,
)
from api_v1.services.device_security.network import (
    analyze_ip_transition,
    extract_network_context,
    get_server_observed_ip,
)
from api_v1.services.device_security.hardware import (
    _clean_hw_token,
    _extract_device_hw_profile,
    _find_all_devices_for_hardware,
    _find_matching_canonical_hardware_id,
    _normalize_gpu_core,
    _resolve_os_family,
    compute_canonical_hardware_id,
    extract_android_model_from_ua,
    get_device_hardware_id,
)
from api_v1.services.device_security.web import (
    _extract_web_or_device_id_from_request,
    _has_desktop_or_emulated_gpu,
    build_web_device_info,
    detect_web_fingerprint_spoofing,
    get_or_create_web_installation_id,
    is_web_client_request,
    parse_web_user_agent,
)
from api_v1.services.device_security.events import (
    prune_expired_telemetry,
    record_device_activity,
    record_security_event,
)
from api_v1.services.device_security.blocks import (
    _filter_active_non_expired_block,
    block_device_admin,
    get_active_device_block,
    unblock_device_admin,
)
from api_v1.services.device_security.risk import (
    _verify_app_identity_signals,
    detect_account_sharing,
    evaluate_and_apply_risk,
)
from api_v1.selectors.device_selectors import (
    _platform_tag_for_device,
    build_unified_devices_registry,
    get_user_device_limit,
)
from api_v1.services.device_security.registration import (
    check_device_allowed,
    register_or_update_device,
    revoke_user_device,
    serialize_device_summary,
)
from api_v1.services.device_security.web_playback import (
    check_web_ios_only_lecture_access,
    enforce_web_lecture_playback,
    verify_web_device_live_consistency,
)
from api_v1.services.device_security.boot_gate import (
    evaluate_boot_security_gate,
    is_maintenance_admin_approved_device,
)

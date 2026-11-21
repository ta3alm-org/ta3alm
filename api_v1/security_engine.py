"""
Compatibility facade for api_v1.security_engine.
"""
from __future__ import annotations

import hashlib
import hmac
import time
from datetime import timedelta
from typing import Any
from django.conf import settings
from django.core.cache import cache
from django.db import transaction
from django.db.models import Q
from django.utils import timezone
from rest_framework.authtoken.models import Token
from dashboard_admin.models import AuditLog
from api_v1.device_security_service import (
    block_device_admin,
    extract_network_context,
    record_device_activity,
    record_security_event,
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

from api_v1.services.security_engine.constants import (
    MIN_SIGNED_NATIVE_BUILD,
    _HIGH_VALUE_SIGNAL_TAGS,
    _MASK_SEQ,
    _SHARD_A,
    _SHARD_B,
    _SHARD_C,
    _SHARD_D,
)
from api_v1.services.security_engine.request_signing import (
    _derive_client_signing_key,
    _empty_body_sha256,
    _extract_raw_body_sha256,
    verify_client_request_signature,
)
from api_v1.services.security_engine.behavioral import (
    compute_behavioral_risk,
    is_protected_admin_user,
    record_behavioral_activity,
    serialize_user_security_profile,
)
from api_v1.services.security_engine.enforcement import (
    enforce_security_ban,
    unban_user_and_devices,
)
from api_v1.selectors.security_selectors import collect_user_today_telemetry
from api_v1.services.security_engine.ai_audit import (
    _call_ai_security_llm,
    _derive_heuristic_action,
    _extract_json_object,
    _mask_secret,
    _pick_riskiest_installation_id,
    analyze_user_with_ai,
    get_effective_ai_config,
    maybe_trigger_hourly_ai_audit_async,
    run_hourly_ai_behavioral_audit,
)

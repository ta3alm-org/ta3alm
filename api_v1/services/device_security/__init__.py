"""
api_v1/services/device_security package.
"""
from __future__ import annotations

from .constants import (
    FINGERPRINT_ALGORITHM_VERSION,
    MAX_IP_HISTORY_ENTRIES,
    WEB_PACKAGE_NAME,
    WEB_COOKIE_NAME,
    WEB_COOKIE_SALT,
    CORE_FINGERPRINT_FIELDS,
    SUPPORTING_FINGERPRINT_FIELDS,
    BENIGN_DRIFT_FIELDS,
    WEB_STRICT_CORE_FIELDS,
    _VPN_ISP_KEYWORDS,
    _DESKTOP_OR_EMULATED_GPU_TOKENS,
    _BROWSER_UA_MARKERS,
    WEB_IOS_ONLY_ERROR,
)
from .fingerprint import (
    _fingerprint_secret,
    validate_installation_id,
    normalize_device_info,
    generate_versioned_fingerprint,
)
from .network import (
    get_server_observed_ip,
    extract_network_context,
    analyze_ip_transition,
)
from .hardware import (
    _clean_hw_token,
    _normalize_gpu_core,
    extract_android_model_from_ua,
    _resolve_os_family,
    _extract_device_hw_profile,
    _find_matching_canonical_hardware_id,
    compute_canonical_hardware_id,
    get_device_hardware_id,
    _find_all_devices_for_hardware,
)
from .web import (
    parse_web_user_agent,
    _has_desktop_or_emulated_gpu,
    is_web_client_request,
    _extract_web_or_device_id_from_request,
    detect_web_fingerprint_spoofing,
    build_web_device_info,
    get_or_create_web_installation_id,
)
from .events import (
    record_device_activity,
    record_security_event,
    prune_expired_telemetry,
)
from .blocks import (
    _filter_active_non_expired_block,
    get_active_device_block,
    block_device_admin,
    unblock_device_admin,
)
from .risk import (
    _verify_app_identity_signals,
    evaluate_and_apply_risk,
    detect_account_sharing,
)
from .registration import (
    serialize_device_summary,
    register_or_update_device,
    check_device_allowed,
    revoke_user_device,
)
from .web_playback import (
    check_web_ios_only_lecture_access,
    verify_web_device_live_consistency,
    enforce_web_lecture_playback,
)
from .boot_gate import (
    is_maintenance_admin_approved_device,
    evaluate_boot_security_gate,
)

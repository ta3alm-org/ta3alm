"""
api_v1/services/security_engine package.
"""
from __future__ import annotations

from .constants import (
    _SHARD_A,
    _SHARD_B,
    _SHARD_C,
    _SHARD_D,
    _MASK_SEQ,
    MIN_SIGNED_NATIVE_BUILD,
    _HIGH_VALUE_SIGNAL_TAGS,
)
from .request_signing import (
    _derive_client_signing_key,
    _empty_body_sha256,
    _extract_raw_body_sha256,
    verify_client_request_signature,
)
from .behavioral import (
    is_protected_admin_user,
    compute_behavioral_risk,
    record_behavioral_activity,
    serialize_user_security_profile,
)
from .enforcement import (
    enforce_security_ban,
    unban_user_and_devices,
)
from .ai_audit import (
    _mask_secret,
    get_effective_ai_config,
    _extract_json_object,
    _call_ai_security_llm,
    analyze_user_with_ai,
    _pick_riskiest_installation_id,
    _derive_heuristic_action,
    run_hourly_ai_behavioral_audit,
    maybe_trigger_hourly_ai_audit_async,
)

"""
api_v1/services/video_security package.
"""
from __future__ import annotations

from .constants import (
    PLAYBACK_TOKEN_TTL_SECONDS,
    HEARTBEAT_INTERVAL_SECONDS,
    MAX_CONCURRENT_SESSIONS,
    ANOMALY_WINDOW_SECONDS,
    ANOMALY_AUTH_THRESHOLD,
    VIEW_WINDOW_MINUTES,
)
from .watch_window import (
    watch_window_cache_key,
    get_active_watch_window_expiry,
    has_active_watch_window,
    grant_watch_window,
    clear_watch_window,
)
from .playback import (
    get_client_ip,
    _video_signing_secret,
    issue_playback_token,
    decode_playback_token,
    build_watermark_payload,
    log_security_event,
    detect_and_record_anomaly,
    create_or_rotate_playback_session,
)
from .sealing import (
    _b64url_encode,
    _b64url_decode,
    _derive_seal_key,
    _hmac_keystream,
    seal_video_reference,
    unseal_video_reference,
)
from .cdn_signing import (
    _sign_cloudflare_stream_url,
    _sign_bunny_stream_url,
    _sign_hmac_cdn_url,
    resolve_signed_playback_source,
)

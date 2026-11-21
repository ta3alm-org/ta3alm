"""
Compatibility facade for api_v1.video_security.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import time
import urllib.parse
import uuid
from datetime import datetime, timedelta, timezone as dt_timezone
from typing import Any
import jwt
from django.conf import settings
from django.core.cache import cache
from django.db import transaction
from django.utils import timezone
from api_v1.models import (
    PlaybackSession,
    VideoAsset,
    VideoSecurityAuditLog,
)

from api_v1.services.video_security.constants import (
    ANOMALY_AUTH_THRESHOLD,
    ANOMALY_WINDOW_SECONDS,
    HEARTBEAT_INTERVAL_SECONDS,
    MAX_CONCURRENT_SESSIONS,
    PLAYBACK_TOKEN_TTL_SECONDS,
    VIEW_WINDOW_MINUTES,
)
from api_v1.services.video_security.watch_window import (
    clear_watch_window,
    get_active_watch_window_expiry,
    grant_watch_window,
    has_active_watch_window,
    watch_window_cache_key,
)
from api_v1.services.video_security.playback import (
    _video_signing_secret,
    build_watermark_payload,
    create_or_rotate_playback_session,
    decode_playback_token,
    detect_and_record_anomaly,
    get_client_ip,
    issue_playback_token,
    log_security_event,
)
from api_v1.services.video_security.sealing import (
    _b64url_decode,
    _b64url_encode,
    _derive_seal_key,
    _hmac_keystream,
    seal_video_reference,
    unseal_video_reference,
)
from api_v1.services.video_security.cdn_signing import (
    _sign_bunny_stream_url,
    _sign_cloudflare_stream_url,
    _sign_hmac_cdn_url,
    resolve_signed_playback_source,
)

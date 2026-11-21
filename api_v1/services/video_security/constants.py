"""api_v1.services.video_security.constants
Extracted from api_v1/video_security.py.
"""
from __future__ import annotations

import os


PLAYBACK_TOKEN_TTL_SECONDS = int(os.environ.get('VIDEO_PLAYBACK_TOKEN_TTL', '180'))


HEARTBEAT_INTERVAL_SECONDS = int(os.environ.get('VIDEO_HEARTBEAT_INTERVAL', '25'))


MAX_CONCURRENT_SESSIONS = int(os.environ.get('VIDEO_MAX_CONCURRENT_SESSIONS', '1'))


ANOMALY_WINDOW_SECONDS = 300


ANOMALY_AUTH_THRESHOLD = int(os.environ.get('VIDEO_ANOMALY_THRESHOLD', '25'))


VIEW_WINDOW_MINUTES = int(os.environ.get('VIDEO_VIEW_WINDOW_MINUTES', '20'))

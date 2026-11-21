"""api_v1.views.video.throttles
Extracted from api_v1/views_video.py.
"""
from __future__ import annotations

from rest_framework.throttling import UserRateThrottle


class VideoAuthorizeThrottle(UserRateThrottle):
    rate = '30/min'


class VideoHeartbeatThrottle(UserRateThrottle):
    rate = '120/min'


class IntegrityCheckThrottle(UserRateThrottle):
    rate = '30/min'


class VideoProgressThrottle(UserRateThrottle):
    rate = '60/min'

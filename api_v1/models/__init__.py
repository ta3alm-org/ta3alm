"""
api_v1/models package (preserving all model registrations and imports).
"""

import uuid
from django.conf import settings
from django.db import models
from django.utils import timezone

from api_v1.models.video import (
    PlaybackSession,
    VideoAsset,
    VideoBookmark,
    VideoProgress,
)
from api_v1.models.integrity import (
    DeviceIntegrityRecord,
    PlayIntegrityNonce,
    VideoSecurityAuditLog,
)
from api_v1.models.devices import (
    DeviceActivity,
    DeviceBlock,
    DeviceFingerprint,
    DeviceSecurityEvent,
    DeviceSession,
    DeviceTrustStatus,
    RegisteredDevice,
)
from api_v1.models.policy import (
    SecurityPolicyConfig,
    UserSecurityProfile,
)

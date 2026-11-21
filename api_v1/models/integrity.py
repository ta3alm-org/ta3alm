"""api_v1.models.integrity
Extracted from api_v1/models.py.
"""

import uuid
from django.conf import settings
from django.db import models


class PlayIntegrityNonce(models.Model):
    nonce_id = models.UUIDField(default=uuid.uuid4, unique=True, editable=False)
    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        null=True,
        blank=True,
        related_name='integrity_nonces',
    )
    action = models.CharField(max_length=64, default='app_startup')
    binding_data = models.CharField(max_length=255, blank=True)
    expected_request_hash = models.CharField(max_length=128, blank=True)
    is_used = models.BooleanField(default=False)
    expires_at = models.DateTimeField()
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"PlayIntegrityNonce({self.nonce_id}, action={self.action}, used={self.is_used})"


class DeviceIntegrityRecord(models.Model):
    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name='integrity_records',
    )
    device_id = models.CharField(max_length=128, db_index=True)
    package_name = models.CharField(max_length=128, blank=True)
    app_recognition_verdict = models.CharField(max_length=64, blank=True)
    device_recognition_verdict = models.JSONField(default=list, blank=True)
    licensing_verdict = models.CharField(max_length=64, blank=True)
    risk_level = models.CharField(max_length=16, default='low')
    policy_decision = models.CharField(max_length=32, default='allow')
    tamper_signals = models.JSONField(default=dict, blank=True)
    ip_address = models.GenericIPAddressField(null=True, blank=True)
    verified_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ['-verified_at']

    def __str__(self):
        return f"DeviceIntegrity({self.device_id}, {self.risk_level}, {self.policy_decision})"


class VideoSecurityAuditLog(models.Model):
    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name='video_security_logs',
    )
    lecture = models.ForeignKey(
        'teachers.Lecture',
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name='security_logs',
    )
    session_id = models.CharField(max_length=64, blank=True)
    event_type = models.CharField(max_length=64, db_index=True)
    severity = models.CharField(max_length=16, default='info')
    ip_address = models.GenericIPAddressField(null=True, blank=True)
    device_id = models.CharField(max_length=128, blank=True)
    details = models.JSONField(default=dict, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ['-created_at']

    def __str__(self):
        return f"AuditLog({self.event_type}, severity={self.severity}, user={self.user_id})"

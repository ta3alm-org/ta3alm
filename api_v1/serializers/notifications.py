"""api_v1.serializers.notifications
Extracted from api_v1/serializers.py.
"""

from rest_framework import serializers
from core.models import (
    Notification,
    FCMDeviceToken,
)


class NotificationSerializer(serializers.ModelSerializer):
    class Meta:
        model = Notification
        fields = ['id', 'title', 'message', 'link', 'is_read', 'created_at']


class FCMDeviceTokenSerializer(serializers.Serializer):
    token = serializers.CharField(max_length=512, min_length=20, trim_whitespace=True)
    installation_id = serializers.CharField(max_length=128, required=False, allow_blank=True, default='')
    platform = serializers.ChoiceField(
        choices=[c[0] for c in FCMDeviceToken.PLATFORM_CHOICES],
        required=False,
        default='android',
    )
    app_version = serializers.CharField(max_length=32, required=False, allow_blank=True, default='')

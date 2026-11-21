"""api_v1.serializers.staff
Extracted from api_v1/serializers.py.
"""

from rest_framework import serializers
from assistants.models import AssistantJob
from dashboard_admin.models import (
    AdminProfile,
    AuditLog,
)

from api_v1.serializers.accounts import UserPublicSerializer
from api_v1.serializers.catalog import TeacherCardSerializer


class AssistantJobSerializer(serializers.ModelSerializer):
    assistant_id = serializers.IntegerField(source='assistant.id', read_only=True)
    assistant_name = serializers.SerializerMethodField()
    assistant_phone = serializers.CharField(source='assistant.phone', read_only=True)
    assistant_custom_id = serializers.CharField(source='assistant.user.custom_id', read_only=True)
    teacher = TeacherCardSerializer(read_only=True)

    class Meta:
        model = AssistantJob
        fields = [
            'id', 'assistant_id', 'assistant_name', 'assistant_phone', 'assistant_custom_id',
            'teacher', 'is_active', 'joined_at',
            'can_manage_students', 'can_manage_exams',
            'can_manage_videos', 'can_manage_packages',
        ]

    def get_assistant_name(self, obj):
        u = obj.assistant.user
        return f"{u.first_name} {u.last_name}".strip() or u.username


class AdminProfileSerializer(serializers.ModelSerializer):
    user = UserPublicSerializer(read_only=True)
    admin_role_display = serializers.CharField(source='get_admin_role_display', read_only=True)
    appointed_by_name = serializers.SerializerMethodField()

    class Meta:
        model = AdminProfile
        fields = [
            'id', 'user', 'admin_role', 'admin_role_display',
            'is_active_admin', 'notes', 'appointed_by_name', 'appointed_at',
        ]

    def get_appointed_by_name(self, obj):
        if obj.appointed_by:
            return f"{obj.appointed_by.first_name} {obj.appointed_by.last_name}".strip() or obj.appointed_by.username
        return '-'


class AuditLogSerializer(serializers.ModelSerializer):
    admin_name = serializers.SerializerMethodField()
    action_display = serializers.CharField(source='get_action_display', read_only=True)

    class Meta:
        model = AuditLog
        fields = [
            'id', 'admin', 'admin_name', 'action', 'action_display',
            'target_label', 'target_id', 'details', 'ip_address', 'created_at',
        ]

    def get_admin_name(self, obj):
        if obj.admin:
            return f"{obj.admin.first_name} {obj.admin.last_name}".strip() or obj.admin.username
        return 'محذوف'

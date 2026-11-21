"""api_v1.serializers.catalog
Extracted from api_v1/serializers.py.
"""

from rest_framework import serializers
from teachers.models import (
    SubscriptionPlan,
    TeacherProfile,
)
from core.models import Subject


class SubjectSerializer(serializers.ModelSerializer):
    class Meta:
        model = Subject
        fields = ['id', 'name']


class SubscriptionPlanSerializer(serializers.ModelSerializer):
    class Meta:
        model = SubscriptionPlan
        fields = [
            'id', 'name', 'price', 'description',
            'student_limit', 'group_limit', 'assistant_limit',
            'allow_online_packages', 'allow_question_images', 'is_default',
        ]


class TeacherCardSerializer(serializers.ModelSerializer):
    first_name = serializers.CharField(source='user.first_name', read_only=True)
    last_name = serializers.CharField(source='user.last_name', read_only=True)
    full_name = serializers.SerializerMethodField()
    phone = serializers.CharField(source='user.phone', read_only=True)
    custom_id = serializers.CharField(source='user.custom_id', read_only=True)
    subject_name = serializers.CharField(source='subject.name', default='', read_only=True)
    image_url = serializers.SerializerMethodField()
    has_active_subscription = serializers.SerializerMethodField()

    class Meta:
        model = TeacherProfile
        fields = [
            'id', 'first_name', 'last_name', 'full_name', 'phone', 'custom_id',
            'bio', 'subject', 'subject_name', 'image', 'image_url',
            'is_approved', 'approved_at', 'has_active_subscription',
        ]

    def get_full_name(self, obj):
        return f"{obj.user.first_name} {obj.user.last_name}".strip() or obj.user.username

    def get_image_url(self, obj):
        if not obj.image:
            return None
        request = self.context.get('request')
        try:
            return request.build_absolute_uri(obj.image.url) if request else obj.image.url
        except Exception:
            return str(obj.image)

    def get_has_active_subscription(self, obj):
        return obj.has_active_subscription()

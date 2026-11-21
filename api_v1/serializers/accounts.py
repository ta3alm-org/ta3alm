"""api_v1.serializers.accounts
Extracted from api_v1/serializers.py.
"""

from django.contrib.auth import get_user_model
from rest_framework import serializers

from api_v1.serializers.catalog import SubscriptionPlanSerializer

User = get_user_model()


class UserPublicSerializer(serializers.ModelSerializer):
    full_name = serializers.SerializerMethodField()
    role_display = serializers.CharField(source='get_role_display', read_only=True)

    class Meta:
        model = User
        fields = [
            'id', 'username', 'first_name', 'last_name', 'full_name',
            'email', 'phone', 'custom_id', 'role', 'role_display',
        ]

    def get_full_name(self, obj):
        return f"{obj.first_name} {obj.last_name}".strip() or obj.username


class UserDetailSerializer(serializers.ModelSerializer):
    full_name = serializers.SerializerMethodField()
    role_display = serializers.CharField(source='get_role_display', read_only=True)
    is_profile_complete = serializers.SerializerMethodField()
    is_email_verified = serializers.SerializerMethodField()
    requires_verification = serializers.SerializerMethodField()
    is_teacher_approved = serializers.SerializerMethodField()
    profile_data = serializers.SerializerMethodField()

    class Meta:
        model = User
        fields = [
            'id', 'username', 'first_name', 'last_name', 'full_name',
            'email', 'phone', 'national_id', 'custom_id',
            'role', 'role_display', 'is_banned', 'is_superuser',
            'is_email_verified', 'requires_verification',
            'is_profile_complete', 'is_teacher_approved', 'profile_data', 'date_joined',
        ]
        read_only_fields = ['id', 'username', 'custom_id', 'role', 'is_banned', 'is_superuser', 'date_joined']

    def get_is_teacher_approved(self, obj):
        if obj.role != 'teacher':
            return True
        tp = getattr(obj, 'teacher_profile', None)
        return bool(tp and getattr(tp, 'is_approved', False))

    def get_full_name(self, obj):
        return f"{obj.first_name} {obj.last_name}".strip() or obj.username

    def get_is_email_verified(self, obj):
        if hasattr(obj, 'requires_email_verification'):
            return not obj.requires_email_verification()
        return True

    def get_requires_verification(self, obj):
        if hasattr(obj, 'requires_email_verification'):
            return obj.requires_email_verification()
        return False

    def get_is_profile_complete(self, obj):
        if obj.is_superuser or obj.role == 'admin':
            return True
        if not obj.custom_id:
            return False
        if obj.role == 'student':
            return hasattr(obj, 'student_profile') and bool(obj.student_profile.parent_phone)
        if obj.role == 'teacher':
            return hasattr(obj, 'teacher_profile') and bool(obj.teacher_profile.subject_id)
        if obj.role == 'assistant':
            return hasattr(obj, 'assistant_profile') and bool(obj.assistant_profile.phone)
        return True

    def get_profile_data(self, obj):
        request = self.context.get('request')
        if obj.role == 'student' and hasattr(obj, 'student_profile'):
            sp = obj.student_profile
            return {
                'student_profile_id': sp.id,
                'parent_phone': sp.parent_phone,
            }
        if obj.role == 'teacher' and hasattr(obj, 'teacher_profile'):
            tp = obj.teacher_profile
            img_url = None
            if tp.image:
                try:
                    img_url = request.build_absolute_uri(tp.image.url) if request else tp.image.url
                except Exception:
                    img_url = str(tp.image)
            return {
                'teacher_profile_id': tp.id,
                'bio': tp.bio,
                'subject_id': tp.subject_id,
                'subject_name': tp.subject.name if tp.subject else '',
                'image': img_url,
                'image_url': img_url,
                'is_approved': bool(tp.is_approved),
                'approved_at': tp.approved_at.isoformat() if tp.approved_at else None,
                'has_active_subscription': tp.has_active_subscription(),
                'days_remaining': tp.days_remaining(),
                'subscription_end_date': tp.subscription_end_date,
                'current_plan': SubscriptionPlanSerializer(tp.current_plan).data if tp.current_plan else None,
            }
        if obj.role == 'assistant' and hasattr(obj, 'assistant_profile'):
            ap = obj.assistant_profile
            return {
                'assistant_profile_id': ap.id,
                'phone': ap.phone,
            }
        if (obj.is_superuser or obj.role == 'admin'):
            ap = getattr(obj, 'admin_profile', None)
            return {
                'admin_role': ap.admin_role if ap else 'owner',
                'is_owner': obj.is_superuser or (ap.is_owner if ap else False),
                'can_manage_users': obj.is_superuser or (ap.can_manage_users if ap else False),
                'can_delete_users': obj.is_superuser or (ap.can_delete_users if ap else False),
                'can_view_finance': obj.is_superuser or (ap.can_view_finance if ap else False),
                'can_manage_plans': obj.is_superuser or (ap.can_manage_plans if ap else False),
                'can_view_audit_log': obj.is_superuser or (ap.can_view_audit_log if ap else False),
            }
        return {}

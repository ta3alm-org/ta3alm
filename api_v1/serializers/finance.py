"""api_v1.serializers.finance
Extracted from api_v1/serializers.py.
"""

from rest_framework import serializers
from teachers.models import (
    Wallet,
    WithdrawRequest,
)
from core.models import ManualPayment


class WalletSerializer(serializers.ModelSerializer):
    class Meta:
        model = Wallet
        fields = ['id', 'balance', 'total_earnings']


class WithdrawRequestSerializer(serializers.ModelSerializer):
    method_display = serializers.CharField(source='get_method_display', read_only=True)
    status_display = serializers.CharField(source='get_status_display', read_only=True)
    teacher_name = serializers.SerializerMethodField()
    teacher_phone = serializers.CharField(source='wallet.teacher.user.phone', read_only=True)

    class Meta:
        model = WithdrawRequest
        fields = [
            'id', 'amount', 'method', 'method_display',
            'details', 'status', 'status_display', 'is_paid',
            'rejection_reason', 'reviewed_at',
            'teacher_name', 'teacher_phone', 'created_at',
        ]
        read_only_fields = [
            'id', 'status', 'status_display', 'is_paid',
            'rejection_reason', 'reviewed_at', 'created_at',
        ]

    def get_teacher_name(self, obj):
        u = obj.wallet.teacher.user
        return f"{u.first_name} {u.last_name}".strip() or u.username


class ManualPaymentSerializer(serializers.ModelSerializer):
    user_name = serializers.SerializerMethodField()
    user_phone = serializers.CharField(source='user.phone', read_only=True)
    status_display = serializers.CharField(source='get_status_display', read_only=True)
    payment_type_display = serializers.CharField(source='get_payment_type_display', read_only=True)
    receipt_image_url = serializers.SerializerMethodField()

    class Meta:
        model = ManualPayment
        fields = [
            'id', 'user', 'user_name', 'user_phone',
            'amount', 'payment_type', 'payment_type_display',
            'status', 'status_display', 'target_id',
            'phone_number', 'receipt_image', 'receipt_image_url', 'created_at',
        ]
        read_only_fields = ['id', 'user', 'status', 'created_at']

    def get_user_name(self, obj):
        return f"{obj.user.first_name} {obj.user.last_name}".strip() or obj.user.username

    def get_receipt_image_url(self, obj):
        if not obj.receipt_image:
            return None
        request = self.context.get('request')
        try:
            return request.build_absolute_uri(obj.receipt_image.url) if request else obj.receipt_image.url
        except Exception:
            return str(obj.receipt_image)

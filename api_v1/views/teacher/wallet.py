"""api_v1.views.teacher.wallet
Extracted from api_v1/views_teacher.py.
"""

from decimal import Decimal
from django.db import transaction
from rest_framework import status
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView
from core.models import (
    SiteSetting,
    reconcile_teacher_wallet,
)
from teachers.models import (
    Wallet,
    WithdrawRequest,
)
from api_v1.permissions import IsTeacherRole
from api_v1.serializers import (
    WalletSerializer,
    WithdrawRequestSerializer,
)


class TeacherWalletAPIView(APIView):
    """محفظة المعلم وطلبات سحب الأرباح."""
    permission_classes = [IsAuthenticated, IsTeacherRole]

    def get(self, request):
        teacher = request.user.teacher_profile
        wallet = reconcile_teacher_wallet(teacher) or Wallet.objects.get_or_create(teacher=teacher)[0]
        site_setting = SiteSetting.load()
        withdraws = wallet.withdrawals.all().order_by('-created_at')
        return Response({
            'wallet': WalletSerializer(wallet).data,
            'platform_commission_percentage': site_setting.platform_commission_percentage,
            'withdrawals': WithdrawRequestSerializer(withdraws, many=True).data,
        })

    @transaction.atomic
    def post(self, request):
        teacher = request.user.teacher_profile
        wallet, _ = Wallet.objects.select_for_update().get_or_create(teacher=teacher)

        try:
            amount = Decimal(str(request.data.get('amount', '0')))
        except Exception:
            return Response({'error': 'يرجى إدخال مبلغ صحيح.'}, status=status.HTTP_400_BAD_REQUEST)

        method = str(request.data.get('method', 'vodafone')).strip()
        details = str(request.data.get('details', '')).strip()

        if amount > wallet.balance:
            return Response({'error': 'رصيدك الحالي لا يكفي.'}, status=status.HTTP_400_BAD_REQUEST)
        if amount < Decimal('50'):
            return Response({'error': 'الحد الأدنى للسحب 50 جنيه.'}, status=status.HTTP_400_BAD_REQUEST)
        if not details:
            return Response({'error': 'يرجى إدخال رقم المحفظة أو بيانات التحويل.'}, status=status.HTTP_400_BAD_REQUEST)

        wallet.balance -= amount
        wallet.save(update_fields=['balance'])

        req = WithdrawRequest.objects.create(
            wallet=wallet,
            amount=amount,
            method=method,
            details=details,
        )
        return Response({
            'message': 'تم إرسال طلب السحب بنجاح.',
            'wallet': WalletSerializer(wallet).data,
            'withdrawal': WithdrawRequestSerializer(req).data,
        }, status=status.HTTP_201_CREATED)

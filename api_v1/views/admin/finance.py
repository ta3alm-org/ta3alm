"""api_v1.views.admin.finance
Extracted from api_v1/views_admin.py.
"""

from django.db import transaction
from django.db.models import Sum
from django.shortcuts import get_object_or_404
from django.utils import timezone
from rest_framework import status
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView
from decimal import (
    Decimal,
    ROUND_HALF_UP,
)
from core.models import (
    SiteSetting,
    ManualPayment,
    reconcile_teacher_wallet,
)
from dashboard_admin.models import AuditLog
from students.models import PackageEnrollment
from teachers.models import (
    TeacherProfile,
    PaymentTransaction,
    WithdrawRequest,
)
from api_v1.permissions import IsPlatformFinance
from api_v1.serializers import (
    WithdrawRequestSerializer,
    ManualPaymentSerializer,
    PackageEnrollmentSerializer,
)


class AdminFinanceAPIView(APIView):
    """التقارير المالية، طلبات السحب، مبيعات الحزم، وطلبات الدفع اليدوي."""
    permission_classes = [IsAuthenticated, IsPlatformFinance]

    def get(self, request):
        site_settings = SiteSetting.load()
        teacher_ids = PackageEnrollment.objects.filter(is_paid=True).values_list('package__teacher_id', flat=True).distinct()
        for t in TeacherProfile.objects.filter(id__in=teacher_ids):
            reconcile_teacher_wallet(t)

        transactions = PaymentTransaction.objects.select_related('teacher__user').order_by('-date')[:100]
        total_sub_revenue = PaymentTransaction.objects.aggregate(t=Sum('amount'))['t'] or 0
        total_pkg_revenue = PackageEnrollment.objects.filter(is_paid=True).aggregate(t=Sum('package__price'))['t'] or 0
        gross_pkg = Decimal(str(total_pkg_revenue or 0))
        commission_pct = int(site_settings.platform_commission_percentage or 0)
        platform_commission_revenue = float(
            (gross_pkg * Decimal(commission_pct) / Decimal('100')).quantize(
                Decimal('0.01'), rounding=ROUND_HALF_UP
            )
        )
        teachers_net_revenue = float(
            (gross_pkg - Decimal(str(platform_commission_revenue))).quantize(
                Decimal('0.01'), rounding=ROUND_HALF_UP
            )
        )
        withdraw_requests = WithdrawRequest.objects.select_related('wallet__teacher__user').order_by('-created_at')
        manual_payments = ManualPayment.objects.select_related('user').order_by('-created_at')
        student_payments = (
            PackageEnrollment.objects
            .filter(is_paid=True)
            .select_related('student__user', 'package__teacher__user', 'package__teacher__subject')
            .order_by('-joined_at')[:100]
        )

        return Response({
            'total_subscription_revenue': total_sub_revenue,
            'total_package_revenue': total_pkg_revenue,
            'platform_commission_percentage': commission_pct,
            'platform_commission_revenue': platform_commission_revenue,
            'teachers_net_revenue': teachers_net_revenue,
            'withdraw_requests': WithdrawRequestSerializer(withdraw_requests, many=True).data,
            'manual_payments': ManualPaymentSerializer(manual_payments, many=True, context={'request': request}).data,
            'student_payments': PackageEnrollmentSerializer(student_payments, many=True, context={'request': request}).data,
            'transactions': [
                {
                    'id': tr.id,
                    'teacher_name': f"{tr.teacher.user.first_name} {tr.teacher.user.last_name}".strip(),
                    'amount': tr.amount,
                    'date': tr.date,
                    'transaction_id': tr.transaction_id,
                }
                for tr in transactions
            ],
        })

    def post(self, request):
        """تسديد/رفض طلب سحب، قبول/رفض طلب دفع يدوي، أو تحديث نسبة عمولة المنصة."""
        item_type = request.data.get('item_type')  # 'withdrawal' | 'manual_payment' | 'commission'
        action = request.data.get('action')
        if item_type == 'commission' or action == 'update_commission':
            raw_commission = request.data.get('platform_commission_percentage')
            try:
                commission = int(raw_commission)
            except (TypeError, ValueError):
                return Response({'error': 'يرجى إدخال نسبة عمولة صحيحة بين 0 و 100.'}, status=status.HTTP_400_BAD_REQUEST)
            if commission < 0 or commission > 100:
                return Response({'error': 'يجب أن تكون نسبة العمولة بين 0 و 100%.'}, status=status.HTTP_400_BAD_REQUEST)
            site_settings = SiteSetting.load()
            site_settings.platform_commission_percentage = commission
            site_settings.save()
            AuditLog.log(
                request,
                AuditLog.ACTION_EDIT_USER,
                target_label='نسبة عمولة المنصة',
                details={'platform_commission_percentage': commission},
            )
            return Response({
                'message': f'تم تحديث نسبة عمولة المنصة إلى {commission}% بنجاح.',
                'platform_commission_percentage': site_settings.platform_commission_percentage,
            })

        if item_type == 'withdrawal' or action in ('pay_withdrawal', 'reject_withdrawal'):
            from decimal import Decimal
            from teachers.models import Wallet

            withdrawal_id = request.data.get('id') or request.data.get('withdrawal_id')
            req_action = str(action or 'approve').strip().lower()
            reason = str(request.data.get('reason') or request.data.get('rejection_reason') or '').strip()

            with transaction.atomic():
                req = get_object_or_404(WithdrawRequest.objects.select_for_update(), id=withdrawal_id)
                if req.status != WithdrawRequest.STATUS_PENDING:
                    return Response(
                        {'error': 'تمت معالجة طلب السحب هذا مسبقاً.'},
                        status=status.HTTP_400_BAD_REQUEST,
                    )

                if req_action in ('reject', 'reject_withdrawal'):
                    wallet = Wallet.objects.select_for_update().get(pk=req.wallet_id)
                    wallet.balance = (wallet.balance or Decimal('0.00')) + req.amount
                    wallet.save(update_fields=['balance'])
                    req.status = WithdrawRequest.STATUS_REJECTED
                    req.is_paid = False
                    req.rejection_reason = reason
                    req.reviewed_at = timezone.now()
                    req.save(update_fields=['status', 'is_paid', 'rejection_reason', 'reviewed_at'])
                    AuditLog.log(
                        request,
                        AuditLog.ACTION_REJECT_WITHDRAW,
                        target_label=f"{req} (مرفوض)",
                        target_id=req.id,
                    )
                    return Response({
                        'message': f'تم رفض طلب السحب وإعادة {req.amount} EGP إلى محفظة المعلم.',
                        'withdrawal': WithdrawRequestSerializer(req).data,
                    })

                req.status = WithdrawRequest.STATUS_PAID
                req.is_paid = True
                req.reviewed_at = timezone.now()
                req.save(update_fields=['status', 'is_paid', 'reviewed_at'])
                AuditLog.log(request, AuditLog.ACTION_PAY_WITHDRAW, target_label=str(req), target_id=req.id)
                return Response({
                    'message': f'تم تسجيل تحويل {req.amount} EGP.',
                    'withdrawal': WithdrawRequestSerializer(req).data,
                })

        if item_type == 'manual_payment':
            payment = get_object_or_404(ManualPayment, id=request.data.get('id'))
            if action == 'approve':
                payment.status = 'approved'
                payment.save()
                AuditLog.log(request, AuditLog.ACTION_EDIT_USER, target_label=f'دفع يدوي {payment.id}', target_id=payment.id)
                return Response({'message': 'تم قبول طلب الدفع وتفعيل الاشتراك/الحزمة.'})
            if action == 'reject':
                payment.status = 'rejected'
                payment.save()
                return Response({'message': 'تم رفض طلب الدفع.'})

        return Response({'error': 'إجراء غير صالح.'}, status=status.HTTP_400_BAD_REQUEST)

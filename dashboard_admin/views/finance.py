"""dashboard_admin.views.finance
Extracted from dashboard_admin/views.py.
"""

from django.shortcuts import (
    render,
    redirect,
    get_object_or_404,
)
from django.contrib import messages
from django.db.models import (
    Sum,
    Q,
)
from django.utils import timezone
from teachers.models import (
    PaymentTransaction,
    WithdrawRequest,
)
from students.models import PackageEnrollment
from dashboard_admin.models import AuditLog
from dashboard_admin.decorators import finance_required

from dashboard_admin.views.base import _base_context


# ==========================================================
# 6. التقارير المالية
# ==========================================================
@finance_required
def finance_report(request):
    ctx = _base_context(request)

    query = request.GET.get('q', '').strip()
    transactions = PaymentTransaction.objects.select_related('teacher__user').order_by('-date')

    if query:
        transactions = transactions.filter(
            Q(teacher__user__first_name__icontains=query) |
            Q(teacher__user__phone__icontains=query)       |
            Q(transaction_id__icontains=query)
        )

    total_revenue = transactions.aggregate(total=Sum('amount'))['total'] or 0

    ctx.update({
        'transactions': transactions,
        'total_revenue': total_revenue,
        'query': query,
    })
    return render(request, 'admin_panel/finance_report.html', ctx)


# ==========================================================
# 7. طلبات السحب
# ==========================================================
@finance_required
def withdrawals(request):
    from decimal import Decimal
    from django.db import transaction
    from teachers.models import Wallet

    ctx = _base_context(request)

    withdraw_requests = WithdrawRequest.objects.select_related(
        'wallet__teacher__user'
    ).order_by('-created_at')

    if request.method == 'POST':
        req_id = request.POST.get('req_id')
        req_action = (request.POST.get('action') or 'approve').strip().lower()
        reason = (request.POST.get('rejection_reason') or '').strip()

        with transaction.atomic():
            req = get_object_or_404(WithdrawRequest.objects.select_for_update(), id=req_id)
            if req.status != WithdrawRequest.STATUS_PENDING:
                messages.warning(request, "تمت معالجة طلب السحب هذا مسبقاً.")
                return redirect('admin_panel:withdrawals')

            if req_action == 'reject':
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
                    details={'amount': str(req.amount), 'reason': reason},
                )
                messages.info(request, f"تم رفض طلب السحب وإعادة {req.amount} EGP إلى محفظة المعلم.")
            else:
                req.status = WithdrawRequest.STATUS_PAID
                req.is_paid = True
                req.reviewed_at = timezone.now()
                req.save(update_fields=['status', 'is_paid', 'reviewed_at'])
                AuditLog.log(
                    request,
                    AuditLog.ACTION_PAY_WITHDRAW,
                    target_label=str(req),
                    target_id=req.id,
                    details={'amount': str(req.amount)},
                )
                messages.success(request, f"تم تسجيل تحويل {req.amount} EGP.")
        return redirect('admin_panel:withdrawals')

    ctx['requests'] = withdraw_requests
    return render(request, 'admin_panel/withdrawals.html', ctx)


# ==========================================================
# 8. مدفوعات الطلاب على الحزم
# ==========================================================
@finance_required
def student_payments(request):
    ctx = _base_context(request)

    payments = PackageEnrollment.objects.filter(
        is_paid=True
    ).select_related('student__user', 'package__teacher__user').order_by('-joined_at')

    # ✅ إصلاح N+1: aggregate بدلاً من sum في Python
    total_revenue = payments.aggregate(total=Sum('package__price'))['total'] or 0
    commission_pct = int(ctx['site_settings'].platform_commission_percentage or 0)
    platform_commission_revenue = round(float(total_revenue) * commission_pct / 100.0, 2)
    teachers_net_revenue = round(float(total_revenue) - platform_commission_revenue, 2)

    ctx.update({
        'payments': payments,
        'total_revenue': total_revenue,
        'commission_percentage': commission_pct,
        'platform_commission_revenue': platform_commission_revenue,
        'teachers_net_revenue': teachers_net_revenue,
    })
    return render(request, 'admin_panel/student_payments.html', ctx)


# ==========================================================
# 12. طلبات الدفع اليدوي
# ==========================================================
@finance_required
def manual_payments(request):
    from core.models import ManualPayment
    ctx = _base_context(request)

    payments = ManualPayment.objects.select_related('user').order_by('-created_at')

    if request.method == 'POST':
        payment_id = request.POST.get('payment_id')
        action = request.POST.get('action')
        payment = get_object_or_404(ManualPayment, id=payment_id)

        if action == 'approve':
            payment.status = 'approved'
            payment.save()
            AuditLog.log(request, AuditLog.ACTION_EDIT_USER,
                         target_label=f"دفع يدوي {payment.id}",
                         target_id=payment.id,
                         details={'status': 'approved'})
            messages.success(request, "تم قبول طلب الدفع بنجاح وتفعيل الاشتراك/الحزمة.")
        elif action == 'reject':
            payment.status = 'rejected'
            payment.save()
            messages.warning(request, "تم رفض طلب الدفع.")

        return redirect('admin_panel:manual_payments')

    ctx['payments'] = payments
    return render(request, 'admin_panel/manual_payments.html', ctx)

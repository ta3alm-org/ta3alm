"""
core/services/wallet.py
خدمات احتساب أرباح المدرس ومزامنة المحفظة (منقولة من core.models).
"""
from decimal import Decimal, ROUND_HALF_UP
from django.db import transaction


def credit_teacher_wallet_for_sale(teacher, gross_amount):
    """إضافة صافي ربح المدرس لمحفظته بعد خصم نسبة عمولة المنصة."""
    from teachers.models import Wallet

    if teacher is None:
        return Decimal('0.00')

    gross = Decimal(str(gross_amount or 0))
    if gross <= Decimal('0.00'):
        return Decimal('0.00')

    from core.models import SiteSetting
    site_setting = SiteSetting.load()
    net_share = (gross * site_setting.teacher_share_ratio).quantize(
        Decimal('0.01'), rounding=ROUND_HALF_UP
    )

    with transaction.atomic():
        wallet, _ = Wallet.objects.select_for_update().get_or_create(teacher=teacher)
        current_balance = Decimal(str(wallet.balance or 0))
        current_total = Decimal(str(wallet.total_earnings or 0))
        wallet.balance = (current_balance + net_share).quantize(Decimal('0.01'))
        wallet.total_earnings = (current_total + net_share).quantize(Decimal('0.01'))
        wallet.save(update_fields=['balance', 'total_earnings'])

    return net_share


def reconcile_teacher_wallet(teacher):
    """مزامنة محفظة المدرس للاشتراكات المدفوعة غير المحتسبة سابقاً."""
    from django.db.models import Sum
    from students.models import PackageEnrollment
    from teachers.models import Wallet, WithdrawRequest

    if teacher is None:
        return None

    with transaction.atomic():
        wallet, _ = Wallet.objects.select_for_update().get_or_create(teacher=teacher)
        gross_total = Decimal(
            str(
                PackageEnrollment.objects.filter(
                    package__teacher=teacher, is_paid=True
                ).aggregate(total=Sum('package__price'))['total']
                or 0
            )
        )
        if gross_total > Decimal('0.00') and Decimal(str(wallet.total_earnings or 0)) == Decimal('0.00'):
            from core.models import SiteSetting
            site_setting = SiteSetting.load()
            expected_net = (gross_total * site_setting.teacher_share_ratio).quantize(
                Decimal('0.01'), rounding=ROUND_HALF_UP
            )
            withdrawn = Decimal(
                str(
                    wallet.withdrawals.exclude(status=WithdrawRequest.STATUS_REJECTED)
                    .aggregate(total=Sum('amount'))['total']
                    or 0
                )
            ).quantize(Decimal('0.01'))
            wallet.total_earnings = expected_net
            wallet.balance = max(Decimal('0.00'), expected_net - withdrawn)
            wallet.save(update_fields=['balance', 'total_earnings'])
        return wallet

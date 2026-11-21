"""teachers.views.wallet
Extracted from teachers/views.py.
"""

from core.models import (
    SiteSetting,
    reconcile_teacher_wallet,
)
from django.shortcuts import (
    render,
    redirect,
)
from django.contrib.auth.decorators import login_required
from django.contrib import messages
from teachers.models import Wallet
from decimal import (
    Decimal,
    InvalidOperation,
)
from django.db import transaction
from teachers.models import WithdrawRequest


@login_required
def teacher_wallet(request):
    try: teacher = request.user.teacher_profile
    except: return redirect('home')

    if not request.user.phone or len(request.user.phone.strip()) < 11 or not teacher.image:
        messages.warning(
            request,
            "يرجى رفع صورتك الشخصية وإدخال رقم هاتفك المحمول (إجباري لجميع المعلمين) قبل المتابعة في المنصة.",
        )
        return redirect('teacher_settings')
    
    wallet = reconcile_teacher_wallet(teacher) or Wallet.objects.get_or_create(teacher=teacher)[0]
    site_setting = SiteSetting.load()

    if request.method == 'POST':
        try:
            amount = Decimal(str(request.POST.get('amount') or '0').strip())
        except (InvalidOperation, TypeError, ValueError):
            amount = Decimal('0')
        method = (request.POST.get('method') or '').strip()
        details = (request.POST.get('details') or '').strip()

        if amount < Decimal('50'):
            messages.error(request, "الحد الأدنى للسحب 50 جنيه.")
        else:
            with transaction.atomic():
                locked_wallet = Wallet.objects.select_for_update().get(id=wallet.id)
                if amount > locked_wallet.balance:
                    messages.error(request, "رصيدك الحالي لا يكفي.")
                else:
                    locked_wallet.balance = locked_wallet.balance - amount
                    locked_wallet.save(update_fields=['balance'])

                    WithdrawRequest.objects.create(
                        wallet=locked_wallet, amount=amount, method=method, details=details
                    )
                    messages.success(request, "تم إرسال طلب السحب بنجاح.")
                    return redirect('teacher_wallet')

    withdraws = wallet.withdrawals.all().order_by('-created_at')
    return render(
        request,
        'teachers/wallet.html',
        {
            'wallet': wallet,
            'withdraws': withdraws,
            'commission_percentage': site_setting.platform_commission_percentage,
        },
    )

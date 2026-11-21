"""teachers.views.payments
Extracted from teachers/views.py.
"""

import requests
from datetime import timedelta
from core.models import credit_teacher_wallet_for_sale
from django.utils import timezone
from django.shortcuts import (
    render,
    redirect,
    get_object_or_404,
)
from django.contrib.auth.decorators import login_required
from django.contrib import messages
from django.conf import settings
from django.http import HttpResponse
from teachers.models import PaymentTransaction
from django.urls import reverse
from teachers.models import SubscriptionPlan
from students.models import PackageEnrollment
from teachers.models import CoursePackage
import hashlib
import hmac
import logging
from django.conf import settings as django_settings
from django.db import transaction


@login_required
def paymob_checkout(request):
    try: teacher = request.user.teacher_profile
    except: return redirect('home')

    if teacher.has_active_subscription():
        messages.warning(request, "اشتراكك ما زال سارياً. لا يمكنك الاشتراك في باقة جديدة الآن.")
        return redirect('subscription_info')
    
    plan_id = request.GET.get('plan_id')
    
    if plan_id:
        plan = get_object_or_404(SubscriptionPlan, id=plan_id)
        amount = plan.price
    else:
        amount = 500 

    # توجيه إلى الدفع اليدوي
    url = reverse('manual_checkout')
    return redirect(f"{url}?type=teacher_subscription&id={plan_id or 1}&amount={amount}")

    # ===== كود Paymob القديم معطل مؤقتاً =====
    # method = request.GET.get('method', 'card') # card or wallet
    # wallet_number = request.GET.get('wallet_number')
    # amount_cents = int(amount) * 100 

    # if method == 'wallet':
    #     integration_id = settings.PAYMOB_WALLET_INTEGRATION_ID
    # else:
    #     integration_id = settings.PAYMOB_INTEGRATION_ID

    try:
        # 1. Auth
        auth_req = requests.post("https://accept.paymob.com/api/auth/tokens", json={"api_key": settings.PAYMOB_API_KEY})
        auth_token = auth_req.json().get("token")
        
        # 2. Order
        order_req = requests.post("https://accept.paymob.com/api/ecommerce/orders", json={
            "auth_token": auth_token, "delivery_needed": "false", "amount_cents": amount_cents, "currency": "EGP", "items": []
        })
        order_id = order_req.json().get("id")
        
        # 3. Payment Key
        payment_req = requests.post("https://accept.paymob.com/api/acceptance/payment_keys", json={
            "auth_token": auth_token, "amount_cents": amount_cents, "expiration": 3600, "order_id": order_id,
            "billing_data": {
                "apartment": "NA", "email": request.user.email, "floor": "NA", "first_name": "Teacher", 
                "street": "NA", "building": "NA", "phone_number": wallet_number or request.user.phone or "+201000000000", 
                "shipping_method": "NA", "postal_code": "NA", "city": "NA", "country": "EG", 
                "last_name": "User", "state": "NA"
            }, 
            "currency": "EGP", "integration_id": integration_id
        })
        payment_key = payment_req.json().get("token")
        
        if not payment_key:
            return HttpResponse(f"Paymob Error: {payment_req.text}")

        # 4. التوجيه (حسب الطريقة)
        if method == 'wallet' and wallet_number:
            # دفع مباشر للمحفظة (API Call)
            pay_req = requests.post("https://accept.paymob.com/api/acceptance/payments/pay", json={
                "source": {"identifier": wallet_number, "subtype": "WALLET"},
                "payment_token": payment_key
            })
            pay_data = pay_req.json()
            # +++++ أضف هذا السطر للتشخيص +++++
            print("--- WALLET TRANSACTION INFO ---")
            print(f"Transaction ID: {pay_data.get('id')}") # <--- هذا هو الرقم الذي تريده
            print(f"Pending: {pay_data.get('pending')}")
            print("-------------------------------")           
            # توجيه لرابط التأكيد (إن وجد) أو عرض رسالة
            if pay_data.get('redirect_url'):
                return redirect(pay_data.get('redirect_url'))
            else:
                # في حالة Pending (نجاح مبدئي)
                return HttpResponse("<h1>تم إرسال طلب الدفع لمحفظتك. يرجى فتح التطبيق والموافقة.</h1>")
        else:
            # دفع بالفيزا (Iframe)
            return redirect(f"https://accept.paymob.com/api/acceptance/iframes/{settings.PAYMOB_IFRAME_ID}?payment_token={payment_key}")

    except Exception as e:
        messages.error(request, f"خطأ: {e}")
        return redirect('subscription_info')


_pay_logger = logging.getLogger('teachers.views')


_PAYMOB_HMAC_FIELDS = (
    'amount_cents',
    'created_at',
    'currency',
    'error_occured',
    'has_parent_transaction',
    'id',
    'integration_id',
    'is_3d_secure',
    'is_auth',
    'is_capture',
    'is_refunded',
    'is_standalone_payment',
    'is_voided',
    'order',
    'owner',
    'pending',
    'source_data.pan',
    'source_data.sub_type',
    'source_data.type',
    'success',
)


def _verify_paymob_hmac(query_dict) -> bool:
    """يتحقق من توقيع Paymob HMAC-SHA512 قبل اعتماد أي معاملة مالية."""
    hmac_sent = (query_dict.get('hmac') or '').strip()
    secret = (getattr(django_settings, 'PAYMOB_HMAC_SECRET', '') or '').strip()
    if not secret or not hmac_sent:
        return False
    concat = ''.join(str(query_dict.get(field, '')) for field in _PAYMOB_HMAC_FIELDS)
    expected = hmac.new(
        secret.encode('utf-8'),
        concat.encode('utf-8'),
        hashlib.sha512,
    ).hexdigest()
    return hmac.compare_digest(expected.lower(), hmac_sent.lower())


@login_required
def payment_callback(request):
    success = request.GET.get('success')

    # 1. التحقق الصارم من نجاح الدفع وصحة توقيع HMAC
    if success != "true" or not _verify_paymob_hmac(request.GET):
        _pay_logger.warning(
            "Rejected unverified payment callback for user=%s success=%s has_hmac=%s",
            getattr(request.user, 'id', None),
            success,
            bool(request.GET.get('hmac')),
        )
        error_msg = request.GET.get('data.message') or "فشل التحقق الأمني من عملية الدفع (HMAC غير صالح)."
        messages.error(request, f"فشلت عملية الدفع: {error_msg}")
        return render(request, 'teachers/payment_failed.html', status=403)

    # 2. حالة النجاح الموثّقة (نتفرع حسب الدور)
    try:
        user = request.user
        paymob_id = str(request.GET.get('id') or request.GET.get('order') or "Unknown")

        # ==========================
        # أ) لو المستخدم "معلم" (تجديد اشتراك)
        # ==========================
        if user.role == 'teacher':
            try:
                teacher = user.teacher_profile
            except Exception:
                return redirect('home')

            if paymob_id != "Unknown" and PaymentTransaction.objects.filter(transaction_id=paymob_id).exists():
                messages.info(request, "تم تسجيل هذه المعاملة مسبقًا.")
                return render(request, 'teachers/payment_success.html')

            with transaction.atomic():
                # تحديث الباقة
                plan_id = request.session.get('selected_plan_id')
                if plan_id:
                    try:
                        new_plan = SubscriptionPlan.objects.get(id=plan_id)
                        teacher.current_plan = new_plan
                    except SubscriptionPlan.DoesNotExist:
                        pass

                # تمديد التاريخ
                if teacher.has_active_subscription():
                    teacher.subscription_end_date += timedelta(days=30)
                else:
                    teacher.subscription_end_date = timezone.now() + timedelta(days=30)
                teacher.save()

                # حفظ السجل
                amount = teacher.current_plan.price if teacher.current_plan else 500
                PaymentTransaction.objects.create(teacher=teacher, amount=amount, transaction_id=paymob_id)

            # تنظيف السيشن
            if 'selected_plan_id' in request.session:
                del request.session['selected_plan_id']

            messages.success(request, "مبروك! تم تجديد اشتراكك بنجاح.")
            return render(request, 'teachers/payment_success.html')

        # ==========================
        # ب) لو المستخدم "طالب" (شراء حزمة)
        # ==========================
        elif user.role == 'student':
            pkg_id = request.session.get('buying_package_id')

            if not pkg_id:
                messages.error(request, "حدث خطأ: بيانات الحزمة غير موجودة في الجلسة.")
                return redirect('student_dashboard')

            package = get_object_or_404(CoursePackage, id=pkg_id)
            student = user.student_profile

            # 1 & 2. تفعيل الحزمة وإضافة الرصيد مرة واحدة فقط داخل معاملة ذرية
            with transaction.atomic():
                enrollment, _created = PackageEnrollment.objects.get_or_create(
                    student=student,
                    package=package,
                    defaults={'is_paid': False}
                )
                enrollment = PackageEnrollment.objects.select_for_update().get(id=enrollment.id)
                if not enrollment.is_paid:
                    enrollment.is_paid = True
                    enrollment.save(update_fields=['is_paid'])
                    credit_teacher_wallet_for_sale(package.teacher, package.price)

            # 3. تنظيف السيشن
            if 'buying_package_id' in request.session:
                del request.session['buying_package_id']

            messages.success(request, f"تم شراء حزمة '{package.title}' بنجاح! ابدأ التعلم الآن.")

            # التوجيه المباشر لمحتوى الحزمة
            return redirect('my_package_content', package_id=package.id)

    except Exception as e:
        print(f"❌ Callback Error: {e}")
        messages.warning(request, "تمت عملية الدفع، لكن حدث خطأ أثناء التوجيه. يرجى التحقق من اشتراكاتك.")
        if request.user.role == 'student':
            return redirect('student_dashboard')
        else:
            return redirect('teacher_dashboard')

    return redirect('home')

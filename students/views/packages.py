"""students.views.packages
Extracted from students/views.py.
"""

from django.shortcuts import (
    render,
    redirect,
    get_object_or_404,
)
from django.contrib.auth.decorators import login_required
from django.contrib import messages
from teachers.models import Lecture
from exams.models import Exam
import requests
from django.conf import settings
from django.db import transaction
from django.http import HttpResponse
from core.utils import get_optimized_package_leaderboard
from students.models import (
    PackageEnrollment,
    VideoViewTracking,
)
from teachers.models import CoursePackage
from django.urls import reverse
from students.models import PackageExamResult

from students.views.access import _clear_student_web_watch_state


def package_detail(request, package_id):
    package = get_object_or_404(CoursePackage, id=package_id)
    is_enrolled = False
    
    if request.user.is_authenticated and request.user.role == 'student':
        is_enrolled = PackageEnrollment.objects.filter(
            student=request.user.student_profile, 
            package=package, 
            is_paid=True
        ).exists()

    return render(request, 'students/package_detail.html', {
        'package': package,
        'is_enrolled': is_enrolled
    })


@login_required
def my_package_content(request, package_id):
    _clear_student_web_watch_state(request)
    student = request.user.student_profile
    package = get_object_or_404(CoursePackage, id=package_id)
    
    # التأكد من الدفع
    if not PackageEnrollment.objects.filter(student=student, package=package, is_paid=True).exists():
        return redirect('package_detail', package_id=package.id)

    # جلب المحتوى
    lectures = package.lectures.all()
    exams = package.exams.all()
    
    # جلب التقدم (عشان نعرف شاف ايه)
    progress = VideoViewTracking.objects.filter(student=student, package=package)
    watched_ids = progress.values_list('lecture_id', flat=True)

    from api_v1.device_security_service import check_web_ios_only_lecture_access
    ios_access = check_web_ios_only_lecture_access(request, request.user, force_web=True)
    web_lectures_allowed = bool(ios_access.get('allowed'))

    return render(request, 'students/my_package_content.html', {
        'package': package,
        'lectures': lectures if web_lectures_allowed else [],
        'exams': exams,
        'watched_ids': watched_ids if web_lectures_allowed else [],
        'web_lectures_allowed': web_lectures_allowed,
        'web_lectures_block_reason': '' if web_lectures_allowed else (ios_access.get('error') or ''),
        'web_lectures_needs_ipad_probe': bool(ios_access.get('needs_ipad_probe')) if not web_lectures_allowed else False,
    })


@login_required
def paymob_package_checkout(request, package_id):
    if request.user.role != 'student': return redirect('home')

    package = get_object_or_404(CoursePackage, id=package_id)
    amount = package.price

    # توجيه إلى الدفع اليدوي
    url = reverse('manual_checkout')
    return redirect(f"{url}?type=student_package&id={package.id}&amount={amount}")

    # ===== كود Paymob القديم معطل مؤقتاً =====
    # method = request.GET.get('method', 'card')
    # wallet_number = request.GET.get('wallet_number')
    
    # amount_cents = int(package.price) * 100
    # request.session['buying_package_id'] = package.id

    # if method == 'wallet':
    #     integration_id = settings.PAYMOB_WALLET_INTEGRATION_ID
    # else:
    #     integration_id = settings.PAYMOB_INTEGRATION_ID

    try:
        # Auth
        auth_req = requests.post("https://accept.paymob.com/api/auth/tokens", json={"api_key": settings.PAYMOB_API_KEY})
        auth_token = auth_req.json().get("token")
        
        # Order
        order_req = requests.post("https://accept.paymob.com/api/ecommerce/orders", json={
            "auth_token": auth_token, "delivery_needed": "false", "amount_cents": amount_cents, "currency": "EGP", "items": []
        })
        order_id = order_req.json().get("id")
        
        # Key
        payment_req = requests.post("https://accept.paymob.com/api/acceptance/payment_keys", json={
            "auth_token": auth_token, "amount_cents": amount_cents, "expiration": 3600, "order_id": order_id,
            "billing_data": {
                "apartment": "NA", "email": request.user.email, "floor": "NA", "first_name": "Student", 
                "street": "NA", "building": "NA", "phone_number": wallet_number or request.user.phone or "+201000000000", 
                "shipping_method": "NA", "postal_code": "NA", "city": "NA", "country": "EG", 
                "last_name": "User", "state": "NA"
            }, 
            "currency": "EGP", "integration_id": integration_id
        })
        payment_key = payment_req.json().get("token")
        
        if not payment_key:
            return HttpResponse(f"Paymob Error: {payment_req.text}")

        # Redirect Logic
        if method == 'wallet' and wallet_number:
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
            
            if pay_data.get('redirect_url'):
                return redirect(pay_data.get('redirect_url'))
            else:
                return HttpResponse("<h1>تم إرسال الطلب لمحفظتك. يرجى الموافقة من التطبيق.</h1>")
        else:
            return redirect(f"https://accept.paymob.com/api/acceptance/iframes/{settings.PAYMOB_IFRAME_ID}?payment_token={payment_key}")

    except Exception as e:
        messages.error(request, f"خطأ: {e}")
        return redirect('package_detail', package_id=package.id)


@login_required
def watch_package_lecture(request, package_id, lecture_id):
    if not hasattr(request.user, 'student_profile'):
        return redirect('home')
    student = request.user.student_profile
    package = get_object_or_404(CoursePackage, id=package_id)
    lecture = get_object_or_404(Lecture, id=lecture_id)

    # 1. التحقق من الاشتراك (الدفع) وانتماء المحاضرة وتفعيلها داخل الباقة
    is_enrolled = PackageEnrollment.objects.filter(student=student, package=package, is_paid=True).exists()
    if not is_enrolled:
        messages.error(request, "يجب شراء الحزمة أولاً.")
        return redirect('package_detail', package_id=package.id)

    if not package.lectures.filter(id=lecture.id, is_active=True).exists():
        messages.error(request, "هذه المحاضرة غير متاحة ضمن هذه الباقة.")
        return redirect('my_package_content', package_id=package.id)

    from api_v1.device_security_service import check_web_ios_only_lecture_access
    ios_access = check_web_ios_only_lecture_access(request, request.user, force_web=True)
    if not ios_access.get('allowed'):
        return render(
            request,
            'students/web_lectures_blocked.html',
            {
                'package': package,
                'block_reason': ios_access.get('error') or '',
                'needs_ipad_probe': bool(ios_access.get('needs_ipad_probe')),
            },
            status=403,
        )

    # 2. تتبع المشاهدة
    tracker, created = VideoViewTracking.objects.get_or_create(
        student=student, package=package, lecture=lecture
    )

    from api_v1.video_security import (
        get_active_watch_window_expiry,
        grant_watch_window,
    )
    request.session.pop(f"viewed_pkg_lec_{package.id}_{lecture.id}", None)
    watch_window_exp = get_active_watch_window_expiry(
        request.user, lecture.id, package_id=package.id
    )
    is_currently_viewing = watch_window_exp is not None

    # التحقق من حد المشاهدات
    if tracker.views_count >= package.view_limit and not (
        is_currently_viewing and tracker.views_count <= package.view_limit
    ):
        messages.error(request, "لقد استهلكت عدد مرات مشاهدة هذا الفيديو في الباقة.")
        return redirect('my_package_content', package_id=package.id)

    from django.utils.translation import gettext as _
    from api_v1.device_security_service import enforce_web_lecture_playback
    from api_v1.models import PlaybackSession
    playback_res = enforce_web_lecture_playback(request, request.user, lecture, course_package=package)
    if not playback_res.get('allowed'):
        messages.error(request, playback_res.get('error') or _("هذا المتصفح غير مخوّل لتشغيل المحاضرة."))
        return redirect('web_trusted_devices')

    # 3. احتساب النقاط والمشاهدة ذرياً بعد التحقق الأمني من الجهاز
    with transaction.atomic():
        locked_tracker = VideoViewTracking.objects.select_for_update().get(pk=tracker.pk)
        if not is_currently_viewing:
            if locked_tracker.views_count >= package.view_limit:
                messages.error(request, "لقد استهلكت عدد مرات مشاهدة هذا الفيديو في الباقة.")
                return redirect('my_package_content', package_id=package.id)
            if not locked_tracker.is_completed:
                locked_tracker.is_completed = True
                locked_tracker.points_awarded = 10
                messages.success(request, "تم احتساب 10 درجات مشاهدة!")
            locked_tracker.views_count += 1
            locked_tracker.save()
            watch_window_exp = grant_watch_window(request.user, lecture.id)
        tracker = locked_tracker

    if playback_res.get('playback_session_uuid') and watch_window_exp is not None:
        PlaybackSession.objects.filter(
            session_id=playback_res.get('playback_session_uuid')
        ).update(view_window_expires_at=watch_window_exp)

    return render(request, 'students/watch_package_lecture.html', {
        'lecture': lecture,
        'package': package,
        'tracker': tracker,
        'playback_session_uuid': playback_res.get('playback_session_uuid', ''),
        'web_installation_id': playback_res.get('installation_id', ''),
        'watermark': playback_res.get('watermark', {}),
    })


@login_required
def student_take_package_exam(request, package_id, exam_id):
    if not hasattr(request.user, 'student_profile'):
        return redirect('home')
    student = request.user.student_profile
    package = get_object_or_404(CoursePackage, id=package_id)
    exam = get_object_or_404(Exam, id=exam_id)

    # 1. التأكد من شراء الحزمة وارتباط الامتحان وتفعيله
    if not PackageEnrollment.objects.filter(student=student, package=package, is_paid=True).exists():
        return redirect('package_detail', package_id=package.id)

    if not package.exams.filter(id=exam.id, is_active=True).exists():
        messages.error(request, "هذا الامتحان غير متاح حالياً ضمن هذه الباقة.")
        return redirect('my_package_content', package_id=package.id)

    # 2. التأكد من عدم أداء الامتحان "داخل هذه الحزمة"
    if PackageExamResult.objects.filter(student=student, package=package, exam=exam).exists():
        messages.info(request, "لقد أديت هذا الامتحان داخل الحزمة مسبقاً.")
        return redirect('my_package_content', package_id=package.id)

    # 3. معالجة الإجابات
    if request.method == 'POST':
        score = 0
        questions = exam.questions.all()
        for q in questions:
            selected = request.POST.get(f'question_{q.id}')
            if selected == q.correct_answer:
                score += q.marks
        
        # حفظ النتيجة في الجدول الجديد
        PackageExamResult.objects.create(student=student, package=package, exam=exam, score=score)
        
        messages.success(request, f"تم التسليم. درجتك: {score}")
        return redirect('my_package_content', package_id=package.id)

    return render(request, 'students/take_package_exam.html', {'exam': exam, 'package': package, 'questions': exam.questions.all()})


@login_required
def my_package_marks(request, package_id):
    if not hasattr(request.user, 'student_profile'):
        return redirect('home')
    student = request.user.student_profile
    package = get_object_or_404(CoursePackage, id=package_id)

    if not PackageEnrollment.objects.filter(student=student, package=package, is_paid=True).exists():
        messages.error(request, "يجب الاشتراك في الباقة أولاً لعرض الدرجات.")
        return redirect('package_detail', package_id=package.id)
    
    # 1. نتائج الامتحانات
    exam_results = PackageExamResult.objects.filter(student=student, package=package)
    
    # 2. نقاط الفيديوهات
    video_points = VideoViewTracking.objects.filter(student=student, package=package, is_completed=True)
    
    # 3. المجموع الكلي
    total_score = sum(r.score for r in exam_results) + sum(v.points_awarded for v in video_points)

    return render(request, 'students/package_marks.html', {
        'package': package,
        'exam_results': exam_results,
        'video_points': video_points,
        'total_score': total_score
    })


@login_required
def package_leaderboard(request, package_id):
    if not hasattr(request.user, 'student_profile'):
        return redirect('home')
    student = request.user.student_profile
    package = get_object_or_404(CoursePackage, id=package_id)
    if not PackageEnrollment.objects.filter(student=student, package=package, is_paid=True).exists():
        messages.error(request, "يجب الاشتراك في الباقة أولاً لعرض لوحة الشرف.")
        return redirect('package_detail', package_id=package.id)
    leaderboard = get_optimized_package_leaderboard(package)
    my_rank = next((x['rank'] for x in leaderboard if x['student'] == student), '-')

    return render(request, 'students/package_leaderboard.html', {
        'package': package,
        'leaderboard': leaderboard,
        'my_rank': my_rank
    })


# ملفات الحزمة
@login_required
def student_package_files(request, package_id):
    student = request.user.student_profile
    package = get_object_or_404(CoursePackage, id=package_id)
    
    if not PackageEnrollment.objects.filter(student=student, package=package, is_paid=True).exists():
        return redirect('package_detail', package_id=package.id)

    pdfs = package.pdfs.all().order_by('-created_at')

    return render(request, 'students/package_files.html', { # سنستخدم نفس التصميم
        'package': package,
        'pdfs': pdfs,
        'active_tab': 'files'
    })

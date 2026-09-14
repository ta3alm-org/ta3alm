from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth.decorators import login_required
from django.contrib import messages
from django.db.models import Q
from teachers.models import Group
from .models import Enrollment
from accounts.models import StudentProfile
from django.utils import timezone
from teachers.models import Group, Lecture, VideoCode
from exams.models import Exam, Question, ExamResult
from .models import Enrollment, PerformanceLog
import requests
import random
import string
from datetime import timedelta
from django.utils import timezone
from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth.decorators import login_required
from django.contrib import messages
from django.conf import settings
from django.db.models import Q
from django.http import HttpResponse
from core.utils import send_notification
from core.models import Subject
# 1. لوحة تحكم الطالب (سنعرض فيها المجموعات المشترك بها)
@login_required
def student_dashboard(request):
    if request.user.role != 'student':
        return redirect('home')

    try:
        student = request.user.student_profile
    except StudentProfile.DoesNotExist:
        return redirect('complete_profile')

    # جلب المجموعات مع البيانات المرتبطة لتجنب N+1 Queries
    enrollments = (
        student.enrollments
        .filter(is_active=True)
        .select_related('group__teacher__current_plan', 'group__teacher__user')
    )
    pending_groups = student.enrollments.filter(is_active=False).select_related('group__teacher__user')
    my_packages = PackageEnrollment.objects.filter(student=student, is_paid=True).select_related('package')

    # التحقق من حالة كل مجموعة (بناءً على باقة المعلم)
    active_enrollments = []
    locked_enrollments = []

    for enroll in enrollments:
        teacher = enroll.group.teacher
        allowed_ids = list(teacher.get_allowed_group_ids())
        if enroll.group.id in allowed_ids:
            active_enrollments.append(enroll)
        else:
            locked_enrollments.append(enroll)

    context = {
        'my_groups': active_enrollments,       # المجموعات النشطة والمسموح بها
        'locked_groups': locked_enrollments,   # المجموعات المقيّدة (تجاوز حد الباقة)
        'pending_groups': pending_groups,      # طلبات الانتظار
        'my_packages': my_packages,
    }

    return render(request, 'students/dashboard.html', context)


def list_packages(request):
    # نعرض فقط الحزم التي يملك معلموها صلاحية "أونلاين" في باقتهم الحالية
    packages = CoursePackage.objects.filter(
        is_active=True,
        teacher__current_plan__allow_online_packages=True # <--- الشرط السحري
    ).order_by('-created_at')
    
    return render(request, 'students/list_packages.html', {'packages': packages})



# 2. صفحة البحث عن مجموعات جديدة
@login_required
def search_groups(request):
    # 1. التعريف الأولي (الأساسي)
    # نضمن أن المتغير groups موجود دائماً حتى لو لم يدخل في أي if
    groups = Group.objects.select_related('teacher__user', 'teacher__subject').order_by('-created_at')
    
    query = request.GET.get('q')
    grade = request.GET.get('grade')
    subject_id = request.GET.get('subject')

    # 2. الفلاتر (تعديل المتغير الموجود)
    if query:
        groups = groups.filter(
            Q(name__icontains=query) | 
            Q(teacher__user__first_name__icontains=query) |
            Q(teacher__user__last_name__icontains=query) |
            # لاحظ: teacher__subject__name لأن subject أصبح ForeignKey
            Q(teacher__subject__name__icontains=query)
        )
    
    if grade:
        groups = groups.filter(grade=grade)
        
    if subject_id:
        groups = groups.filter(teacher__subject__id=subject_id)

    # 3. بيانات الطالب (لزر الانضمام)
    my_enrollment_ids = []
    if request.user.role == 'student':
        try:
            student = request.user.student_profile
            my_enrollment_ids = student.enrollments.values_list('group_id', flat=True)
        except:
            pass

    # 4. قائمة المواد للفلتر
    subjects = Subject.objects.all()

    context = {
        'groups': groups, # الآن هو موجود ومفلتر
        'my_enrollment_ids': my_enrollment_ids,
        'query': query,
        'subjects': subjects
    }
    return render(request, 'students/search.html', context)

# 3. إرسال طلب انضمام
@login_required
def join_group(request, group_id):
    student = request.user.student_profile
    group = get_object_or_404(Group, id=group_id)
    teacher = group.teacher
    current_count = teacher.get_total_students()
    limit = teacher.get_student_limit()

    # التأكد أنه لم ينضم سابقاً (سواء مقبول أو انتظار)
    existing = Enrollment.objects.filter(student=student, group=group).exists()
    if current_count >= limit:
        messages.error(request, "عفواً، لا يمكن الانضمام. لقد وصل المعلم للحد الأقصى من الطلاب.")
        return redirect('student_dashboard')
    if not existing:
        Enrollment.objects.create(student=student, group=group, is_active=False)
        send_notification(
    group.teacher.user,
    "طلب انضمام جديد",
    f"الطالب {student.user.first_name} طلب الانضمام لمجموعة {group.name}",
    f"/teacher/group/{group.id}/requests/"
)
        messages.success(request, f"تم إرسال طلب الانضمام لمجموعة '{group.name}' بنجاح، في انتظار موافقة المعلم.")
    else:
        messages.warning(request, "أنت بالفعل عضو في هذه المجموعة أو الطلب قيد الانتظار.")
        
    return redirect('student_dashboard')






# --- دالة مساعدة للتحقق من الطالب واشتراك المعلم ---
# دالة التحقق الذكية (تشمل الباقات والاشتراك)
def check_student_access(user, group_id):
    if user.role != 'student':
        return None, "not_student"
    
    group = get_object_or_404(Group, id=group_id)
    teacher = group.teacher

    # 1. التحقق من صلاحية الاشتراك الزمنية
    if not teacher.has_active_subscription():
        return group, "teacher_expired"

    # 2. التحقق من الانضمام
    try:
        enrollment = Enrollment.objects.get(student=user.student_profile, group=group, is_active=True)
    except Enrollment.DoesNotExist:
        return group, "not_enrolled"

    # 3. التحقق من حد الباقة (الخدعة الذكية)
    limit = teacher.get_student_limit() # مثلاً 1000
    
    # نجلب كل طلاب المعلم (عبر كل المجموعات) مرتبين بتاريخ الانضمام (الأقدم فالأحدث)
    # ونأخذ أول 1000 طالب فقط (المحظوظين)
    allowed_students_ids = Enrollment.objects.filter(
        group__teacher=teacher, 
        is_active=True
    ).order_by('joined_at').values_list('student__id', flat=True)[:limit]

    # هل الطالب الحالي ضمن المحظوظين؟
    if user.student_profile.id not in allowed_students_ids:
        # الطالب زائد عن الحد (رقم 1001)
        return group, "limit_exceeded"
    
    # +++++ فحص جديد: هل المجموعة مسموحة للمعلم؟ +++++
    allowed_ids = group.teacher.get_allowed_group_ids()
    if group.id not in allowed_ids:
        return group, "group_locked_by_plan" # حالة جديدة
    # ++++++++++++++++++++++++++++++++++++++++++++++
    

    return group, "ok"

# ==========================================
# 1. صفحة المحاضرات (الرئيسية للمجموعة)
# ==========================================
@login_required
def student_group_content(request, group_id):
    group, status = check_student_access(request.user, group_id)
    
    if status == "teacher_expired":
        return render(request, 'students/teacher_unavailable.html', {'teacher_name': group.teacher.user.first_name})
    elif status == "limit_exceeded": # <--- الحالة الجديدة
        return render(request, 'students/teacher_full.html', {'teacher_name': group.teacher.user.first_name})
    elif status != "ok":
        return redirect('student_dashboard')

    lectures = group.lectures.filter(is_active=True).order_by('-created_at')
    
    # معرفة الفيديوهات التي فتحها الطالب بالفعل
    unlocked_lectures = VideoCode.objects.filter(
        used_by=request.user.student_profile, 
        lecture__group=group
    ).values_list('lecture_id', flat=True)

    context = {
        'group': group,
        'lectures': lectures,
        'unlocked_ids': unlocked_lectures,
        'active_tab': 'content'
    }
    return render(request, 'students/group_content.html', context)

# ==========================================
# 2. مشاهدة محاضرة (إدخال الكود)
# ==========================================
@login_required
def student_watch_lecture(request, lecture_id):
    lecture = get_object_or_404(Lecture, id=lecture_id)
    group, status = check_student_access(request.user, lecture.group.id)
    
    if status != "ok": return redirect('student_dashboard')

    student = request.user.student_profile
    
    # جلب الكود المستخدم (إن وجد) الأحدث
    active_code = VideoCode.objects.filter(lecture=lecture, used_by=student).order_by('-used_at').first()
    
    # 1. التحقق من السماح بالمشاهدة
    is_unlocked = False
    if active_code:
        session_key = f"viewed_lec_{lecture.id}_{active_code.id}"
        is_currently_viewing = request.session.get(session_key, False)

        # إذا لم يكن في جلسة المشاهدة الحالية، وتجاوز الحد المسموح
        if not is_currently_viewing and active_code.current_views >= active_code.max_views:
            messages.error(request, "لقد استهلكت عدد مرات مشاهدة هذا الفيديو. يرجى شراء كود جديد.")
            is_unlocked = False
        else:
            is_unlocked = True
            # إذا كانت أول مرة يفتح فيها الفيديو في هذه الجلسة
            if request.method == 'GET' and not is_currently_viewing:
                active_code.current_views += 1
                active_code.save()
                request.session[session_key] = True

    # 2. معالجة إدخال كود جديد (POST)
    if request.method == 'POST':
        # لو الفيديو مفتوح ولسه فيه مشاهدات، ليه يدخل كود؟
        if is_unlocked: 
            return redirect('student_watch_lecture', lecture_id=lecture.id)

        code_input = request.POST.get('code', '').strip()
        try:
            # نبحث عن كود جديد، سليم، وغير مستخدم
            new_code = VideoCode.objects.get(code=code_input, lecture=lecture, is_used=False)
            
            # تفعيل الكود الجديد
            new_code.is_used = True
            new_code.used_by = student
            new_code.used_at = timezone.now()
            # لا نزيد العداد هنا لأن الـ GET redirect سيتكفل به
            new_code.save()
            
            messages.success(request, "تم تفعيل الكود بنجاح!")
            return redirect('student_watch_lecture', lecture_id=lecture.id)
            
        except VideoCode.DoesNotExist:
            messages.error(request, "الكود غير صحيح أو مستخدم من قبل.")

    return render(request, 'students/watch_lecture.html', {
        'lecture': lecture,
        'group': group,
        'is_unlocked': is_unlocked,
        'active_code': active_code # لنعرض له (المتبقي: X)
    })

# ==========================================
# 3. قائمة الامتحانات
# ==========================================
@login_required
def student_group_exams(request, group_id):
    group, status = check_student_access(request.user, group_id)
    if status == "teacher_expired": return render(request, 'students/teacher_unavailable.html', {'teacher_name': group.teacher.user.first_name})
    elif status != "ok": return redirect('student_dashboard')

    # الامتحانات المفعلة فقط
    exams = group.exams.filter(is_active=True).order_by('-created_at')
    
    # الامتحانات التي دخلها الطالب سابقاً
    taken_exam_ids = ExamResult.objects.filter(
        student=request.user.student_profile, 
        exam__group=group
    ).values_list('exam_id', flat=True)

    context = {
        'group': group,
        'exams': exams,
        'taken_ids': taken_exam_ids,
        'active_tab': 'exams'
    }
    return render(request, 'students/group_exams.html', context)

# ==========================================
# 4. أداء الامتحان
# ==========================================
@login_required
def student_take_exam(request, exam_id):
    exam = get_object_or_404(Exam, id=exam_id)
    group, status = check_student_access(request.user, exam.group.id)
    
    if status == "teacher_expired": return render(request, 'students/teacher_unavailable.html', {'teacher_name': group.teacher.user.first_name})
    elif status != "ok": return redirect('student_dashboard')

    student = request.user.student_profile

    # منع الدخول إذا كان الامتحان مغلقاً أو تم أداؤه
    if not exam.is_active:
        messages.error(request, "هذا الامتحان مغلق حالياً.")
        return redirect('student_group_exams', group_id=group.id)
    
    if ExamResult.objects.filter(student=student, exam=exam).exists():
        messages.info(request, "لقد قمت بأداء هذا الامتحان مسبقاً.")
        return redirect('student_group_exams', group_id=group.id)

    # معالجة الإجابات (التصحيح)
    if request.method == 'POST':
        score = 0
        questions = exam.questions.all()
        
        for q in questions:
            # اسم الحقل في الفورم هو question_ID
            selected_option = request.POST.get(f'question_{q.id}')
            if selected_option == q.correct_answer:
                score += q.marks
        
        # حفظ النتيجة
        ExamResult.objects.create(student=student, exam=exam, score=score)
        
        messages.success(request, f"تم تسليم الامتحان. درجتك: {score} / {exam.total_marks()}")
        return redirect('student_group_exams', group_id=group.id)

    questions = exam.questions.all()
    return render(request, 'students/take_exam.html', {'exam': exam, 'questions': questions})

# ==========================================
# 5. درجاتي (السجل)
# ==========================================
@login_required
def student_group_marks(request, group_id):
    group, status = check_student_access(request.user, group_id)
    if status == "teacher_expired": return render(request, 'students/teacher_unavailable.html', {'teacher_name': group.teacher.user.first_name})
    elif status != "ok": return redirect('student_dashboard')

    # سجلات الأداء (واجب، حصة، غياب)
    logs = PerformanceLog.objects.filter(student=request.user.student_profile, group=group).order_by('-date')
    
        # +++++ فلتر الشهر +++++
    selected_month = request.GET.get('month')
    if selected_month:
        logs = logs.filter(date__month=selected_month)
    # ++++++++++++++++++++++

    # نتائج الامتحانات الإلكترونية
    exam_results = ExamResult.objects.filter(student=request.user.student_profile, exam__group=group).order_by('-submitted_at')

    context = {
        'group': group,
        'logs': logs,
        'exam_results': exam_results,
        'active_tab': 'marks',
        'selected_month': selected_month
    }
    return render(request, 'students/group_marks.html', context)

@login_required
def student_settings(request):
    if request.user.role != 'student': return redirect('home')
    return render(request, 'students/settings.html', {'student': request.user})

# دالة مساعدة لحساب الترتيب (ضعها في بداية الملف أو نهايته)


# ==========================================
# صفحة الترتيب للطالب (الدالة الناقصة)
# ==========================================
@login_required
def student_group_ranking(request, group_id):
    group, status = check_student_access(request.user, group_id)
    if status != "ok": return redirect('student_dashboard')

    from core.utils import get_optimized_group_leaderboard
    leaderboard = get_optimized_group_leaderboard(group)
    
    # معرفة ترتيب الطالب الحالي
    my_rank = next((item['rank'] for item in leaderboard if item['student'] == request.user.student_profile), '-')

    # عرض أول 20 طالب فقط
    return render(request, 'students/group_ranking.html', {
        'group': group,
        'leaderboard': leaderboard[:20], 
        'my_rank': my_rank,
        'active_tab': 'ranking'
    })


@login_required
def student_group_contact(request, group_id):
    group, status = check_student_access(request.user, group_id)
    if status != "ok": return redirect('student_dashboard')
    
    teacher = group.teacher
    # جلب المساعدين النشطين
    assistants = teacher.assistants_jobs.filter(is_active=True).select_related('assistant__user')
    
    return render(request, 'students/group_contact.html', {
        'group': group,
        'teacher': teacher,
        'assistants': assistants,
        'active_tab': 'contact' # أضف تاب جديد في الناف بار
    })

from .models import PackageEnrollment, VideoViewTracking
from teachers.models import CoursePackage
from django.db import models # <--- هذا هو الاستيراد الناقص
from django.db.models import Sum # أو يمكنك استيراد Sum مباشرة

# دالة حساب ترتيب الحزمة
def get_package_leaderboard(package):
    enrollments = package.enrollments.filter(is_paid=True)
    leaderboard = []

    for enroll in enrollments:
        student = enroll.student
        total_score = 0
        
        # 1. نقاط الفيديوهات
        video_points = VideoViewTracking.objects.filter(
            student=student, package=package
        ).aggregate(sum=models.Sum('points_awarded'))['sum'] or 0
        
        # 2. درجات الامتحانات (داخل هذه الحزمة فقط)
        # نحتاج لتصفية النتائج للامتحانات الموجودة في الحزمة
        exam_points = ExamResult.objects.filter(
            student=student, 
            exam__in=package.exams.all()
        ).aggregate(sum=models.Sum('score'))['sum'] or 0
        
        total_score = video_points + exam_points
        
        leaderboard.append({'student': student, 'score': total_score})

    # ترتيب
    leaderboard.sort(key=lambda x: x['score'], reverse=True)
    return leaderboard


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

    return render(request, 'students/my_package_content.html', {
        'package': package,
        'lectures': lectures,
        'exams': exams,
        'watched_ids': watched_ids
    })

# نفس منطق الدفع، لكن نمرر package_id في الـ Session أو كـ order item
# ==========================================
# 1. دالة بدء الدفع للحزم (Paymob Checkout for Packages)
# ==========================================
from django.urls import reverse

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
# في students/views.py

@login_required
def watch_package_lecture(request, package_id, lecture_id):
    student = request.user.student_profile
    package = get_object_or_404(CoursePackage, id=package_id)
    lecture = get_object_or_404(Lecture, id=lecture_id)

    # 1. التحقق من الاشتراك (الدفع)
    is_enrolled = PackageEnrollment.objects.filter(student=student, package=package, is_paid=True).exists()
    if not is_enrolled:
        messages.error(request, "يجب شراء الحزمة أولاً.")
        return redirect('package_detail', package_id=package.id)

    # 2. تتبع المشاهدة
    tracker, created = VideoViewTracking.objects.get_or_create(
        student=student, package=package, lecture=lecture
    )

    # التحقق من حد المشاهدات
    if tracker.views_count >= package.view_limit:
        messages.error(request, "لقد استهلكت عدد مرات مشاهدة هذا الفيديو في الباقة.")
        return redirect('my_package_content', package_id=package.id)

    # 3. احتساب الـ 10 درجات (أول مرة فقط)
    if not tracker.is_completed:
        tracker.is_completed = True
        tracker.points_awarded = 10
        tracker.save() # حفظ النقاط
        messages.success(request, "تم احتساب 10 درجات مشاهدة!")
    
    # زيادة العداد عند المشاهدة
    # استخدام الجلسة لمنع زيادة العداد عند الـ Refresh
    session_key = f"viewed_pkg_lec_{package.id}_{lecture.id}"
    if not request.session.get(session_key):
        tracker.views_count += 1
        tracker.save()
        request.session[session_key] = True

    return render(request, 'students/watch_package_lecture.html', {
        'lecture': lecture,
        'package': package,
        'tracker': tracker
    })

from .models import PackageExamResult

@login_required
def student_take_package_exam(request, package_id, exam_id):
    student = request.user.student_profile
    package = get_object_or_404(CoursePackage, id=package_id)
    exam = get_object_or_404(Exam, id=exam_id)

    # 1. التأكد من شراء الحزمة
    if not PackageEnrollment.objects.filter(student=student, package=package, is_paid=True).exists():
        return redirect('package_detail', package_id=package.id)

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
    student = request.user.student_profile
    package = get_object_or_404(CoursePackage, id=package_id)
    
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


from django.db.models import Sum # تأكد من الاستيراد

@login_required
def package_leaderboard(request, package_id):
    package = get_object_or_404(CoursePackage, id=package_id)
    
    enrollments = package.enrollments.filter(is_paid=True)
    leaderboard = []
    
    for enroll in enrollments:
        std = enroll.student
        
        # 1. نقاط الفيديوهات
        v_agg = VideoViewTracking.objects.filter(
            student=std, package=package
        ).aggregate(total=Sum('points_awarded'))
        v_points = v_agg['total'] if v_agg['total'] is not None else 0
        
        # 2. نقاط الامتحانات
        e_agg = PackageExamResult.objects.filter(
            student=std, package=package
        ).aggregate(total=Sum('score'))
        e_points = e_agg['total'] if e_agg['total'] is not None else 0
        
        # المجموع
        total_score = v_points + e_points
        
        leaderboard.append({'student': std, 'score': total_score})
    
    # الترتيب
    leaderboard.sort(key=lambda x: x['score'], reverse=True)
    
    # المراكز
    for i, item in enumerate(leaderboard):
        item['rank'] = i + 1
    
    # ترتيبي
    my_rank = next((x['rank'] for x in leaderboard if x['student'] == request.user.student_profile), '-')

    return render(request, 'students/package_leaderboard.html', {
        'package': package,
        'leaderboard': leaderboard,
        'my_rank': my_rank
    })


from teachers.models import PDFFile

# ملفات المجموعة
@login_required
def student_group_files(request, group_id):
    group, status = check_student_access(request.user, group_id)
    if status != "ok": return redirect('student_dashboard')

    pdfs = group.pdfs.all().order_by('-created_at')

    return render(request, 'students/group_files.html', {
        'group': group,
        'pdfs': pdfs,
        'active_tab': 'files' # تفعيل التبويب
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
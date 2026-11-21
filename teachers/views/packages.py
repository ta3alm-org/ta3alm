"""teachers.views.packages
Extracted from teachers/views.py.
"""

from assistants.models import AssistantJob
from django.shortcuts import (
    render,
    redirect,
    get_object_or_404,
)
from django.contrib.auth.decorators import login_required
from django.contrib import messages
from teachers.models import (
    TeacherProfile,
    Lecture,
)
from exams.models import (
    Exam,
    Question,
)
from teachers.forms import CoursePackageForm
from teachers.models import CoursePackage
from core.utils import get_optimized_package_leaderboard

from teachers.views.permissions import get_package_permission


@login_required
def create_package(request):
    teacher = None
    
    # 1. تحديد المعلم بناءً على الدور
    if request.user.role == 'teacher':
        try:
            teacher = request.user.teacher_profile
        except:
            return redirect('complete_profile')
        if not request.user.phone or len(request.user.phone.strip()) < 11 or not teacher.image:
            messages.warning(
                request,
                "يرجى رفع صورتك الشخصية وإدخال رقم هاتفك المحمول (إجباري لجميع المعلمين) قبل المتابعة في المنصة.",
            )
            return redirect('teacher_settings')
            
    elif request.user.role == 'assistant':
        # المساعد يجب أن يمرر teacher_id في الرابط
        teacher_id = request.GET.get('teacher_id')
        if teacher_id:
            teacher = get_object_or_404(TeacherProfile, id=teacher_id)
            # التحقق من الصلاحية
            job = AssistantJob.objects.filter(
                assistant__user=request.user, 
                teacher=teacher, 
                can_manage_packages=True,
                is_active=True
            ).first()
            
            if not job:
                messages.error(request, "ليس لديك صلاحية لإنشاء حزم لهذا المعلم.")
                return redirect('assistant_dashboard')
        else:
            return redirect('assistant_dashboard')
    
    # حماية إضافية
    if not teacher:
        return redirect('home')

    # 2. التحقق من صلاحية الباقة (Online Packages)
    if teacher.current_plan and not teacher.current_plan.allow_online_packages:
        messages.error(request, "باقة المعلم لا تدعم الحزم الأونلاين.")
        return redirect('teacher_dashboard')

    # 3. معالجة الفورم
    if request.method == 'POST':
        form = CoursePackageForm(teacher.user, request.POST, request.FILES)
        if form.is_valid():
            pkg = form.save(commit=False)
            pkg.teacher = teacher
            pkg.save()
            form.save_m2m()
            messages.success(request, "تم إنشاء الحزمة بنجاح.")
            
            if request.user.role == 'assistant':
                return redirect('assistant_view_packages', teacher_id=teacher.id)
            return redirect('teacher_packages')
    else:
        form = CoursePackageForm(user=teacher.user)

    # تمرير المجموعات للفلترة
    groups = teacher.groups.prefetch_related('lectures', 'exams').all()

    return render(request, 'teachers/create_package.html', {
        'form': form,
        'groups': groups
    })


@login_required
def teacher_packages(request):
    try: teacher = request.user.teacher_profile
    except: return redirect('home')

    if not request.user.phone or len(request.user.phone.strip()) < 11 or not teacher.image:
        messages.warning(
            request,
            "يرجى رفع صورتك الشخصية وإدخال رقم هاتفك المحمول (إجباري لجميع المعلمين) قبل المتابعة في المنصة.",
        )
        return redirect('teacher_settings')

    # جلب حزم المعلم
    packages = teacher.packages.all().order_by('-created_at')

    # معالجة الحذف
    if request.method == 'POST':
        pkg_id = request.POST.get('pkg_id')
        try:
            pkg = packages.get(id=pkg_id)
            pkg.delete()
            messages.success(request, "تم حذف الحزمة بنجاح.")
            return redirect('teacher_packages')
        except:
            messages.error(request, "حدث خطأ أثناء الحذف.")

    return render(request, 'teachers/manage_packages.html', {'packages': packages})


@login_required
def edit_package(request, package_id):
    # 1. تعريف المعلم بشكل آمن
    try:
        teacher = request.user.teacher_profile
    except:
        return redirect('home')
    
    # 2. جلب الحزمة (مع التأكد من الملكية)
    package = get_object_or_404(CoursePackage, id=package_id, teacher=teacher)

    # 3. التحقق من صلاحية الباقة (لتعديل الحزم الأونلاين)
    if teacher.current_plan and not teacher.current_plan.allow_online_packages:
        messages.error(request, "باقتك الحالية لا تدعم تعديل الحزم الأونلاين.")
        return redirect('teacher_packages')

    if request.method == 'POST':
        # نمرر user للفورم لفلترة المحتوى
        form = CoursePackageForm(request.user, request.POST, request.FILES, instance=package)
        if form.is_valid():
            form.save()
            form.save_m2m() # هام للعلاقات المتعددة
            messages.success(request, "تم تعديل الحزمة بنجاح.")
            return redirect('teacher_packages')
    else:
        form = CoursePackageForm(user=request.user, instance=package)

    # بيانات للعرض في التيمبلت
    groups = teacher.groups.prefetch_related('lectures', 'exams').all()
    selected_lectures = package.lectures.values_list('id', flat=True)
    selected_exams = package.exams.values_list('id', flat=True)

    return render(request, 'teachers/edit_package.html', {
        'form': form,
        'groups': groups,
        'package': package,
        'sel_lec': selected_lectures,
        'sel_exam': selected_exams
    })


# 1. المحتوى (الرئيسية)
@login_required
def teacher_package_detail(request, package_id):
    package = get_object_or_404(CoursePackage, id=package_id)
    
    # التحقق من الصلاحية (مالك أو مساعد بصلاحية الحزم)
    # لاحظ: نستخدم دالة مخصصة أو نفحص يدوياً لأن get_group_permission للمجموعات فقط
    
    is_owner = False
    if package.teacher.user == request.user:
        is_owner = True
    elif request.user.role == 'assistant':
        job = AssistantJob.objects.filter(assistant__user=request.user, teacher=package.teacher, is_active=True).first()
        if job and job.can_manage_packages:
            is_owner = False # مسموح له بالدخول
        else:
            return redirect('home')
    else:
        return redirect('home')
    
    return render(request, 'teachers/package_dashboard/content.html', {
        'package': package,
        'active_tab': 'content'
    })


# 2. الطلاب المشتركين (Paid Only)
@login_required
def teacher_package_students(request, package_id):
    # جلب الحزمة بدون شرط المالك أولاً
    package = get_object_or_404(CoursePackage, id=package_id)
    
    # التحقق من الصلاحية (معلم أو مساعد)
    is_owner = False
    if package.teacher.user == request.user:
        is_owner = True
    elif request.user.role == 'assistant':
        job = AssistantJob.objects.filter(assistant__user=request.user, teacher=package.teacher, is_active=True).first()
        # المساعد الذي يدير الحزم، من المنطقي أن يرى المشتركين
        if job and job.can_manage_packages:
            is_owner = False # مسموح بالدخول
        else:
            return redirect('home')
    else:
        return redirect('home')

    # الطلاب الذين دفعوا فقط
    enrollments = package.enrollments.filter(is_paid=True).select_related('student__user')
    
    # حساب الأرباح
    total_revenue = enrollments.count() * package.price

    return render(request, 'teachers/package_dashboard/students.html', {
        'package': package,
        'enrollments': enrollments,
        'total_revenue': total_revenue,
        'active_tab': 'students'
    })


# ==========================================
# 1. دالة مساعدة (Logic Only) - لحساب الأرقام فقط
# ==========================================
def calculate_package_leaderboard(package):
    return get_optimized_package_leaderboard(package)


# ==========================================
# 2. دالة العرض (View) - هذه التي نربطها بالرابط
# ==========================================
@login_required
def teacher_package_ranking(request, package_id):
    # جلب الحزمة
    package = get_object_or_404(CoursePackage, id=package_id)
    
    # التحقق من الصلاحية (معلم أو مساعد)
    is_owner = False
    if package.teacher.user == request.user:
        is_owner = True
    elif request.user.role == 'assistant':
        job = AssistantJob.objects.filter(
            assistant__user=request.user, 
            teacher=package.teacher, 
            is_active=True
        ).first()
        
        if job and job.can_manage_packages:
            is_owner = False # مسموح له بالدخول
        else:
            messages.error(request, "ليس لديك صلاحية لدخول هذه الصفحة.")
            return redirect('home')
    else:
        return redirect('home')

    # استدعاء دالة الحساب
    leaderboard = calculate_package_leaderboard(package)

    return render(request, 'teachers/package_dashboard/ranking.html', {
        'package': package,
        'leaderboard': leaderboard,
        'active_tab': 'ranking'
    })


@login_required
def import_package_content(request, package_id):
    package = get_object_or_404(CoursePackage, id=package_id)
    
    # التحقق من الصلاحيات (مالك أو مساعد)
    if package.teacher.user != request.user:
        # تحقق إضافي للمساعد إذا لزم الأمر
        if not (request.user.role == 'assistant' and AssistantJob.objects.filter(assistant__user=request.user, teacher=package.teacher, can_manage_packages=True).exists()):
             return redirect('home')

    if request.method == 'POST':
        source_group_id = request.POST.get('source_group_id')
        
        # القوائم المختارة
        selected_lecture_ids = request.POST.getlist('lecture_ids')
        selected_exam_ids = request.POST.getlist('exam_ids')
        
        # أ) استيراد المحاضرات (مملوكة لمعلم هذه الحزمة فقط)
        if selected_lecture_ids:
            lectures = Lecture.objects.filter(
                id__in=selected_lecture_ids,
                group__teacher=package.teacher,
            )
            package.lectures.add(*lectures)

        # ب) استيراد الامتحانات (نسخ عميق لامتحانات معلم هذه الحزمة فقط)
        if selected_exam_ids:
            source_exams = Exam.objects.filter(
                id__in=selected_exam_ids,
                group__teacher=package.teacher,
            )
            
            for old_exam in source_exams:
                # 1. إنشاء امتحان جديد مستقل (بدون مجموعة)
                new_exam = Exam.objects.create(
                    group=None, # <--- هام جداً للفصل
                    title=old_exam.title,
                    description=old_exam.description,
                    duration_minutes=old_exam.duration_minutes,
                    is_active=False # مغلق للمراجعة
                )
                
                # 2. نسخ الأسئلة للامتحان الجديد
                for q in old_exam.questions.all():
                    Question.objects.create(
                        exam=new_exam,
                        text=q.text,
                        image=q.image, # نسخ الصورة
                        option_a=q.option_a, 
                        option_b=q.option_b,
                        option_c=q.option_c, 
                        option_d=q.option_d,
                        correct_answer=q.correct_answer,
                        marks=q.marks
                    )
                
                # 3. ربط الامتحان الجديد بالحزمة
                package.exams.add(new_exam)
            
        messages.success(request, "تم استيراد المحتوى ونسخ الامتحانات بنجاح.")
        return redirect('teacher_package_detail', package_id=package.id)
        
    return redirect('teacher_package_detail', package_id=package.id)


@login_required
def remove_package_content(request, package_id):
    package, is_owner = get_package_permission(request, package_id, permission_type='videos')
    if not package: return redirect('home')
    
    if request.method == 'POST':
        item_type = request.POST.get('type') # 'lecture' or 'exam'
        item_id = request.POST.get('id')
        
        if item_type == 'lecture':
            lec = get_object_or_404(Lecture, id=item_id)
            package.lectures.remove(lec)
            messages.success(request, "تمت إزالة المحاضرة من الحزمة.")
            
        elif item_type == 'exam':
            exam = get_object_or_404(Exam, id=item_id)
            package.exams.remove(exam)
            messages.success(request, "تمت إزالة الامتحان من الحزمة.")
            
    return redirect('teacher_package_detail', package_id=package.id)


@login_required
def add_lecture_to_package(request, package_id):
    package, is_owner = get_package_permission(request, package_id, permission_type='videos')
    if not package: return redirect('home')
    
    if request.method == 'POST':
        title = request.POST.get('title')
        link = request.POST.get('video_link')
        desc = request.POST.get('description')
        
        # إنشاء محاضرة (بدون مجموعة)
        lecture = Lecture.objects.create(
            group=None, # لا مجموعة
            title=title,
            video_link=link,
            description=desc
        )
        
        package.lectures.add(lecture)
        messages.success(request, "تم إنشاء المحاضرة في الحزمة.")
        
    return redirect('teacher_package_detail', package_id=package.id)


@login_required
def add_exam_to_package(request, package_id):
    package, is_owner = get_package_permission(request, package_id, permission_type='exams')
    if not package: return redirect('home')
    
    if request.method == 'POST':
        title = request.POST.get('title')
        duration = request.POST.get('duration')
        
        # إنشاء امتحان (بدون مجموعة)
        exam = Exam.objects.create(
            group=None,
            title=title,
            duration_minutes=duration,
            is_active=False # مغلق حتى تضيف أسئلة
        )
        
        package.exams.add(exam)
        messages.success(request, "تم إنشاء الامتحان. أضف الأسئلة الآن.")
        
        # توجيه لصفحة إدارة الامتحان لإضافة الأسئلة
        return redirect('exam_manage', exam_id=exam.id)
        
    return redirect('teacher_package_detail', package_id=package.id)

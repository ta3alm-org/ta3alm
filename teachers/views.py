from django.db.models import Sum
from students.models import VideoViewTracking, PackageExamResult
from assistants.models import AssistantJob
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
# --- استيراد المودلز (Models) ---
from .models import TeacherProfile, Group, Lecture, VideoCode, PaymentTransaction,Wallet
from accounts.models import StudentProfile
from exams.models import Exam, Question
from students.models import Enrollment, PerformanceLog
from assistants.models import AssistantJob
from .models import PDFFile
from .forms import PDFForm
from django.urls import reverse
# --- استيراد الفورمز (Forms) ---
from .forms import GroupForm, LectureForm, TeacherSettingsForm, CoursePackageForm
from exams.forms import ExamForm, QuestionForm
from students.forms import PerformanceForm
from assistants.forms import AssistantPermissionsForm

# ==========================================
# دالة مساعدة للتحقق من الصلاحيات (معلم أو مساعد)
# ==========================================
def get_group_permission(request, group_id, permission_type=None):
    """
    تتحقق هل المستخدم هو مالك المجموعة، أو مساعد لديه الصلاحية المطلوبة.
    ترجع: (Group Object, is_owner Boolean)
    """
    group = get_object_or_404(Group, id=group_id)
    user = request.user

    # فحص الحد (حتى للمالك والمساعد)
    allowed_ids = group.teacher.get_allowed_group_ids()
    if group.id not in allowed_ids:
        return None, False # نمنع الدخول تماماً


    # 1. المالك (المعلم)
    if group.teacher.user == user:
        return group, True

    # 2. المساعد
    if user.role == 'assistant':
        job = AssistantJob.objects.filter(
            assistant__user=user, 
            teacher=group.teacher, 
            is_active=True
        ).first()
        
        if job:
            # التحقق من الصلاحيات
            if permission_type == 'students' and job.can_manage_students:
                return group, False
            elif permission_type == 'exams' and job.can_manage_exams:
                return group, False
            elif permission_type == 'videos' and job.can_manage_videos:
                return group, False
            elif permission_type is None: # دخول عام
                return group, False

    return None, False

def get_package_permission(request, package_id, permission_type=None):
    from .models import CoursePackage
    package = get_object_or_404(CoursePackage, id=package_id)
    user = request.user

    # 1. المالك (المعلم)
    if package.teacher.user == user:
        return package, True

    # 2. المساعد
    if user.role == 'assistant':
        job = AssistantJob.objects.filter(
            assistant__user=user, 
            teacher=package.teacher, 
            is_active=True
        ).first()
        
        if job:
            if permission_type == 'videos' and job.can_manage_videos:
                return package, False
            elif permission_type == 'exams' and job.can_manage_exams:
                return package, False
            elif permission_type is None:
                return package, False

    return None, False


# ==========================================
# 1. لوحة تحكم المعلم (Dashboard)
# ==========================================
@login_required
def teacher_dashboard(request):
    if request.user.role != 'teacher':
        return redirect('home')
    try:
        teacher = request.user.teacher_profile
    except TeacherProfile.DoesNotExist:
        return redirect('complete_profile')
    
    if request.method == 'POST':
        # التحقق من الحد الأقصى للمجموعات
        current_groups = teacher.groups.count()
        limit = teacher.current_plan.group_limit if teacher.current_plan else 5
        
        if current_groups >= limit:
            messages.error(request, f"لقد وصلت للحد الأقصى من المجموعات ({limit}). يرجى ترقية الباقة.")
            return redirect('teacher_dashboard')

        # ... (باقي كود الإنشاء) ...
        form = GroupForm(request.POST)
        if form.is_valid():
            new_group = form.save(commit=False)
            new_group.teacher = teacher
            new_group.save()
            messages.success(request, f"تم إنشاء مجموعة '{new_group.name}' بنجاح!")
            return redirect('teacher_dashboard')
    else:
        form = GroupForm()

    # جلب المجموعات
    groups = teacher.groups.all().order_by('created_at')
    allowed_ids = list(teacher.get_allowed_group_ids()) # قائمة المسموح

    # معلومات الاشتراك
    days_left = teacher.days_remaining()
    is_active = teacher.has_active_subscription()

        # ++++++ كود البحث (جديد) ++++++
    query = request.GET.get('q')
    if query:
        groups = groups.filter(name__icontains=query)
    # ++++++++++++++++++++++++++++++


    context = {
        'groups': groups,
        'form': form,
        'days_left': days_left,
        'is_active': is_active,
        'subscription_end': teacher.subscription_end_date,
        'allowed_ids': allowed_ids,
    }
    return render(request, 'teachers/dashboard.html', context)


# ==========================================
# 2. إدارة المجموعة (التبويبات الأربعة)
# ==========================================

# أ) تبويب المحاضرات (Videos)
@login_required
def group_detail(request, group_id):
    group, is_owner = get_group_permission(request, group_id, permission_type='videos')
    if not group:
        messages.error(request, "ليس لديك صلاحية لدخول المحاضرات.")
        return redirect('home')
    
    if not is_owner and not group.teacher.has_active_subscription():
        return render(request, 'students/teacher_unavailable.html', {'teacher_name': group.teacher.user.first_name})

    form = LectureForm()
    if request.method == 'POST' and 'video_submit' in request.POST:
        form = LectureForm(request.POST)
        if form.is_valid():
            video = form.save(commit=False)
            video.group = group
            video.save()
            messages.success(request, "تم نشر المحاضرة بنجاح!")
            for enroll in group.enrollments.filter(is_active=True):
                send_notification(
                    enroll.student.user,
                    "محاضرة جديدة 📹",
                    f"تم نشر محاضرة '{video.title}' في مجموعة {group.name}.",
                    f"/student/group/{group.id}/"
                )
            return redirect('group_detail', group_id=group.id)

    # بحث المحاضرات
    lectures = group.lectures.all().order_by('-created_at')
    query = request.GET.get('q')
    if query:
        lectures = lectures.filter(title__icontains=query)

    pending_count = group.enrollments.filter(is_active=False).count()
    
    # جلب المجموعات الأخرى (مع محتوياتها للاستيراد)
    other_groups = None
    if is_owner:
        other_groups = Group.objects.filter(
            teacher__user=request.user, 
            grade=group.grade
        ).exclude(id=group.id).prefetch_related('lectures', 'exams')

    context = {
        'group': group,
        'lectures': lectures,
        'form': form,
        'pending_count': pending_count,
        'active_tab': 'lectures',
        'is_owner': is_owner,
        'other_groups': other_groups,
        'query': query
    }
    return render(request, 'teachers/group_detail.html', context)


# ب) تبويب الامتحانات (Exams)
@login_required
def group_exams(request, group_id):
    group, is_owner = get_group_permission(request, group_id, permission_type='exams')
    if not group:
        messages.error(request, "ليس لديك صلاحية لدخول الامتحانات.")
        return redirect('home')
    
    if not is_owner and not group.teacher.has_active_subscription():
        return render(request, 'students/teacher_unavailable.html', {'teacher_name': group.teacher.user.first_name})

    exam_form = ExamForm()
    if request.method == 'POST' and 'exam_submit' in request.POST:
        exam_form = ExamForm(request.POST)
        if exam_form.is_valid():
            exam = exam_form.save(commit=False)
            exam.group = group
            exam.save()
            messages.success(request, "تم إنشاء الامتحان بنجاح!")
            return redirect('exam_manage', exam_id=exam.id)

    exams = group.exams.all().order_by('-created_at')
    pending_count = group.enrollments.filter(is_active=False).count()


    # بحث الامتحانات
    query = request.GET.get('q')
    if query:
        exams = exams.filter(title__icontains=query)

    context = {
        'group': group,
        'exams': exams,
        'exam_form': exam_form,
        'pending_count': pending_count,
        'active_tab': 'exams',
        'is_owner': is_owner
    }
    return render(request, 'teachers/group_exams.html', context)


# ج) تبويب الطلاب (Students)
@login_required
def group_students(request, group_id):
    group, is_owner = get_group_permission(request, group_id, permission_type='students')
    if not group:
        messages.error(request, "ليس لديك صلاحية لدخول صفحة الطلاب.")
        return redirect('home')
    
    if not is_owner and not group.teacher.has_active_subscription():
        return render(request, 'students/teacher_unavailable.html', {'teacher_name': group.teacher.user.first_name})

    # معالجة تسجيل الأداء الفردي
    if request.method == 'POST':
        student_id = request.POST.get('student_id')
        student = get_object_or_404(StudentProfile, id=student_id)
        form = PerformanceForm(request.POST)
        if form.is_valid():
            log = form.save(commit=False)
            log.group = group
            log.student = student
            log.save()
            messages.success(request, f"تم تسجيل الأداء للطالب {student.user.first_name}")
            return redirect('group_students', group_id=group.id)

    enrollments = group.enrollments.filter(is_active=True).select_related('student__user')
    pending_count = group.enrollments.filter(is_active=False).count()
    form = PerformanceForm()


        # كود البحث (ضعه بعد جلب البيانات الأساسية وقبل الـ context)
    query = request.GET.get('q')
    
    if query:
        # 1. بحث المحاضرات
        if 'lectures' in locals():
            lectures = lectures.filter(title__icontains=query)
            
        # 2. بحث الامتحانات
        if 'exams' in locals():
            exams = exams.filter(title__icontains=query)
            
        # 3. بحث الطلاب (والطلبات)
        if 'enrollments' in locals():
            enrollments = enrollments.filter(
                Q(student__user__first_name__icontains=query) |
                Q(student__user__last_name__icontains=query) |
                Q(student__user__phone__icontains=query)
            )
        if 'pending_enrollments' in locals():
            pending_enrollments = pending_enrollments.filter(
                Q(student__user__first_name__icontains=query) | ...
            )

    context = {
        'group': group,
        'enrollments': enrollments,
        'pending_count': pending_count,
        'form': form,
        'active_tab': 'students',
        'is_owner': is_owner
    }
    return render(request, 'teachers/group_students.html', context)


# د) تبويب طلبات الانضمام (Requests)
@login_required
def group_requests(request, group_id):
    group, is_owner = get_group_permission(request, group_id, permission_type='students')
    if not group:
        messages.error(request, "ليس لديك صلاحية لإدارة الطلبات.")
        return redirect('home')
    
    if not is_owner and not group.teacher.has_active_subscription():
        return render(request, 'students/teacher_unavailable.html', {'teacher_name': group.teacher.user.first_name})
    
    if request.method == 'POST':
        enroll_id = request.POST.get('enroll_id')
        action = request.POST.get('action_type')
        enrollment = get_object_or_404(Enrollment, id=enroll_id, group=group)
        
        if action == 'accept':
            enrollment.is_active = True
            enrollment.save()
            send_notification(
        enrollment.student.user,
        "تم قبول طلبك!",
        f"وافق المستر على انضمامك لمجموعة {group.name}. ابدأ التعلم الآن.",
        f"/student/group/{group.id}/"
    )
            messages.success(request, f"تم قبول الطالب {enrollment.student.user.first_name}")
        elif action == 'reject':
            enrollment.delete()
            messages.warning(request, "تم رفض الطلب وحذفه.")
            
        return redirect('group_requests', group_id=group.id)

    pending_enrollments = group.enrollments.filter(is_active=False).select_related('student__user')
    pending_count = pending_enrollments.count()

        # كود البحث (ضعه بعد جلب البيانات الأساسية وقبل الـ context)
    query = request.GET.get('q')
    
    if query:
        # 1. بحث المحاضرات
        if 'lectures' in locals():
            lectures = lectures.filter(title__icontains=query)
            
        # 2. بحث الامتحانات
        if 'exams' in locals():
            exams = exams.filter(title__icontains=query)
            
        # 3. بحث الطلاب (والطلبات)
        if 'enrollments' in locals():
            enrollments = enrollments.filter(
                Q(student__user__first_name__icontains=query) |
                Q(student__user__last_name__icontains=query) |
                Q(student__user__phone__icontains=query)
            )
        if 'pending_enrollments' in locals():
            pending_enrollments = pending_enrollments.filter(
                Q(student__user__first_name__icontains=query) | ...
            )

    context = {
        'group': group,
        'pending_enrollments': pending_enrollments,
        'pending_count': pending_count,
        'active_tab': 'requests',
        'is_owner': is_owner
    }
    return render(request, 'teachers/group_requests.html', context)


# ==========================================
# 3. وظائف إضافية للمجموعة (رصد، استيراد، أكواد، حذف)
# ==========================================

# رصد الدرجات الجماعي
@login_required
def bulk_log(request, group_id):
    group, is_owner = get_group_permission(request, group_id, permission_type='students')
    if not group:
        messages.error(request, "صلاحية غير كافية.")
        return redirect('home')

    if not is_owner and not group.teacher.has_active_subscription():
        return render(request, 'students/teacher_unavailable.html', {'teacher_name': group.teacher.user.first_name})

    enrollments = group.enrollments.filter(is_active=True).select_related('student__user').order_by('student__user__first_name')

    if request.method == 'POST':
        # 1. القيم العامة الموحدة (رقم الحصة + الدرجات العظمى)
        global_session = int(request.POST.get('global_session_number') or 1)
        
        hw_max = int(request.POST.get('global_hw_max') or 10)
        class_max = int(request.POST.get('global_class_max') or 10)
        recit_max = int(request.POST.get('global_recit_max') or 10)
        comp_max = int(request.POST.get('global_comp_max') or 50)
        
        count = 0
        for enroll in enrollments:
            sid = enroll.student.id
            
            # حالة الغياب
            is_absent = request.POST.get(f'is_absent_{sid}') == 'on'
            
            # القيم المدخلة
            hw_val = request.POST.get(f'hw_score_{sid}')
            cls_val = request.POST.get(f'class_score_{sid}')
            rec_val = request.POST.get(f'recit_score_{sid}')
            comp_val = request.POST.get(f'comp_score_{sid}')
            note = request.POST.get(f'note_{sid}')
            
            def clean(val): return int(val) if val and val.strip() else None

            # منطق الحفظ والتصفير
            if is_absent:
                present = False
                hw_score = 0
                class_score = 0
                recitation_score = 0
                # الشامل لا يصفر تلقائياً (نحفظ ما أدخله المعلم أو None)
                comprehensive_score = clean(comp_val)
            else:
                present = True
                hw_score = clean(hw_val)
                class_score = clean(cls_val)
                recitation_score = clean(rec_val)
                comprehensive_score = clean(comp_val)

            # إنشاء السجل
            PerformanceLog.objects.create(
                group=group,
                student=enroll.student,
                session_number=global_session, # رقم الحصة الموحد
                is_present=present,
                homework_score=hw_score, homework_max=hw_max,
                class_exam_score=class_score, class_exam_max=class_max,
                recitation_score=recitation_score, recitation_max=recit_max,
                comprehensive_exam_score=comprehensive_score, comprehensive_exam_max=comp_max,
                note=note or ""
            )
            count += 1
            
        messages.success(request, f"تم رصد الحصة رقم {global_session} لـ {count} طالب بنجاح.")
        return redirect('group_students', group_id=group.id)

    return render(request, 'teachers/bulk_log.html', {'group': group, 'enrollments': enrollments})

# استيراد محتوى (للمعلم فقط)
@login_required
def import_group_content(request, group_id):
    target_group = get_object_or_404(Group, id=group_id, teacher__user=request.user)
    
    if request.method == 'POST':
        # استقبال القوائم المختارة
        selected_lecture_ids = request.POST.getlist('lecture_ids')
        selected_exam_ids = request.POST.getlist('exam_ids')
        
        count_lec = 0
        count_exam = 0

        # أ) نسخ المحاضرات
        if selected_lecture_ids:
            source_lectures = Lecture.objects.filter(id__in=selected_lecture_ids)
            for old_lec in source_lectures:
                # التحقق من الملكية
                if old_lec.group and old_lec.group.teacher == target_group.teacher:
                    Lecture.objects.create(
                        group=target_group,
                        title=old_lec.title,
                        video_link=old_lec.video_link,
                        description=old_lec.description,
                        is_active=True
                    )
                    count_lec += 1

        # ب) نسخ الامتحانات
        if selected_exam_ids:
            source_exams = Exam.objects.filter(id__in=selected_exam_ids)
            for old_exam in source_exams:
                if old_exam.group and old_exam.group.teacher == target_group.teacher:
                    new_exam = Exam.objects.create(
                        group=target_group,
                        title=old_exam.title,
                        description=old_exam.description,
                        duration_minutes=old_exam.duration_minutes,
                        is_active=False
                    )
                    for q in old_exam.questions.all():
                        Question.objects.create(
                            exam=new_exam,
                            text=q.text,
                            image=q.image,
                            option_a=q.option_a, option_b=q.option_b,
                            option_c=q.option_c, option_d=q.option_d,
                            correct_answer=q.correct_answer,
                            marks=q.marks
                        )
                    count_exam += 1

        messages.success(request, f"تم استيراد {count_lec} محاضرة و {count_exam} امتحان بنجاح.")
        return redirect('group_detail', group_id=target_group.id)

    return redirect('group_detail', group_id=target_group.id)

# إدارة الأكواد
@login_required
def manage_video_codes(request, lecture_id):
    lecture = get_object_or_404(Lecture, id=lecture_id)
    if not lecture.group:
        messages.error(request, "هذه المحاضرة تابعة لحزمة أونلاين ولا تستخدم أكواد فيديو.")
        pkg = lecture.packages.first()
        if pkg: return redirect('teacher_package_detail', package_id=pkg.id)
        return redirect('home')

    group, is_owner = get_group_permission(request, lecture.group.id, permission_type='videos')
    
    if not group:
        messages.error(request, "صلاحية غير كافية.")
        return redirect('teacher_dashboard')
    
    if not is_owner and not group.teacher.has_active_subscription():
        return render(request, 'students/teacher_unavailable.html', {'teacher_name': group.teacher.user.first_name})

    if request.method == 'POST':
        try:
            amt = int(request.POST.get('amount', 10))
            views_limit = int(request.POST.get('views_limit', 1)) # <--- استقبال عدد مرات الفتح
            
            # حماية من الأرقام الكبيرة
            if amt > 100: amt = 100
            
            created_count = 0
            for _ in range(amt):
                while True:
                    code = VideoCode.generate_random_code()
                    if not VideoCode.objects.filter(code=code).exists():
                        VideoCode.objects.create(
                            lecture=lecture, 
                            code=code,
                            max_views=views_limit # <--- حفظ العدد
                        )
                        created_count += 1
                        break
            
            messages.success(request, f"تم توليد {created_count} كود (صلاحية {views_limit} مشاهدات).")
        except ValueError:
            messages.error(request, "أدخل أرقاماً صحيحة.")
            
        return redirect('manage_video_codes', lecture_id=lecture.id)

    codes = lecture.codes.all().order_by('is_used', '-id')
    unused_count = lecture.codes.filter(is_used=False).count()
    
    context = {
        'lecture': lecture, 
        'group': group, 
        'codes': codes, 
        'unused_count': unused_count, 
        'is_owner': is_owner
    }
    return render(request, 'teachers/manage_codes.html', context)

# حذف محاضرة
@login_required
def delete_lecture(request, lecture_id):
    lecture = get_object_or_404(Lecture, id=lecture_id)
    if lecture.group:
        group, is_owner = get_group_permission(request, lecture.group.id, permission_type='videos')
        if not group: return redirect('home')
        if not is_owner and not group.teacher.has_active_subscription():
            return render(request, 'students/teacher_unavailable.html', {'teacher_name': group.teacher.user.first_name})
        redirect_url = reverse('group_detail', args=[group.id])
    else:
        pkg = lecture.packages.first()
        if pkg:
            package, is_owner = get_package_permission(request, pkg.id, permission_type='videos')
            if not package: return redirect('home')
            redirect_url = reverse('teacher_package_detail', args=[pkg.id])
        else:
            return redirect('home')
            
    lecture.delete()
    messages.success(request, "تم حذف المحاضرة.")
    return redirect(redirect_url)

# تعديل وحذف المجموعة
@login_required
def edit_group(request, group_id):
    group = get_object_or_404(Group, id=group_id, teacher__user=request.user)
    if request.method == 'POST':
        form = GroupForm(request.POST, instance=group)
        if form.is_valid(): form.save(); return redirect('teacher_dashboard')
    else: form = GroupForm(instance=group)
    return render(request, 'teachers/edit_group.html', {'form': form, 'group': group})

@login_required
def delete_group(request, group_id):
    group = get_object_or_404(Group, id=group_id, teacher__user=request.user)
    if request.method == 'POST':
        group.delete()
        messages.success(request, "تم حذف المجموعة.")
        return redirect('teacher_dashboard')
    return render(request, 'teachers/confirm_delete_group.html', {'group': group})


# ==========================================
# 4. إعدادات المعلم (Settings)
# ==========================================
@login_required
def teacher_settings(request):
    try: teacher = request.user.teacher_profile
    except: return redirect('home')
    
    if request.method == 'POST':
        form = TeacherSettingsForm(request.POST, request.FILES, instance=teacher)
        if form.is_valid():
            form.save()
            request.user.first_name = form.cleaned_data['first_name']
            request.user.last_name = form.cleaned_data['last_name']
            request.user.save()
            messages.success(request, "تم تحديث البيانات.")
            return redirect('teacher_settings')
    else:
        form = TeacherSettingsForm(instance=teacher, initial={'first_name': request.user.first_name, 'last_name': request.user.last_name})
    return render(request, 'teachers/settings.html', {'form': form})

@login_required
def delete_teacher_account(request):
    if request.method == 'POST' and request.user.role == 'teacher':
        request.user.delete()
        messages.info(request, "تم حذف حسابك.")
        return redirect('home')
    return redirect('teacher_settings')


# ==========================================
# 5. إدارة المساعدين (Manage Assistants)
# ==========================================
@login_required
def manage_assistants(request):
    try: teacher = request.user.teacher_profile
    except: return redirect('home')

    if request.method == 'POST':
        job_id = request.POST.get('job_id')
        action = request.POST.get('action')
        job = get_object_or_404(AssistantJob, id=job_id, teacher=teacher)
        
        if action == 'accept':
            # التحقق من عدد المساعدين الحاليين
            current_assistants = teacher.assistants_jobs.filter(is_active=True).count()
            limit = teacher.current_plan.assistant_limit if teacher.current_plan else 2
            
            if current_assistants >= limit:
                messages.error(request, f"لا يمكن قبول المزيد. حد باقتك {limit} مساعدين.")
            else:
                job.is_active = True
                job.save()
                messages.success(request, "تم قبول المساعد.")    

        elif action in ['reject', 'delete']:
            job.delete(); messages.warning(request, "تم الحذف.")
            
        elif action == 'update_permissions':
            form = AssistantPermissionsForm(request.POST, instance=job)
            if form.is_valid(): form.save(); messages.success(request, "تم تحديث الصلاحيات.")
        
        return redirect('manage_assistants')

    active = teacher.assistants_jobs.filter(is_active=True).select_related('assistant__user')
    pending = teacher.assistants_jobs.filter(is_active=False).select_related('assistant__user')
    permissions_form = AssistantPermissionsForm() # للعرض فقط

    return render(request, 'teachers/manage_assistants.html', {
        'active_assistants': active, 'pending_requests': pending, 'permissions_form': permissions_form
    })


# ==========================================
# 6. المدفوعات والاشتراك (Paymob)
# ==========================================
@login_required
def subscription_info(request):
    try: teacher = request.user.teacher_profile
    except: return redirect('home')
    plans = SubscriptionPlan.objects.all().order_by('price')
    return render(request, 'teachers/subscription.html', {'teacher': teacher, 'is_active': teacher.has_active_subscription(), 'days_left': teacher.days_remaining(),'plans':plans})





from .models import SubscriptionPlan
from django.urls import reverse

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

# استيراد مودلز الطلاب والحزم
from students.models import PackageEnrollment
from teachers.models import CoursePackage # لو مش مستورد

# تأكد من استيراد Wallet و PackageEnrollment
from students.models import PackageEnrollment
from .models import Wallet, CoursePackage, SubscriptionPlan, PaymentTransaction

@login_required
def payment_callback(request):
    print("--- UNIFIED PAYMOB CALLBACK ---")
    
    success = request.GET.get('success')
    pending = request.GET.get('pending')
    
    # 1. حالة الفشل
    if success != "true" and pending != "true":
        error_msg = request.GET.get('data.message', 'Unknown Error')
        messages.error(request, f"فشلت عملية الدفع: {error_msg}")
        # يمكن إنشاء صفحة فشل خاصة بالطالب لو أردت، لكن الحالية تكفي
        return render(request, 'teachers/payment_failed.html')

    # 2. حالة النجاح (نتفرع حسب الدور)
    try:
        user = request.user
        paymob_id = str(request.GET.get('id') or request.GET.get('order') or "Unknown")

        # ==========================
        # أ) لو المستخدم "معلم" (تجديد اشتراك)
        # ==========================
        if user.role == 'teacher':
            try:
                teacher = user.teacher_profile
            except:
                return redirect('home')
            
            # تحديث الباقة
            plan_id = request.session.get('selected_plan_id')
            if plan_id:
                try:
                    new_plan = SubscriptionPlan.objects.get(id=plan_id)
                    teacher.current_plan = new_plan
                except SubscriptionPlan.DoesNotExist: pass
            
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
            
            # 1. تفعيل الحزمة (إنشاء أو تحديث الاشتراك)
            enrollment, created = PackageEnrollment.objects.get_or_create(
                student=student,
                package=package,
                defaults={'is_paid': True}
            )
            
            if not created and not enrollment.is_paid:
                enrollment.is_paid = True
                enrollment.save()
            
            # 2. ++++++ إضافة الرصيد لمحفظة المعلم ++++++
            wallet, _ = Wallet.objects.get_or_create(teacher=package.teacher)
            
            # حساب حصة المعلم (80%)
            price = float(package.price)
            teacher_share = price * 0.80
            
            # تحديث الرصيد
            wallet.balance = float(wallet.balance) + teacher_share
            wallet.total_earnings = float(wallet.total_earnings) + teacher_share
            wallet.save()
            
            print(f"💰 Wallet updated for {package.teacher.user.username}: +{teacher_share} EGP")
            # +++++++++++++++++++++++++++++++++++++++++++

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


from exams.models import ExamResult



from .models import Group
@login_required
def group_ranking(request, group_id):
    group, is_owner = get_group_permission(request, group_id, permission_type='students')
    if not group: return redirect('home')

    from core.utils import get_optimized_group_leaderboard
    leaderboard = get_optimized_group_leaderboard(group)
    
    pending_count = group.enrollments.filter(is_active=False).count()

    return render(request, 'teachers/group_ranking.html', {
        'group': group,
        'leaderboard': leaderboard,
        'active_tab': 'ranking',
        'pending_count': pending_count,
        'is_owner': is_owner
    })

@login_required
def student_full_log(request, group_id, student_id):
    group, is_owner = get_group_permission(request, group_id, permission_type='students')
    if not group: return redirect('home')

    student = get_object_or_404(StudentProfile, id=student_id)
    
    # معالجة الحذف
    if request.method == 'POST' and request.POST.get('action') == 'delete_log':
        log_id = request.POST.get('log_id')
        PerformanceLog.objects.get(id=log_id, group=group).delete()
        messages.success(request, "تم حذف السجل.")
        return redirect('student_full_log', group_id=group.id, student_id=student.id)

    # جلب السجلات
    logs = PerformanceLog.objects.filter(student=student, group=group).order_by('-date')

        # +++++ فلتر الشهر +++++
    selected_month = request.GET.get('month')
    if selected_month:
        logs = logs.filter(date__month=selected_month)
    # ++++++++++++++++++++++
    
    return render(request, 'teachers/student_full_log.html', {
        'group': group,
        'student': student,
        'logs': logs,
        'is_owner': is_owner,
        'selected_month': selected_month,
    })

@login_required
def toggle_lecture_status(request, lecture_id):
    lecture = get_object_or_404(Lecture, id=lecture_id)
    
    if lecture.group:
        group, is_owner = get_group_permission(request, lecture.group.id, permission_type='videos')
        if not group: return redirect('home')
        redirect_url = reverse('group_detail', args=[group.id])
    else:
        pkg = lecture.packages.first()
        if pkg:
            package, is_owner = get_package_permission(request, pkg.id, permission_type='videos')
            if not package: return redirect('home')
            redirect_url = reverse('teacher_package_detail', args=[pkg.id])
        else:
            return redirect('home')

    lecture.is_active = not lecture.is_active
    lecture.save()
    return redirect(redirect_url)



@login_required
def create_package(request):
    teacher = None
    
    # 1. تحديد المعلم بناءً على الدور
    if request.user.role == 'teacher':
        try:
            teacher = request.user.teacher_profile
        except:
            return redirect('complete_profile')
            
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


from .models import Wallet, WithdrawRequest

@login_required
def teacher_wallet(request):
    try: teacher = request.user.teacher_profile
    except: return redirect('home')
    
    wallet, created = Wallet.objects.get_or_create(teacher=teacher)
    
    if request.method == 'POST':
        amount = float(request.POST.get('amount'))
        method = request.POST.get('method')
        details = request.POST.get('details')
        
        if amount > float(wallet.balance):
            messages.error(request, "رصيدك الحالي لا يكفي.")
        elif amount < 50:
            messages.error(request, "الحد الأدنى للسحب 50 جنيه.")
        else:
            # خصم الرصيد مؤقتاً وإنشاء الطلب
            wallet.balance = float(wallet.balance) - amount
            wallet.save()
            
            WithdrawRequest.objects.create(
                wallet=wallet, amount=amount, method=method, details=details
            )
            messages.success(request, "تم إرسال طلب السحب بنجاح.")
            return redirect('teacher_wallet')

    withdraws = wallet.withdrawals.all().order_by('-created_at')
    return render(request, 'teachers/wallet.html', {'wallet': wallet, 'withdraws': withdraws})

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
    from core.utils import get_optimized_package_leaderboard
    leaderboard = get_optimized_package_leaderboard(package)

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
        
        # أ) استيراد المحاضرات (ربط فقط لأن الفيديو واحد)
        if selected_lecture_ids:
            lectures = Lecture.objects.filter(id__in=selected_lecture_ids)
            package.lectures.add(*lectures)
            
        # ب) استيراد الامتحانات (نسخ عميق Deep Copy)
        if selected_exam_ids:
            source_exams = Exam.objects.filter(id__in=selected_exam_ids)
            
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



# 1. إضافة للمجموعة
@login_required
def add_pdf_to_group(request, group_id):
    group, is_owner = get_group_permission(request, group_id, permission_type='videos') # نستخدم نفس صلاحية الفيديو
    if not group: return redirect('home')
    
    if request.method == 'POST':
        form = PDFForm(request.POST)
        if form.is_valid():
            pdf = form.save(commit=False)
            pdf.group = group
            pdf.save()
            messages.success(request, "تم إضافة الملف.")
    return redirect('group_detail', group_id=group.id)

# 2. إضافة للحزمة (يدوي)
@login_required
def add_pdf_to_package(request, package_id):
    package, is_owner = get_package_permission(request, package_id, permission_type='videos')
    if not package: return redirect('home')
    
    if request.method == 'POST':
        form = PDFForm(request.POST)
        if form.is_valid():
            pdf = form.save(commit=False)
            pdf.group = None # ملف حر
            pdf.save()
            package.pdfs.add(pdf)
            messages.success(request, "تم إضافة الملف للحزمة.")
    return redirect('teacher_package_detail', package_id=package.id)

# 3. حذف PDF
@login_required
def delete_pdf(request, pdf_id):
    pdf = get_object_or_404(PDFFile, id=pdf_id)
    if pdf.group:
        group, is_owner = get_group_permission(request, pdf.group.id, permission_type='videos')
        if not group: return redirect('home')
    else:
        pkg = pdf.packages.first()
        if pkg:
            package, is_owner = get_package_permission(request, pkg.id, permission_type='videos')
            if not package: return redirect('home')
        else:
            return redirect('home')
    
    # تحديد مكان العودة
    redirect_url = 'home'
    if pdf.group:
        redirect_url = reverse('group_detail', args=[pdf.group.id])
    else:
        pkg = pdf.packages.first()
        if pkg: redirect_url = reverse('teacher_package_detail', args=[pkg.id])
    
    pdf.delete()
    messages.success(request, "تم الحذف.")
    return redirect(redirect_url)

# ==========================================
# صفحة ملفات المجموعة (للمعلم)
# ==========================================
@login_required
def group_files_teacher(request, group_id):
    group, is_owner = get_group_permission(request, group_id, permission_type='videos')
    if not group: return redirect('home')
    
    if not is_owner and not group.teacher.has_active_subscription():
        return render(request, 'students/teacher_unavailable.html', {'teacher_name': group.teacher.user.first_name})

    pending_count = group.enrollments.filter(is_active=False).count()

    return render(request, 'teachers/group_files.html', {
        'group': group,
        'active_tab': 'files',
        'is_owner': is_owner,
        'pending_count': pending_count
    })

# ==========================================
# صفحة ملفات الحزمة (للمعلم)
# ==========================================
@login_required
def package_files_teacher(request, package_id):
    package = get_object_or_404(CoursePackage, id=package_id)
    
    # التحقق من الملكية
    is_owner = False
    if package.teacher.user == request.user:
        is_owner = True
    elif request.user.role == 'assistant':
        job = AssistantJob.objects.filter(assistant__user=request.user, teacher=package.teacher, is_active=True).first()
        if job and job.can_manage_packages:
            is_owner = False
        else:
            return redirect('home')
    else:
        return redirect('home')

    return render(request, 'teachers/package_dashboard/files.html', {
        'package': package,
        'active_tab': 'files',
        'is_owner': is_owner
    })


@login_required
def remove_student_from_group(request, group_id, student_id):
    # التحقق من الصلاحية (معلم أو مساعد بصلاحية طلاب)
    group, is_owner = get_group_permission(request, group_id, permission_type='students')
    if not group: return redirect('home')

    student = get_object_or_404(StudentProfile, id=student_id)
    
    # الحذف
    Enrollment.objects.filter(student=student, group=group).delete()
    
    messages.success(request, f"تم حذف الطالب {student.user.first_name} من المجموعة.")
    return redirect('group_students', group_id=group.id)


from rest_framework.decorators import api_view, permission_classes
from rest_framework.response import Response
from rest_framework.permissions import AllowAny
from .serializers import TeacherSerializer, PackageSerializer

# 1. API لجلب كل المدرسين (للصفحة الرئيسية في التطبيق)
@api_view(['GET'])
@permission_classes([AllowAny]) # مسموح لأي حد (حتى لو مش مسجل)
def api_all_teachers(request):
    teachers = TeacherProfile.objects.all().order_by('-id')
    serializer = TeacherSerializer(teachers, many=True)
    return Response(serializer.data)

# 2. API لجلب الحزم
@api_view(['GET'])
@permission_classes([AllowAny])
def api_all_packages(request):
    packages = CoursePackage.objects.filter(is_active=True)
    serializer = PackageSerializer(packages, many=True)
    return Response(serializer.data)
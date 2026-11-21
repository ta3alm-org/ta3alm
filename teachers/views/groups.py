"""teachers.views.groups
Extracted from teachers/views.py.
"""

from django.shortcuts import (
    render,
    redirect,
    get_object_or_404,
)
from django.contrib.auth.decorators import login_required
from django.contrib import messages
from django.db.models import Q
from teachers.models import (
    Group,
    Lecture,
    VideoCode,
)
from accounts.models import StudentProfile
from exams.models import (
    Exam,
    Question,
)
from students.models import (
    Enrollment,
    PerformanceLog,
)
from django.urls import reverse
from teachers.forms import (
    GroupForm,
    LectureForm,
)
from exams.forms import ExamForm
from students.forms import PerformanceForm
from core.utils import get_optimized_group_leaderboard

from teachers.views.permissions import (
    get_group_permission,
    get_package_permission,
)


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


    # بحث الطلاب
    query = request.GET.get('q')
    if query:
        enrollments = enrollments.filter(
            Q(student__user__first_name__icontains=query) |
            Q(student__user__last_name__icontains=query) |
            Q(student__user__phone__icontains=query)
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
            messages.success(request, f"تم قبول الطالب {enrollment.student.user.first_name}")
        elif action == 'reject':
            enrollment.delete()
            messages.warning(request, "تم رفض الطلب وحذفه.")
            
        return redirect('group_requests', group_id=group.id)

    pending_enrollments = group.enrollments.filter(is_active=False).select_related('student__user')
    pending_count = pending_enrollments.count()

    # بحث الطلبات
    query = request.GET.get('q')
    if query:
        pending_enrollments = pending_enrollments.filter(
            Q(student__user__first_name__icontains=query) |
            Q(student__user__last_name__icontains=query) |
            Q(student__user__phone__icontains=query)
        )

    context = {
        'group': group,
        'pending_enrollments': pending_enrollments,
        'pending_count': pending_count,
        'active_tab': 'requests',
        'is_owner': is_owner
    }
    return render(request, 'teachers/group_requests.html', context)


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


def calculate_leaderboard(group):
    return get_optimized_group_leaderboard(group)


@login_required
def group_ranking(request, group_id):
    group, is_owner = get_group_permission(request, group_id, permission_type='students')
    if not group: return redirect('home')

    leaderboard = calculate_leaderboard(group)
    
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
def remove_student_from_group(request, group_id, student_id):
    # التحقق من الصلاحية (معلم أو مساعد بصلاحية طلاب)
    group, is_owner = get_group_permission(request, group_id, permission_type='students')
    if not group: return redirect('home')

    student = get_object_or_404(StudentProfile, id=student_id)
    
    # الحذف
    Enrollment.objects.filter(student=student, group=group).delete()
    
    messages.success(request, f"تم حذف الطالب {student.user.first_name} من المجموعة.")
    return redirect('group_students', group_id=group.id)

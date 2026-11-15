from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth.decorators import login_required
from django.contrib import messages
from .models import Exam, Question
from .forms import QuestionForm
from teachers.views import get_group_permission # <--- استيراد الدالة
from django import forms
from django.db.models import Q
from assistants.models import AssistantJob
from students.models import PackageExamResult
from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth.decorators import login_required
from django.contrib import messages
from django.db.models import Q
from .models import Exam, Question, ExamResult
from .forms import QuestionForm
from teachers.models import CoursePackage
from students.models import PackageExamResult # هام جداً
from assistants.models import AssistantJob
from teachers.views import get_group_permission # استيراد دالة الصلاحيات

@login_required
def exam_manage(request, exam_id):
    exam = get_object_or_404(Exam, id=exam_id)
    
    # متغيرات التحكم
    is_owner = False
    back_url = None
    back_id = None
    teacher = None
    results = []

    # ==========================================
    # 1. تحديد السياق (مجموعة أم حزمة؟)
    # ==========================================
    if exam.group:
        # أ) حالة امتحان مجموعة (Offline)
        group_obj, is_owner = get_group_permission(request, exam.group.id, permission_type='exams')
        if not group_obj:
            messages.error(request, "صلاحية غير كافية.")
            return redirect('home')
        
        teacher = exam.group.teacher
        back_url = 'group_exams'
        back_id = exam.group.id
        
        # نتائج المجموعة
        results = exam.results.all().select_related('student__user').order_by('-score')

    else:
        # ب) حالة امتحان حزمة (Online)
        package = exam.packages.first()
        
        if package:
            teacher = package.teacher
            back_url = 'teacher_package_detail'
            back_id = package.id
            
            # التحقق من الملكية
            if teacher.user == request.user:
                is_owner = True
            elif request.user.role == 'assistant':
                job = AssistantJob.objects.filter(assistant__user=request.user, teacher=teacher, is_active=True).first()
                if job and job.can_manage_packages:
                    is_owner = False
                else:
                    messages.error(request, "ليس لديك صلاحية إدارة الحزم.")
                    return redirect('home')
            else:
                return redirect('home')
            
            # نتائج الحزمة (من الجدول المنفصل)
            results = PackageExamResult.objects.filter(exam=exam).select_related('student__user').order_by('-score')
        else:
            return redirect('home')

    # ==========================================
    # 2. التحقق من الاشتراك (للمساعد)
    # ==========================================
    if not is_owner and teacher and not teacher.has_active_subscription():
        return render(request, 'students/teacher_unavailable.html', {'teacher_name': teacher.user.first_name})

    # ==========================================
    # 3. التحقق من صلاحية الصور (الباقة)
    # ==========================================
    allow_images = True

    # ==========================================
    # 4. معالجة إضافة سؤال (POST)
    # ==========================================
    if request.method == 'POST':
        form = QuestionForm(request.POST, request.FILES)
        if form.is_valid():
            question = form.save(commit=False)
            question.exam = exam
            
            # معالجة الصورة
            if 'image' in request.FILES:
                if allow_images:
                    question.image = request.FILES['image']
                else:
                    # لو الباقة لا تسمح، نتجاهل الصورة وننبه المستخدم
                    messages.warning(request, "تم حفظ السؤال، ولكن تم تجاهل الصورة لأن باقتك الحالية لا تدعم ذلك.")
            
            question.save()
            
            # رسالة نجاح (إذا لم يكن هناك تحذير سابق)
            storage = messages.get_messages(request)
            if not storage: 
                messages.success(request, "تم إضافة السؤال بنجاح.")
                
            return redirect('exam_manage', exam_id=exam.id)
    else:
        form = QuestionForm()

    # ==========================================
    # 5. البحث في النتائج
    # ==========================================
    q = request.GET.get('q')
    if q:
        results = results.filter(
            Q(student__user__first_name__icontains=q) |
            Q(student__user__last_name__icontains=q) |
            Q(student__user__phone__icontains=q)
        )

    context = {
        'exam': exam,
        'questions': exam.questions.all(),
        'results': results,
        'form': form,
        'is_owner': is_owner,
        'back_url': back_url,
        'back_id': back_id,
        'allow_images': allow_images # هام جداً للمودال
    }
    return render(request, 'exams/manage.html', context)

@login_required
def add_question_page(request, exam_id):
    exam = get_object_or_404(Exam, id=exam_id)
    
    # تحديد المعلم
    teacher = None
    if exam.group:
        teacher = exam.group.teacher
        group_obj, is_owner = get_group_permission(request, exam.group.id, permission_type='exams')
        if not group_obj: return redirect('home')
    else:
        pkg = exam.packages.first()
        if pkg: teacher = pkg.teacher
        # (يمكنك إضافة نفس التحقق من الصلاحيات هنا للحزم)

    # التحقق من صلاحية الصور
    allow_images = True

    if request.method == 'POST':
        form = QuestionForm(request.POST, request.FILES)
        if form.is_valid():
            question = form.save(commit=False)
            question.exam = exam
            
            # حفظ الصورة فقط لو مسموح
            if 'image' in request.FILES:
                if allow_images:
                    question.image = request.FILES['image']
                else:
                    messages.warning(request, "تم تجاهل الصورة لأن باقتك لا تسمح.")
            
            question.save()
            messages.success(request, "تم إضافة السؤال بنجاح.")
            return redirect('exam_manage', exam_id=exam.id)
    else:
        form = QuestionForm()

    return render(request, 'exams/add_question.html', {
        'form': form, 
        'exam': exam, 
        'allow_images': allow_images
    })


@login_required
def edit_question_page(request, question_id):
    question = get_object_or_404(Question, id=question_id)
    exam = question.exam
    
    # تحديد المعلم
    teacher = None
    if exam.group:
        teacher = exam.group.teacher
        group_obj, is_owner = get_group_permission(request, exam.group.id, permission_type='exams')
        if not group_obj: return redirect('home')
    else:
        pkg = exam.packages.first()
        if pkg: teacher = pkg.teacher

    # التحقق من صلاحية الصور
    allow_images = True

    if request.method == 'POST':
        form = QuestionForm(request.POST, request.FILES, instance=question)
        if form.is_valid():
            # 1. معالجة حذف الصورة (Checkbox)
            if request.POST.get('image-clear') == 'on':
                question.image = None
            
            # 2. معالجة رفع صورة جديدة
            if 'image' in request.FILES:
                if allow_images:
                    question.image = request.FILES['image']
                else:
                    messages.warning(request, "تم تجاهل الصورة الجديدة.")
            
            # 3. حفظ باقي البيانات
            form.save() # سيحفظ التغييرات (بما فيها الحذف إذا تم تعيينه لـ None)
            
            messages.success(request, "تم تحديث السؤال.")
            return redirect('exam_manage', exam_id=exam.id)
    else:
        form = QuestionForm(instance=question)

    return render(request, 'exams/edit_question.html', {
        'form': form, 
        'question': question, 
        'exam': exam,
        'allow_images': allow_images
    })# 1. تفعيل أو إيقاف الامتحان


@login_required
def toggle_exam_status(request, exam_id):
    exam = get_object_or_404(Exam, id=exam_id)
    
    # 1. التحقق من الصلاحيات والاشتراك
    is_allowed = False
    
    # أ) امتحان مجموعة
    if exam.group:
        group_obj, is_owner = get_group_permission(request, exam.group.id, permission_type='exams')
        if group_obj:
            if not is_owner and not group_obj.teacher.has_active_subscription():
                return render(request, 'students/teacher_unavailable.html', {'teacher_name': group_obj.teacher.user.first_name})
            is_allowed = True
            
    # ب) امتحان حزمة
    else:
        package = exam.packages.first()
        if package:
            # التحقق من المالك أو المساعد
            if package.teacher.user == request.user:
                is_allowed = True
            elif request.user.role == 'assistant':
                job = AssistantJob.objects.filter(assistant__user=request.user, teacher=package.teacher, can_manage_packages=True).first()
                if job: is_allowed = True
            
            # التحقق من الاشتراك
            if is_allowed and package.teacher.user != request.user and not package.teacher.has_active_subscription():
                return render(request, 'students/teacher_unavailable.html', {'teacher_name': package.teacher.user.first_name})

    if not is_allowed:
        messages.error(request, "ليس لديك صلاحية لتعديل حالة الامتحان.")
        return redirect('home')

    # 2. تنفيذ التغيير
    exam.is_active = not exam.is_active
    exam.save()
    
    status = "تفعيل" if exam.is_active else "إغلاق"
    messages.success(request, f"تم {status} الامتحان بنجاح.")
    return redirect('exam_manage', exam_id=exam.id)


# 2. حذف الامتحان بالكامل
@login_required
def delete_exam(request, exam_id):
    exam = get_object_or_404(Exam, id=exam_id)
    group_id = exam.group.id # نحفظ الرقم للعودة
    
    # التحقق من الصلاحية
    group_obj, is_owner = get_group_permission(request, group_id, permission_type='exams')
    
    # ملاحظة: قد ترغب في منع المساعد من الحذف النهائي، والسماح للمالك فقط
    # لو عايز تمنع المساعد: if not is_owner: return redirect...
    # لكن حالياً سنسمح له طالما يملك صلاحية الامتحانات
    
    if not group_obj:
        messages.error(request, "ليس لديك صلاحية لحذف الامتحان.")
        return redirect('home')

    if not is_owner and not group_obj.teacher.has_active_subscription():
        return render(request, 'students/teacher_unavailable.html', {'teacher_name': group_obj.teacher.user.first_name})

    # تنفيذ الحذف
    exam.delete()
    messages.success(request, "تم حذف الامتحان نهائياً.")
    return redirect('group_exams', group_id=group_id) # العودة لصفحة الامتحانات
# 3. حذف سؤال معين
@login_required
def delete_question(request, question_id):
    question = get_object_or_404(Question, id=question_id)
    exam = question.exam
    
    # تحقق من الصلاحية
    group_obj, is_owner = get_group_permission(request, exam.group.id, permission_type='exams')
    if not group_obj:
        return redirect('home')

    question.delete()
    messages.success(request, "تم حذف السؤال.")
    return redirect('exam_manage', exam_id=exam.id)

# 4. تعديل سؤال (يحتاج صفحة خاصة)
@login_required
def edit_question(request, question_id):
    # جلب السؤال
    question = get_object_or_404(Question, id=question_id)
    exam = question.exam
    
    # 1. التحقق من الصلاحية (نطلب صلاحية exams)
    # لاحظ: نرسل exam.group.id
    group_obj, is_owner = get_group_permission(request, exam.group.id, permission_type='exams')
    
    if not group_obj:
        messages.error(request, "ليس لديك صلاحية لتعديل هذا السؤال.")
        return redirect('home')

    # 2. التحقق من الاشتراك (للمساعد)
    if not is_owner and not group_obj.teacher.has_active_subscription():
        return render(request, 'students/teacher_unavailable.html', {
            'teacher_name': group_obj.teacher.user.first_name
        })

    # 3. معالجة التعديل (POST)
    if request.method == 'POST':
        form = QuestionForm(request.POST, request.FILES, instance=question)
        if form.is_valid():
            if request.POST.get('image-clear') == 'on':
                question.image = None
            form.save()
            messages.success(request, "تم تعديل السؤال بنجاح.")
            return redirect('exam_manage', exam_id=exam.id)
    else:
        form = QuestionForm(instance=question)

        # تحديد المعلم للتحقق من الباقة
    teacher = None
    if exam.group:
        teacher = exam.group.teacher
    else:
        pkg = exam.packages.first()
        if pkg: teacher = pkg.teacher

    allow_images = True

    # تمرير المتغير للكونتكس
    
        
    return render(request, 'exams/edit_question.html', {'form': form, 'question': question,'allow_images': allow_images})


# في exams/views.py

@login_required
def exam_manage(request, exam_id):
    exam = get_object_or_404(Exam, id=exam_id)
    
    # 1. تحديد المالك والصلاحيات ومصدر العودة
    is_owner = False
    back_url = None
    back_id = None
    teacher = None
    results = []

    # أ) حالة امتحان مجموعة
    if exam.group:
        group_obj, is_owner = get_group_permission(request, exam.group.id, permission_type='exams')
        if not group_obj:
            messages.error(request, "صلاحية غير كافية.")
            return redirect('home')
        
        teacher = exam.group.teacher
        back_url = 'group_exams'
        back_id = exam.group.id
        results = exam.results.all().select_related('student__user').order_by('-score')

    # ب) حالة امتحان حزمة
    else:
        package = exam.packages.first()
        if package:
            teacher = package.teacher
            back_url = 'teacher_package_detail'
            back_id = package.id
            
            if teacher.user == request.user:
                is_owner = True
            elif request.user.role == 'assistant':
                job = AssistantJob.objects.filter(assistant__user=request.user, teacher=teacher, is_active=True).first()
                if job and job.can_manage_packages:
                    is_owner = False
                else:
                    return redirect('home')
            else:
                return redirect('home')
            
            results = PackageExamResult.objects.filter(exam=exam).select_related('student__user').order_by('-score')
        else:
            return redirect('home')

    # 2. التحقق من الاشتراك
    if not is_owner and teacher and not teacher.has_active_subscription():
        return render(request, 'students/teacher_unavailable.html', {'teacher_name': teacher.user.first_name})

    # 3. تحديد صلاحية الصور
    allow_images = True

    # 4. معالجة إضافة الأسئلة (من المودال في نفس الصفحة - اختياري)
    form = QuestionForm() # للعرض فقط، الإضافة الفعلية في الصفحة المنفصلة

    # البحث في النتائج
    q = request.GET.get('q')
    if q:
        results = results.filter(
            Q(student__user__first_name__icontains=q) |
            Q(student__user__last_name__icontains=q)
        )

    context = {
        'exam': exam,
        'questions': exam.questions.all(),
        'results': results,
        'form': form,
        'is_owner': is_owner,
        'back_url': back_url,
        'back_id': back_id,
        'allow_images': allow_images # هام للمودال لو استخدمته
    }
    return render(request, 'exams/manage.html', context)


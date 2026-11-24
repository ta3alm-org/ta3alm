from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth.decorators import login_required
from django.contrib import messages
from django.db.models import Q

from .models import Exam, Question
from .forms import QuestionForm
from assistants.models import AssistantJob
from students.models import PackageExamResult
from teachers.views import get_group_permission
from teachers.views.permissions import is_platform_content_admin


def _get_exam_permission(request, exam):
    """
    يتحقق من صلاحية المعلم أو المساعد لإدارة الامتحان (سواء كان امتحان مجموعة أو امتحان باقة).
    يُرجع: (allowed, is_owner, teacher, back_url, back_id, sub_expired)
    """
    if exam.group:
        group_obj, is_owner = get_group_permission(request, exam.group.id, permission_type='exams')
        if not group_obj:
            return False, False, None, 'home', None, False
        teacher = exam.group.teacher
        sub_expired = bool(not is_owner and teacher and not teacher.has_active_subscription())
        return True, is_owner, teacher, 'group_exams', exam.group.id, sub_expired

    package = exam.packages.first()
    if not package:
        return False, False, None, 'home', None, False

    teacher = package.teacher
    is_owner = False
    if is_platform_content_admin(request.user):
        is_owner = True
    elif teacher.user == request.user:
        is_owner = True
    elif getattr(request.user, 'role', '') == 'assistant':
        job = AssistantJob.objects.filter(
            assistant__user=request.user,
            teacher=teacher,
            is_active=True,
            can_manage_packages=True,
        ).first()
        if not job:
            return False, False, None, 'home', None, False
    else:
        return False, False, None, 'home', None, False

    sub_expired = bool(not is_owner and teacher and not teacher.has_active_subscription())
    return True, is_owner, teacher, 'teacher_package_detail', package.id, sub_expired


@login_required
def exam_manage(request, exam_id):
    exam = get_object_or_404(Exam, id=exam_id)
    allowed, is_owner, teacher, back_url, back_id, sub_expired = _get_exam_permission(request, exam)
    if not allowed:
        messages.error(request, "صلاحية غير كافية.")
        return redirect('home')

    if sub_expired:
        return render(request, 'students/teacher_unavailable.html', {'teacher_name': teacher.user.first_name})

    if exam.group:
        results = exam.results.all().select_related('student__user').order_by('-score')
    else:
        results = PackageExamResult.objects.filter(exam=exam).select_related('student__user').order_by('-score')

    allow_images = True

    if request.method == 'POST':
        form = QuestionForm(request.POST, request.FILES)
        if form.is_valid():
            question = form.save(commit=False)
            question.exam = exam

            if 'image' in request.FILES:
                if allow_images:
                    question.image = request.FILES['image']
                else:
                    messages.warning(request, "تم حفظ السؤال، ولكن تم تجاهل الصورة لأن باقتك الحالية لا تدعم ذلك.")

            question.save()

            storage = messages.get_messages(request)
            if not storage:
                messages.success(request, "تم إضافة السؤال بنجاح.")

            return redirect('exam_manage', exam_id=exam.id)
    else:
        form = QuestionForm()

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
        'allow_images': allow_images,
    }
    return render(request, 'exams/manage.html', context)


@login_required
def add_question_page(request, exam_id):
    exam = get_object_or_404(Exam, id=exam_id)
    allowed, is_owner, teacher, _back_url, _back_id, sub_expired = _get_exam_permission(request, exam)
    if not allowed:
        messages.error(request, "ليس لديك صلاحية لإضافة أسئلة لهذا الامتحان.")
        return redirect('home')
    if sub_expired:
        return render(request, 'students/teacher_unavailable.html', {'teacher_name': teacher.user.first_name})

    allow_images = True

    if request.method == 'POST':
        form = QuestionForm(request.POST, request.FILES)
        if form.is_valid():
            question = form.save(commit=False)
            question.exam = exam

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
        'allow_images': allow_images,
    })


@login_required
def edit_question_page(request, question_id):
    question = get_object_or_404(Question, id=question_id)
    exam = question.exam
    allowed, is_owner, teacher, _back_url, _back_id, sub_expired = _get_exam_permission(request, exam)
    if not allowed:
        messages.error(request, "ليس لديك صلاحية لتعديل هذا السؤال.")
        return redirect('home')
    if sub_expired:
        return render(request, 'students/teacher_unavailable.html', {'teacher_name': teacher.user.first_name})

    allow_images = True

    if request.method == 'POST':
        form = QuestionForm(request.POST, request.FILES, instance=question)
        if form.is_valid():
            if request.POST.get('image-clear') == 'on':
                question.image = None

            if 'image' in request.FILES:
                if allow_images:
                    question.image = request.FILES['image']
                else:
                    messages.warning(request, "تم تجاهل الصورة الجديدة.")

            form.save()
            messages.success(request, "تم تحديث السؤال.")
            return redirect('exam_manage', exam_id=exam.id)
    else:
        form = QuestionForm(instance=question)

    return render(request, 'exams/edit_question.html', {
        'form': form,
        'question': question,
        'exam': exam,
        'allow_images': allow_images,
    })


# 1. تفعيل أو إيقاف الامتحان
@login_required
def toggle_exam_status(request, exam_id):
    exam = get_object_or_404(Exam, id=exam_id)
    allowed, _is_owner, teacher, _back_url, _back_id, sub_expired = _get_exam_permission(request, exam)
    if not allowed:
        messages.error(request, "ليس لديك صلاحية لتعديل حالة الامتحان.")
        return redirect('home')
    if sub_expired:
        return render(request, 'students/teacher_unavailable.html', {'teacher_name': teacher.user.first_name})

    exam.is_active = not exam.is_active
    exam.save()

    status = "تفعيل" if exam.is_active else "إغلاق"
    messages.success(request, f"تم {status} الامتحان بنجاح.")
    return redirect('exam_manage', exam_id=exam.id)


# 2. حذف الامتحان بالكامل
@login_required
def delete_exam(request, exam_id):
    exam = get_object_or_404(Exam, id=exam_id)
    allowed, _is_owner, teacher, back_url, back_id, sub_expired = _get_exam_permission(request, exam)
    if not allowed:
        messages.error(request, "ليس لديك صلاحية لحذف الامتحان.")
        return redirect('home')
    if sub_expired:
        return render(request, 'students/teacher_unavailable.html', {'teacher_name': teacher.user.first_name})

    exam.delete()
    messages.success(request, "تم حذف الامتحان نهائياً.")
    if back_url == 'group_exams' and back_id:
        return redirect('group_exams', group_id=back_id)
    if back_url == 'teacher_package_detail' and back_id:
        return redirect('teacher_package_detail', package_id=back_id)
    return redirect('home')


# 3. حذف سؤال معين
@login_required
def delete_question(request, question_id):
    question = get_object_or_404(Question, id=question_id)
    exam = question.exam
    allowed, _is_owner, teacher, _back_url, _back_id, sub_expired = _get_exam_permission(request, exam)
    if not allowed:
        messages.error(request, "ليس لديك صلاحية لحذف هذا السؤال.")
        return redirect('home')
    if sub_expired:
        return render(request, 'students/teacher_unavailable.html', {'teacher_name': teacher.user.first_name})

    question.delete()
    messages.success(request, "تم حذف السؤال.")
    return redirect('exam_manage', exam_id=exam.id)


# 4. تعديل سؤال
@login_required
def edit_question(request, question_id):
    question = get_object_or_404(Question, id=question_id)
    exam = question.exam
    allowed, _is_owner, teacher, _back_url, _back_id, sub_expired = _get_exam_permission(request, exam)
    if not allowed:
        messages.error(request, "ليس لديك صلاحية لتعديل هذا السؤال.")
        return redirect('home')
    if sub_expired:
        return render(request, 'students/teacher_unavailable.html', {'teacher_name': teacher.user.first_name})

    allow_images = True

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

    return render(request, 'exams/edit_question.html', {
        'form': form,
        'question': question,
        'exam': exam,
        'allow_images': allow_images,
    })

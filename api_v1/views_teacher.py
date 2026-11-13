"""
api_v1/views_teacher.py
جميع نقاط النهاية الخاصة بالمعلم والمساعد (إدارة المجموعات، المحاضرات، الأكواد، الملفات، الامتحانات، الطلاب، الرصد الجماعي، الحزم، المحفظة، الاشتراك، والمساعدين).
"""
from decimal import Decimal
from django.db import transaction
from django.db.models import Q, Sum
from django.shortcuts import get_object_or_404
from rest_framework import status
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView

from accounts.models import StudentProfile
from assistants.models import AssistantProfile, AssistantJob
from core.utils import send_notification
from exams.models import Exam, Question, ExamResult
from students.models import Enrollment, PerformanceLog, PackageEnrollment, VideoViewTracking, PackageExamResult
from teachers.models import (
    TeacherProfile,
    SubscriptionPlan,
    Group,
    Lecture,
    VideoCode,
    PDFFile,
    CoursePackage,
    Wallet,
    WithdrawRequest,
)
from teachers.views import (
    get_group_permission,
    get_package_permission,
    calculate_leaderboard,
    calculate_package_leaderboard,
)

from .permissions import IsTeacherRole, IsAssistantRole, IsTeacherOrAssistantRole
from .serializers import (
    GroupSerializer,
    LectureSerializer,
    VideoCodeSerializer,
    PDFFileSerializer,
    ExamSerializer,
    QuestionTeacherSerializer,
    ExamResultSerializer,
    PackageExamResultSerializer,
    EnrollmentSerializer,
    PerformanceLogSerializer,
    CoursePackageSerializer,
    PackageEnrollmentSerializer,
    WalletSerializer,
    WithdrawRequestSerializer,
    SubscriptionPlanSerializer,
    AssistantJobSerializer,
    TeacherCardSerializer,
)


class TeacherDashboardAPIView(APIView):
    """لوحة تحكم المعلم: حالة الاشتراك، الإحصائيات، المجموعات، وإنشاء مجموعة جديدة."""
    permission_classes = [IsAuthenticated, IsTeacherRole]

    def get(self, request):
        if not hasattr(request.user, 'teacher_profile'):
            return Response({'error': 'يرجى استكمال بيانات المعلم أولاً.', 'require_complete_profile': True}, status=status.HTTP_400_BAD_REQUEST)

        teacher = request.user.teacher_profile
        groups = teacher.groups.all().order_by('created_at')
        query = request.query_params.get('q', '').strip()
        if query:
            groups = groups.filter(name__icontains=query)

        allowed_ids = list(teacher.get_allowed_group_ids())
        wallet, _ = Wallet.objects.get_or_create(teacher=teacher)

        return Response({
            'teacher': TeacherCardSerializer(teacher, context={'request': request}).data,
            'subscription': {
                'is_active': teacher.has_active_subscription(),
                'days_left': teacher.days_remaining(),
                'subscription_end_date': teacher.subscription_end_date,
                'current_plan': SubscriptionPlanSerializer(teacher.current_plan).data if teacher.current_plan else None,
                'total_students': teacher.get_total_students(),
                'student_limit': teacher.get_student_limit(),
                'groups_count': teacher.groups.count(),
                'group_limit': teacher.current_plan.group_limit if teacher.current_plan else 5,
            },
            'wallet': WalletSerializer(wallet).data,
            'allowed_group_ids': allowed_ids,
            'groups': GroupSerializer(groups, many=True, context={'request': request}).data,
        })

    def post(self, request):
        teacher = request.user.teacher_profile
        limit = teacher.current_plan.group_limit if teacher.current_plan else 5
        if teacher.groups.count() >= limit:
            return Response(
                {'error': f'لقد وصلت للحد الأقصى من المجموعات ({limit}). يرجى ترقية الباقة.'},
                status=status.HTTP_400_BAD_REQUEST,
            )

        name = str(request.data.get('name', '')).strip()
        grade = str(request.data.get('grade', '')).strip()
        if not name or not grade:
            return Response({'error': 'يرجى إدخال اسم المجموعة والصف الدراسي.'}, status=status.HTTP_400_BAD_REQUEST)

        group = Group.objects.create(teacher=teacher, name=name, grade=grade)
        return Response({
            'message': f"تم إنشاء مجموعة '{group.name}' بنجاح!",
            'group': GroupSerializer(group, context={'request': request}).data,
        }, status=status.HTTP_201_CREATED)


class TeacherGroupDetailAPIView(APIView):
    """عرض أو تعديل أو حذف مجموعة."""
    permission_classes = [IsAuthenticated, IsTeacherOrAssistantRole]

    def get(self, request, group_id):
        group, is_owner = get_group_permission(request, group_id)
        if not group:
            return Response({'error': 'ليس لديك صلاحية للوصول إلى هذه المجموعة.'}, status=status.HTTP_403_FORBIDDEN)

        lectures = group.lectures.all().order_by('-created_at')
        exams = group.exams.all().order_by('-created_at')
        pdfs = group.pdfs.all().order_by('-created_at')
        pending_count = group.enrollments.filter(is_active=False).count()

        return Response({
            'group': GroupSerializer(group, context={'request': request}).data,
            'is_owner': is_owner,
            'pending_count': pending_count,
            'lectures': LectureSerializer(lectures, many=True).data,
            'exams': ExamSerializer(exams, many=True).data,
            'pdfs': PDFFileSerializer(pdfs, many=True).data,
        })

    def patch(self, request, group_id):
        group = get_object_or_404(Group, id=group_id, teacher__user=request.user)
        if 'name' in request.data:
            group.name = str(request.data['name']).strip()
        if 'grade' in request.data:
            group.grade = str(request.data['grade']).strip()
        group.save()
        return Response({
            'message': 'تم تحديث بيانات المجموعة.',
            'group': GroupSerializer(group, context={'request': request}).data,
        })

    def delete(self, request, group_id):
        group = get_object_or_404(Group, id=group_id, teacher__user=request.user)
        group.delete()
        return Response({'message': 'تم حذف المجموعة بنجاح.'})


class TeacherGroupLecturesAPIView(APIView):
    """إدارة محاضرات المجموعة (عرض وإضافة)."""
    permission_classes = [IsAuthenticated, IsTeacherOrAssistantRole]

    def get(self, request, group_id):
        group, _ = get_group_permission(request, group_id, permission_type='videos')
        if not group:
            return Response({'error': 'ليس لديك صلاحية لإدارة المحاضرات.'}, status=status.HTTP_403_FORBIDDEN)
        lectures = group.lectures.all().order_by('-created_at')
        q = request.query_params.get('q', '').strip()
        if q:
            lectures = lectures.filter(title__icontains=q)
        return Response({'lectures': LectureSerializer(lectures, many=True).data})

    def post(self, request, group_id):
        group, _ = get_group_permission(request, group_id, permission_type='videos')
        if not group:
            return Response({'error': 'ليس لديك صلاحية لإضافة محاضرات.'}, status=status.HTTP_403_FORBIDDEN)

        title = str(request.data.get('title', '')).strip()
        video_link = str(request.data.get('video_link', '')).strip()
        description = str(request.data.get('description', '')).strip()

        if not title or not video_link:
            return Response({'error': 'عنوان المحاضرة ورابط الفيديو مطلوبان.'}, status=status.HTTP_400_BAD_REQUEST)

        lecture = Lecture.objects.create(
            group=group,
            title=title,
            video_link=video_link,
            description=description,
        )
        for enroll in group.enrollments.filter(is_active=True).select_related('student__user'):
            send_notification(
                enroll.student.user,
                'محاضرة جديدة 📹',
                f"تم نشر محاضرة '{lecture.title}' في مجموعة {group.name}.",
                f'/student/group/{group.id}/',
            )
        return Response({
            'message': 'تم نشر المحاضرة بنجاح!',
            'lecture': LectureSerializer(lecture).data,
        }, status=status.HTTP_201_CREATED)


class TeacherLectureActionAPIView(APIView):
    """تفعيل/إخفاء أو حذف محاضرة."""
    permission_classes = [IsAuthenticated, IsTeacherOrAssistantRole]

    def post(self, request, lecture_id):
        lecture = get_object_or_404(Lecture, id=lecture_id)
        if lecture.group:
            group, _ = get_group_permission(request, lecture.group.id, permission_type='videos')
            if not group:
                return Response({'error': 'صلاحية غير كافية.'}, status=status.HTTP_403_FORBIDDEN)
        else:
            pkg = lecture.packages.first()
            if not pkg or not get_package_permission(request, pkg.id, permission_type='videos')[0]:
                return Response({'error': 'صلاحية غير كافية.'}, status=status.HTTP_403_FORBIDDEN)

        lecture.is_active = not lecture.is_active
        lecture.save(update_fields=['is_active'])
        return Response({
            'message': 'تم تحديث حالة المحاضرة.',
            'is_active': lecture.is_active,
        })

    def delete(self, request, lecture_id):
        lecture = get_object_or_404(Lecture, id=lecture_id)
        if lecture.group:
            group, _ = get_group_permission(request, lecture.group.id, permission_type='videos')
            if not group:
                return Response({'error': 'صلاحية غير كافية.'}, status=status.HTTP_403_FORBIDDEN)
        else:
            pkg = lecture.packages.first()
            if not pkg or not get_package_permission(request, pkg.id, permission_type='videos')[0]:
                return Response({'error': 'صلاحية غير كافية.'}, status=status.HTTP_403_FORBIDDEN)

        lecture.delete()
        return Response({'message': 'تم حذف المحاضرة بنجاح.'})


class TeacherVideoCodesAPIView(APIView):
    """عرض وتوليد أكواد المشاهدة لمحاضرة في مجموعة."""
    permission_classes = [IsAuthenticated, IsTeacherOrAssistantRole]

    def get(self, request, lecture_id):
        lecture = get_object_or_404(Lecture, id=lecture_id)
        if not lecture.group:
            return Response({'error': 'هذه المحاضرة تابعة لحزمة أونلاين ولا تستخدم أكواد.'}, status=status.HTTP_400_BAD_REQUEST)
        group, _ = get_group_permission(request, lecture.group.id, permission_type='videos')
        if not group:
            return Response({'error': 'صلاحية غير كافية.'}, status=status.HTTP_403_FORBIDDEN)

        codes = lecture.codes.select_related('used_by__user').order_by('is_used', '-id')
        return Response({
            'lecture': LectureSerializer(lecture).data,
            'unused_count': lecture.codes.filter(is_used=False).count(),
            'codes': VideoCodeSerializer(codes, many=True).data,
        })

    def post(self, request, lecture_id):
        lecture = get_object_or_404(Lecture, id=lecture_id)
        if not lecture.group:
            return Response({'error': 'هذه المحاضرة تابعة لحزمة أونلاين ولا تستخدم أكواد.'}, status=status.HTTP_400_BAD_REQUEST)
        group, _ = get_group_permission(request, lecture.group.id, permission_type='videos')
        if not group:
            return Response({'error': 'صلاحية غير كافية.'}, status=status.HTTP_403_FORBIDDEN)

        try:
            amount = min(max(int(request.data.get('amount', 10)), 1), 100)
            views_limit = max(int(request.data.get('views_limit', 1)), 1)
        except (ValueError, TypeError):
            return Response({'error': 'أدخل أرقاماً صحيحة.'}, status=status.HTTP_400_BAD_REQUEST)

        new_codes = []
        for _ in range(amount):
            while True:
                code_str = VideoCode.generate_random_code()
                if not VideoCode.objects.filter(code=code_str).exists():
                    vc = VideoCode.objects.create(lecture=lecture, code=code_str, max_views=views_limit)
                    new_codes.append(vc)
                    break

        return Response({
            'message': f'تم توليد {len(new_codes)} كود (بحد {views_limit} مشاهدات).',
            'generated_codes': VideoCodeSerializer(new_codes, many=True).data,
        }, status=status.HTTP_201_CREATED)


class TeacherPDFsAPIView(APIView):
    """إضافة وحذف ملفات PDF في المجموعة أو الحزمة."""
    permission_classes = [IsAuthenticated, IsTeacherOrAssistantRole]

    def post(self, request, group_id=None, package_id=None):
        title = str(request.data.get('title', '')).strip()
        link = str(request.data.get('link', '')).strip()
        if not title or not link:
            return Response({'error': 'عنوان الملف والرابط مطلوبان.'}, status=status.HTTP_400_BAD_REQUEST)

        if group_id:
            group, _ = get_group_permission(request, group_id, permission_type='videos')
            if not group:
                return Response({'error': 'صلاحية غير كافية.'}, status=status.HTTP_403_FORBIDDEN)
            pdf = PDFFile.objects.create(group=group, title=title, link=link)
        elif package_id:
            package, _ = get_package_permission(request, package_id, permission_type='videos')
            if not package:
                return Response({'error': 'صلاحية غير كافية.'}, status=status.HTTP_403_FORBIDDEN)
            pdf = PDFFile.objects.create(group=None, title=title, link=link)
            package.pdfs.add(pdf)
        else:
            return Response({'error': 'يرجى تحديد المجموعة أو الحزمة.'}, status=status.HTTP_400_BAD_REQUEST)

        return Response({
            'message': 'تم إضافة الملف بنجاح.',
            'pdf': PDFFileSerializer(pdf).data,
        }, status=status.HTTP_201_CREATED)

    def delete(self, request, pdf_id):
        pdf = get_object_or_404(PDFFile, id=pdf_id)
        if pdf.group:
            group, _ = get_group_permission(request, pdf.group.id, permission_type='videos')
            if not group:
                return Response({'error': 'صلاحية غير كافية.'}, status=status.HTTP_403_FORBIDDEN)
        else:
            pkg = pdf.packages.first()
            if not pkg or not get_package_permission(request, pkg.id, permission_type='videos')[0]:
                return Response({'error': 'صلاحية غير كافية.'}, status=status.HTTP_403_FORBIDDEN)

        pdf.delete()
        return Response({'message': 'تم حذف الملف بنجاح.'})


class TeacherGroupExamsAPIView(APIView):
    """عرض وإنشاء امتحانات المجموعة."""
    permission_classes = [IsAuthenticated, IsTeacherOrAssistantRole]

    def get(self, request, group_id):
        group, _ = get_group_permission(request, group_id, permission_type='exams')
        if not group:
            return Response({'error': 'ليس لديك صلاحية لإدارة الامتحانات.'}, status=status.HTTP_403_FORBIDDEN)
        exams = group.exams.all().order_by('-created_at')
        return Response({'exams': ExamSerializer(exams, many=True).data})

    def post(self, request, group_id):
        group, _ = get_group_permission(request, group_id, permission_type='exams')
        if not group:
            return Response({'error': 'ليس لديك صلاحية لإنشاء امتحانات.'}, status=status.HTTP_403_FORBIDDEN)

        title = str(request.data.get('title', '')).strip()
        description = str(request.data.get('description', '')).strip()
        duration_minutes = int(request.data.get('duration_minutes', 30))
        is_active = bool(request.data.get('is_active', False))

        if not title:
            return Response({'error': 'عنوان الامتحان مطلوب.'}, status=status.HTTP_400_BAD_REQUEST)

        exam = Exam.objects.create(
            group=group,
            title=title,
            description=description,
            duration_minutes=duration_minutes,
            is_active=is_active,
        )
        return Response({
            'message': 'تم إنشاء الامتحان بنجاح!',
            'exam': ExamSerializer(exam).data,
        }, status=status.HTTP_201_CREATED)


def _check_exam_permission(request, exam: Exam):
    if exam.group:
        group, is_owner = get_group_permission(request, exam.group.id, permission_type='exams')
        if not group:
            return False, None
        return True, group.teacher
    pkg = exam.packages.first()
    if pkg:
        package, is_owner = get_package_permission(request, pkg.id, permission_type='exams')
        if not package:
            return False, None
        return True, package.teacher
    return False, None


class TeacherExamDetailAPIView(APIView):
    """إدارة الامتحان: عرض الأسئلة والنتائج، تفعيل/إغلاق، حذف، وإضافة أسئلة."""
    permission_classes = [IsAuthenticated, IsTeacherOrAssistantRole]

    def get(self, request, exam_id):
        exam = get_object_or_404(Exam, id=exam_id)
        allowed, teacher = _check_exam_permission(request, exam)
        if not allowed:
            return Response({'error': 'صلاحية غير كافية.'}, status=status.HTTP_403_FORBIDDEN)

        allow_images = bool(teacher and teacher.current_plan and teacher.current_plan.allow_question_images)
        questions = exam.questions.all()

        if exam.group:
            results = exam.results.select_related('student__user').order_by('-score')
            results_data = ExamResultSerializer(results, many=True).data
        else:
            results = PackageExamResult.objects.filter(exam=exam).select_related('student__user').order_by('-score')
            results_data = PackageExamResultSerializer(results, many=True).data

        return Response({
            'exam': ExamSerializer(exam).data,
            'allow_images': allow_images,
            'questions': QuestionTeacherSerializer(questions, many=True, context={'request': request}).data,
            'results': results_data,
        })

    def post(self, request, exam_id):
        """إضافة سؤال جديد للامتحان أو تبديل حالة التفعيل."""
        exam = get_object_or_404(Exam, id=exam_id)
        allowed, teacher = _check_exam_permission(request, exam)
        if not allowed:
            return Response({'error': 'صلاحية غير كافية.'}, status=status.HTTP_403_FORBIDDEN)

        if request.data.get('action') == 'toggle':
            exam.is_active = not exam.is_active
            exam.save(update_fields=['is_active'])
            return Response({
                'message': 'تم تفعيل الامتحان.' if exam.is_active else 'تم إغلاق الامتحان.',
                'is_active': exam.is_active,
            })

        allow_images = bool(teacher and teacher.current_plan and teacher.current_plan.allow_question_images)
        text = str(request.data.get('text', '')).strip()
        option_a = str(request.data.get('option_a', '')).strip()
        option_b = str(request.data.get('option_b', '')).strip()
        option_c = str(request.data.get('option_c', '')).strip()
        option_d = str(request.data.get('option_d', '')).strip()
        correct_answer = str(request.data.get('correct_answer', 'A')).strip().upper()
        marks = int(request.data.get('marks', 1))

        if not all([text, option_a, option_b, option_c, option_d]):
            return Response({'error': 'يرجى إدخال نص السؤال وجميع الاختيارات الأربعة.'}, status=status.HTTP_400_BAD_REQUEST)

        question = Question(
            exam=exam,
            text=text,
            option_a=option_a,
            option_b=option_b,
            option_c=option_c,
            option_d=option_d,
            correct_answer=correct_answer if correct_answer in ('A', 'B', 'C', 'D') else 'A',
            marks=marks,
        )
        if 'image' in request.FILES and allow_images:
            question.image = request.FILES['image']
        question.save()

        return Response({
            'message': 'تم إضافة السؤال بنجاح.',
            'question': QuestionTeacherSerializer(question, context={'request': request}).data,
        }, status=status.HTTP_201_CREATED)

    def delete(self, request, exam_id):
        exam = get_object_or_404(Exam, id=exam_id)
        allowed, _ = _check_exam_permission(request, exam)
        if not allowed:
            return Response({'error': 'صلاحية غير كافية.'}, status=status.HTTP_403_FORBIDDEN)
        exam.delete()
        return Response({'message': 'تم حذف الامتحان نهائياً.'})


class TeacherQuestionDetailAPIView(APIView):
    """تعديل أو حذف سؤال."""
    permission_classes = [IsAuthenticated, IsTeacherOrAssistantRole]

    def patch(self, request, question_id):
        question = get_object_or_404(Question, id=question_id)
        allowed, teacher = _check_exam_permission(request, question.exam)
        if not allowed:
            return Response({'error': 'صلاحية غير كافية.'}, status=status.HTTP_403_FORBIDDEN)

        allow_images = bool(teacher and teacher.current_plan and teacher.current_plan.allow_question_images)
        for field in ('text', 'option_a', 'option_b', 'option_c', 'option_d', 'correct_answer'):
            if field in request.data:
                setattr(question, field, str(request.data[field]).strip())
        if 'marks' in request.data:
            question.marks = int(request.data['marks'])
        if request.data.get('clear_image') in (True, 'true', 'on'):
            question.image = None
        if 'image' in request.FILES and allow_images:
            question.image = request.FILES['image']
        question.save()

        return Response({
            'message': 'تم تحديث السؤال بنجاح.',
            'question': QuestionTeacherSerializer(question, context={'request': request}).data,
        })

    def delete(self, request, question_id):
        question = get_object_or_404(Question, id=question_id)
        allowed, _ = _check_exam_permission(request, question.exam)
        if not allowed:
            return Response({'error': 'صلاحية غير كافية.'}, status=status.HTTP_403_FORBIDDEN)
        question.delete()
        return Response({'message': 'تم حذف السؤال.'})


class TeacherGroupStudentsAPIView(APIView):
    """عرض طلاب المجموعة، تسجيل أداء فردي، وطلبات الانضمام."""
    permission_classes = [IsAuthenticated, IsTeacherOrAssistantRole]

    def get(self, request, group_id):
        group, _ = get_group_permission(request, group_id, permission_type='students')
        if not group:
            return Response({'error': 'صلاحية غير كافية.'}, status=status.HTTP_403_FORBIDDEN)

        enrollments = group.enrollments.filter(is_active=True).select_related('student__user')
        pending = group.enrollments.filter(is_active=False).select_related('student__user')
        q = request.query_params.get('q', '').strip()
        if q:
            q_filter = (
                Q(student__user__first_name__icontains=q)
                | Q(student__user__last_name__icontains=q)
                | Q(student__user__phone__icontains=q)
            )
            enrollments = enrollments.filter(q_filter)
            pending = pending.filter(q_filter)

        return Response({
            'students': EnrollmentSerializer(enrollments, many=True, context={'request': request}).data,
            'pending_requests': EnrollmentSerializer(pending, many=True, context={'request': request}).data,
        })

    def post(self, request, group_id):
        """تسجيل أداء فردي لطالب أو معالجة طلب انضمام (accept/reject)."""
        group, _ = get_group_permission(request, group_id, permission_type='students')
        if not group:
            return Response({'error': 'صلاحية غير كافية.'}, status=status.HTTP_403_FORBIDDEN)

        action_type = request.data.get('action_type')
        if action_type in ('accept', 'reject'):
            enroll_id = request.data.get('enroll_id')
            enrollment = get_object_or_404(Enrollment, id=enroll_id, group=group)
            if action_type == 'accept':
                enrollment.is_active = True
                enrollment.save(update_fields=['is_active'])
                send_notification(
                    enrollment.student.user,
                    'تم قبول طلبك!',
                    f'وافق المستر على انضمامك لمجموعة {group.name}. ابدأ التعلم الآن.',
                    f'/student/group/{group.id}/',
                )
                return Response({'message': f'تم قبول الطالب {enrollment.student.user.first_name}.'})
            else:
                enrollment.delete()
                return Response({'message': 'تم رفض الطلب وحذفه.'})

        student_id = request.data.get('student_id')
        student = get_object_or_404(StudentProfile, id=student_id)
        log = PerformanceLog.objects.create(
            group=group,
            student=student,
            session_number=int(request.data.get('session_number', 1)),
            is_present=bool(request.data.get('is_present', True)),
            homework_score=request.data.get('homework_score'),
            homework_max=int(request.data.get('homework_max', 10)),
            class_exam_score=request.data.get('class_exam_score'),
            class_exam_max=int(request.data.get('class_exam_max', 10)),
            recitation_score=request.data.get('recitation_score'),
            recitation_max=int(request.data.get('recitation_max', 10)),
            comprehensive_exam_score=request.data.get('comprehensive_exam_score'),
            comprehensive_exam_max=int(request.data.get('comprehensive_exam_max', 50)),
            note=str(request.data.get('note', '')).strip(),
        )
        return Response({
            'message': f'تم تسجيل الأداء للطالب {student.user.first_name}.',
            'log': PerformanceLogSerializer(log).data,
        }, status=status.HTTP_201_CREATED)


class TeacherStudentFullLogAPIView(APIView):
    """السجل الكامل لطالب في مجموعة، أو حذف سجل أداء، أو إزالة الطالب من المجموعة."""
    permission_classes = [IsAuthenticated, IsTeacherOrAssistantRole]

    def get(self, request, group_id, student_id):
        group, _ = get_group_permission(request, group_id, permission_type='students')
        if not group:
            return Response({'error': 'صلاحية غير كافية.'}, status=status.HTTP_403_FORBIDDEN)

        student = get_object_or_404(StudentProfile, id=student_id)
        logs = PerformanceLog.objects.filter(student=student, group=group).order_by('-date', '-id')
        month = request.query_params.get('month')
        if month and str(month).isdigit():
            logs = logs.filter(date__month=int(month))

        return Response({
            'student_id': student.id,
            'student_name': f"{student.user.first_name} {student.user.last_name}".strip(),
            'student_phone': student.user.phone,
            'parent_phone': student.parent_phone,
            'logs': PerformanceLogSerializer(logs, many=True).data,
        })

    def delete(self, request, group_id, student_id):
        group, _ = get_group_permission(request, group_id, permission_type='students')
        if not group:
            return Response({'error': 'صلاحية غير كافية.'}, status=status.HTTP_403_FORBIDDEN)

        log_id = request.query_params.get('log_id') or request.data.get('log_id')
        if log_id:
            PerformanceLog.objects.filter(id=log_id, group=group, student_id=student_id).delete()
            return Response({'message': 'تم حذف سجل الأداء.'})

        Enrollment.objects.filter(group=group, student_id=student_id).delete()
        return Response({'message': 'تم حذف الطالب من المجموعة.'})


class TeacherBulkLogAPIView(APIView):
    """رصد الدرجات والغياب الجماعي لكل طلاب المجموعة دفعة واحدة."""
    permission_classes = [IsAuthenticated, IsTeacherOrAssistantRole]

    @transaction.atomic
    def post(self, request, group_id):
        group, _ = get_group_permission(request, group_id, permission_type='students')
        if not group:
            return Response({'error': 'صلاحية غير كافية.'}, status=status.HTTP_403_FORBIDDEN)

        global_session = int(request.data.get('session_number', 1))
        hw_max = int(request.data.get('homework_max', 10))
        class_max = int(request.data.get('class_exam_max', 10))
        recit_max = int(request.data.get('recitation_max', 10))
        comp_max = int(request.data.get('comprehensive_exam_max', 50))
        records = request.data.get('records', [])

        def _clean_int(val):
            if val is None or val == '':
                return None
            try:
                return int(val)
            except (ValueError, TypeError):
                return None

        created_count = 0
        for rec in records:
            sid = rec.get('student_id')
            if not sid:
                continue
            is_absent = bool(rec.get('is_absent', False))
            if is_absent:
                present = False
                hw_score, cls_score, rec_score = 0, 0, 0
                comp_score = _clean_int(rec.get('comprehensive_exam_score'))
            else:
                present = True
                hw_score = _clean_int(rec.get('homework_score'))
                cls_score = _clean_int(rec.get('class_exam_score'))
                rec_score = _clean_int(rec.get('recitation_score'))
                comp_score = _clean_int(rec.get('comprehensive_exam_score'))

            PerformanceLog.objects.create(
                group=group,
                student_id=sid,
                session_number=global_session,
                is_present=present,
                homework_score=hw_score,
                homework_max=hw_max,
                class_exam_score=cls_score,
                class_exam_max=class_max,
                recitation_score=rec_score,
                recitation_max=recit_max,
                comprehensive_exam_score=comp_score,
                comprehensive_exam_max=comp_max,
                note=str(rec.get('note', '')).strip(),
            )
            created_count += 1

        return Response({
            'message': f'تم رصد الحصة رقم {global_session} لـ {created_count} طالب بنجاح.',
            'count': created_count,
        }, status=status.HTTP_201_CREATED)


class TeacherGroupRankingAndImportAPIView(APIView):
    """ترتيب طلاب المجموعة واستيراد المحتوى من مجموعات أخرى."""
    permission_classes = [IsAuthenticated, IsTeacherOrAssistantRole]

    def get(self, request, group_id):
        group, _ = get_group_permission(request, group_id, permission_type='students')
        if not group:
            return Response({'error': 'صلاحية غير كافية.'}, status=status.HTTP_403_FORBIDDEN)

        raw_board = calculate_leaderboard(group)
        return Response({
            'leaderboard': [
                {
                    'rank': item['rank'],
                    'student_id': item['student'].id,
                    'student_name': f"{item['student'].user.first_name} {item['student'].user.last_name}".strip(),
                    'student_phone': item['student'].user.phone,
                    'total_score': item['total_score'],
                }
                for item in raw_board
            ]
        })

    @transaction.atomic
    def post(self, request, group_id):
        target_group = get_object_or_404(Group, id=group_id, teacher__user=request.user)
        lecture_ids = request.data.get('lecture_ids', [])
        exam_ids = request.data.get('exam_ids', [])
        count_lec, count_exam = 0, 0

        if lecture_ids:
            for old_lec in Lecture.objects.filter(id__in=lecture_ids, group__teacher=target_group.teacher):
                Lecture.objects.create(
                    group=target_group,
                    title=old_lec.title,
                    video_link=old_lec.video_link,
                    description=old_lec.description,
                    is_active=True,
                )
                count_lec += 1

        if exam_ids:
            for old_exam in Exam.objects.filter(id__in=exam_ids, group__teacher=target_group.teacher):
                new_exam = Exam.objects.create(
                    group=target_group,
                    title=old_exam.title,
                    description=old_exam.description,
                    duration_minutes=old_exam.duration_minutes,
                    is_active=False,
                )
                for q in old_exam.questions.all():
                    Question.objects.create(
                        exam=new_exam,
                        text=q.text,
                        image=q.image,
                        option_a=q.option_a,
                        option_b=q.option_b,
                        option_c=q.option_c,
                        option_d=q.option_d,
                        correct_answer=q.correct_answer,
                        marks=q.marks,
                    )
                count_exam += 1

        return Response({
            'message': f'تم استيراد {count_lec} محاضرة و {count_exam} امتحان بنجاح.',
            'imported_lectures': count_lec,
            'imported_exams': count_exam,
        })


class TeacherPackagesAPIView(APIView):
    """عرض وإنشاء الحزم الأونلاين للمعلم أو المساعد."""
    permission_classes = [IsAuthenticated, IsTeacherOrAssistantRole]

    def get(self, request):
        if request.user.role == 'teacher':
            teacher = request.user.teacher_profile
        else:
            teacher_id = request.query_params.get('teacher_id')
            teacher = get_object_or_404(TeacherProfile, id=teacher_id)
            if not AssistantJob.objects.filter(assistant__user=request.user, teacher=teacher, is_active=True, can_manage_packages=True).exists():
                return Response({'error': 'ليس لديك صلاحية لإدارة حزم هذا المعلم.'}, status=status.HTTP_403_FORBIDDEN)

        packages = teacher.packages.all().order_by('-created_at')
        return Response({
            'packages': CoursePackageSerializer(packages, many=True, context={'request': request}).data,
        })

    @transaction.atomic
    def post(self, request):
        if request.user.role == 'teacher':
            teacher = request.user.teacher_profile
        else:
            teacher_id = request.data.get('teacher_id')
            teacher = get_object_or_404(TeacherProfile, id=teacher_id)
            if not AssistantJob.objects.filter(assistant__user=request.user, teacher=teacher, is_active=True, can_manage_packages=True).exists():
                return Response({'error': 'ليس لديك صلاحية لإنشاء حزم لهذا المعلم.'}, status=status.HTTP_403_FORBIDDEN)

        if teacher.current_plan and not teacher.current_plan.allow_online_packages:
            return Response({'error': 'باقة المعلم الحالية لا تدعم الحزم الأونلاين.'}, status=status.HTTP_403_FORBIDDEN)

        title = str(request.data.get('title', '')).strip()
        grade = str(request.data.get('grade', '')).strip()
        description = str(request.data.get('description', '')).strip()
        price = int(request.data.get('price', 0))
        view_limit = int(request.data.get('view_limit', 3))

        if not title or not grade:
            return Response({'error': 'يرجى إدخال اسم الحزمة والصف الدراسي.'}, status=status.HTTP_400_BAD_REQUEST)

        pkg = CoursePackage(
            teacher=teacher,
            title=title,
            grade=grade,
            description=description,
            price=price,
            view_limit=view_limit,
        )
        if 'image' in request.FILES:
            pkg.image = request.FILES['image']
        pkg.save()

        lecture_ids = request.data.get('lecture_ids', [])
        exam_ids = request.data.get('exam_ids', [])
        if lecture_ids:
            pkg.lectures.set(Lecture.objects.filter(id__in=lecture_ids, group__teacher=teacher))
        if exam_ids:
            pkg.exams.set(Exam.objects.filter(id__in=exam_ids, group__teacher=teacher))

        return Response({
            'message': 'تم إنشاء الحزمة بنجاح.',
            'package': CoursePackageSerializer(pkg, context={'request': request}).data,
        }, status=status.HTTP_201_CREATED)


class TeacherPackageDetailAPIView(APIView):
    """إدارة حزمة أونلاين (عرض المحتوى والطلاب والترتيب، إضافة/حذف محتوى، تعديل وحذف الحزمة)."""
    permission_classes = [IsAuthenticated, IsTeacherOrAssistantRole]

    def get(self, request, package_id):
        package, is_owner = get_package_permission(request, package_id)
        if not package:
            return Response({'error': 'ليس لديك صلاحية للوصول إلى هذه الحزمة.'}, status=status.HTTP_403_FORBIDDEN)

        enrollments = package.enrollments.filter(is_paid=True).select_related('student__user')
        raw_board = calculate_package_leaderboard(package)

        return Response({
            'package': CoursePackageSerializer(package, context={'request': request}).data,
            'is_owner': is_owner,
            'lectures': LectureSerializer(package.lectures.all(), many=True).data,
            'exams': ExamSerializer(package.exams.all(), many=True).data,
            'pdfs': PDFFileSerializer(package.pdfs.all(), many=True).data,
            'students': PackageEnrollmentSerializer(enrollments, many=True, context={'request': request}).data,
            'total_revenue': enrollments.count() * package.price,
            'leaderboard': [
                {
                    'rank': item['rank'],
                    'student_id': item['student'].id,
                    'student_name': f"{item['student'].user.first_name} {item['student'].user.last_name}".strip(),
                    'student_phone': item['student'].user.phone,
                    'score': item['score'],
                }
                for item in raw_board
            ],
        })

    def post(self, request, package_id):
        """إضافة محاضرة أو امتحان أو إزالة محتوى أو استيراد محتوى للحزمة."""
        package, _ = get_package_permission(request, package_id)
        if not package:
            return Response({'error': 'صلاحية غير كافية.'}, status=status.HTTP_403_FORBIDDEN)

        action = request.data.get('action')
        if action == 'add_lecture':
            lec = Lecture.objects.create(
                group=None,
                title=str(request.data.get('title', '')).strip(),
                video_link=str(request.data.get('video_link', '')).strip(),
                description=str(request.data.get('description', '')).strip(),
            )
            package.lectures.add(lec)
            return Response({'message': 'تم إضافة المحاضرة للحزمة.', 'lecture': LectureSerializer(lec).data}, status=status.HTTP_201_CREATED)

        if action == 'add_exam':
            exam = Exam.objects.create(
                group=None,
                title=str(request.data.get('title', '')).strip(),
                duration_minutes=int(request.data.get('duration_minutes', 30)),
                is_active=False,
            )
            package.exams.add(exam)
            return Response({'message': 'تم إنشاء الامتحان في الحزمة.', 'exam': ExamSerializer(exam).data}, status=status.HTTP_201_CREATED)

        if action == 'remove_content':
            item_type = request.data.get('type')
            item_id = request.data.get('id')
            if item_type == 'lecture':
                package.lectures.remove(get_object_or_404(Lecture, id=item_id))
            elif item_type == 'exam':
                package.exams.remove(get_object_or_404(Exam, id=item_id))
            return Response({'message': 'تمت إزالة المحتوى من الحزمة.'})

        if action == 'import':
            lecture_ids = request.data.get('lecture_ids', [])
            exam_ids = request.data.get('exam_ids', [])
            if lecture_ids:
                package.lectures.add(*Lecture.objects.filter(id__in=lecture_ids))
            if exam_ids:
                for old_exam in Exam.objects.filter(id__in=exam_ids):
                    new_exam = Exam.objects.create(
                        group=None,
                        title=old_exam.title,
                        description=old_exam.description,
                        duration_minutes=old_exam.duration_minutes,
                        is_active=False,
                    )
                    for q in old_exam.questions.all():
                        Question.objects.create(
                            exam=new_exam, text=q.text, image=q.image,
                            option_a=q.option_a, option_b=q.option_b,
                            option_c=q.option_c, option_d=q.option_d,
                            correct_answer=q.correct_answer, marks=q.marks,
                        )
                    package.exams.add(new_exam)
            return Response({'message': 'تم استيراد المحتوى للحزمة بنجاح.'})

        return Response({'error': 'إجراء غير معروف.'}, status=status.HTTP_400_BAD_REQUEST)

    def patch(self, request, package_id):
        package = get_object_or_404(CoursePackage, id=package_id, teacher__user=request.user)
        for field in ('title', 'grade', 'description'):
            if field in request.data:
                setattr(package, field, str(request.data[field]).strip())
        if 'price' in request.data:
            package.price = int(request.data['price'])
        if 'view_limit' in request.data:
            package.view_limit = int(request.data['view_limit'])
        if 'image' in request.FILES:
            package.image = request.FILES['image']
        package.save()
        return Response({
            'message': 'تم تحديث الحزمة بنجاح.',
            'package': CoursePackageSerializer(package, context={'request': request}).data,
        })

    def delete(self, request, package_id):
        package = get_object_or_404(CoursePackage, id=package_id, teacher__user=request.user)
        package.delete()
        return Response({'message': 'تم حذف الحزمة بنجاح.'})


class TeacherWalletAPIView(APIView):
    """محفظة المعلم وطلبات سحب الأرباح."""
    permission_classes = [IsAuthenticated, IsTeacherRole]

    def get(self, request):
        teacher = request.user.teacher_profile
        wallet, _ = Wallet.objects.get_or_create(teacher=teacher)
        withdraws = wallet.withdrawals.all().order_by('-created_at')
        return Response({
            'wallet': WalletSerializer(wallet).data,
            'withdrawals': WithdrawRequestSerializer(withdraws, many=True).data,
        })

    @transaction.atomic
    def post(self, request):
        teacher = request.user.teacher_profile
        wallet, _ = Wallet.objects.select_for_update().get_or_create(teacher=teacher)

        try:
            amount = Decimal(str(request.data.get('amount', '0')))
        except Exception:
            return Response({'error': 'يرجى إدخال مبلغ صحيح.'}, status=status.HTTP_400_BAD_REQUEST)

        method = str(request.data.get('method', 'vodafone')).strip()
        details = str(request.data.get('details', '')).strip()

        if amount > wallet.balance:
            return Response({'error': 'رصيدك الحالي لا يكفي.'}, status=status.HTTP_400_BAD_REQUEST)
        if amount < Decimal('50'):
            return Response({'error': 'الحد الأدنى للسحب 50 جنيه.'}, status=status.HTTP_400_BAD_REQUEST)
        if not details:
            return Response({'error': 'يرجى إدخال رقم المحفظة أو بيانات التحويل.'}, status=status.HTTP_400_BAD_REQUEST)

        wallet.balance -= amount
        wallet.save(update_fields=['balance'])

        req = WithdrawRequest.objects.create(
            wallet=wallet,
            amount=amount,
            method=method,
            details=details,
        )
        return Response({
            'message': 'تم إرسال طلب السحب بنجاح.',
            'wallet': WalletSerializer(wallet).data,
            'withdrawal': WithdrawRequestSerializer(req).data,
        }, status=status.HTTP_201_CREATED)


class TeacherManageAssistantsAPIView(APIView):
    """إدارة المساعدين وصلاحياتهم للمعلم."""
    permission_classes = [IsAuthenticated, IsTeacherRole]

    def get(self, request):
        teacher = request.user.teacher_profile
        active = teacher.assistants_jobs.filter(is_active=True).select_related('assistant__user')
        pending = teacher.assistants_jobs.filter(is_active=False).select_related('assistant__user')
        return Response({
            'active_assistants': AssistantJobSerializer(active, many=True, context={'request': request}).data,
            'pending_requests': AssistantJobSerializer(pending, many=True, context={'request': request}).data,
        })

    def post(self, request):
        teacher = request.user.teacher_profile
        job_id = request.data.get('job_id')
        action = request.data.get('action')
        job = get_object_or_404(AssistantJob, id=job_id, teacher=teacher)

        if action == 'accept':
            limit = teacher.current_plan.assistant_limit if teacher.current_plan else 2
            if teacher.assistants_jobs.filter(is_active=True).count() >= limit:
                return Response({'error': f'لا يمكن قبول المزيد. حد باقتك {limit} مساعدين.'}, status=status.HTTP_400_BAD_REQUEST)
            job.is_active = True
            job.save(update_fields=['is_active'])
            return Response({'message': 'تم قبول المساعد بنجاح.'})

        if action in ('reject', 'delete'):
            job.delete()
            return Response({'message': 'تم حذف المساعد.'})

        if action == 'update_permissions':
            for perm in ('can_manage_students', 'can_manage_exams', 'can_manage_videos', 'can_manage_packages'):
                if perm in request.data:
                    setattr(job, perm, bool(request.data[perm]))
            job.save()
            return Response({
                'message': 'تم تحديث الصلاحيات بنجاح.',
                'job': AssistantJobSerializer(job, context={'request': request}).data,
            })

        return Response({'error': 'إجراء غير صالح.'}, status=status.HTTP_400_BAD_REQUEST)


class AssistantDashboardAPIView(APIView):
    """لوحة تحكم المساعد والبحث عن معلمين وإرسال طلب عمل."""
    permission_classes = [IsAuthenticated, IsAssistantRole]

    def get(self, request):
        assistant, _ = AssistantProfile.objects.get_or_create(user=request.user)
        active_jobs = assistant.jobs.filter(is_active=True).select_related('teacher__user', 'teacher__subject')
        pending_jobs = assistant.jobs.filter(is_active=False).select_related('teacher__user', 'teacher__subject')
        return Response({
            'active_jobs': AssistantJobSerializer(active_jobs, many=True, context={'request': request}).data,
            'pending_jobs': AssistantJobSerializer(pending_jobs, many=True, context={'request': request}).data,
        })

    def post(self, request):
        """إرسال طلب توظيف لمعلم."""
        teacher_id = request.data.get('teacher_id')
        teacher = get_object_or_404(TeacherProfile, id=teacher_id)
        assistant, _ = AssistantProfile.objects.get_or_create(user=request.user)
        job, created = AssistantJob.objects.get_or_create(assistant=assistant, teacher=teacher)
        if not created:
            return Response({'error': 'لقد أرسلت طلباً لهذا المعلم من قبل.'}, status=status.HTTP_400_BAD_REQUEST)
        return Response({
            'message': f'تم إرسال طلب الانضمام للمستر {teacher.user.first_name} بنجاح.',
            'job': AssistantJobSerializer(job, context={'request': request}).data,
        }, status=status.HTTP_201_CREATED)


class AssistantTeacherGroupsAPIView(APIView):
    """عرض وإنشاء مجموعات لمعلم يعمل معه المساعد."""
    permission_classes = [IsAuthenticated, IsAssistantRole]

    def get(self, request, teacher_id):
        teacher = get_object_or_404(TeacherProfile, id=teacher_id)
        assistant = request.user.assistant_profile
        job = AssistantJob.objects.filter(assistant=assistant, teacher=teacher, is_active=True).first()
        if not job:
            return Response({'error': 'ليس لديك صلاحية للوصول إلى مجموعات هذا المعلم.'}, status=status.HTTP_403_FORBIDDEN)

        groups = teacher.groups.all().order_by('-created_at')
        allowed_ids = list(teacher.get_allowed_group_ids()) if teacher.has_active_subscription() else []
        return Response({
            'teacher': TeacherCardSerializer(teacher, context={'request': request}).data,
            'job': AssistantJobSerializer(job, context={'request': request}).data,
            'allowed_group_ids': allowed_ids,
            'groups': GroupSerializer(groups, many=True, context={'request': request}).data,
        })

    def post(self, request, teacher_id):
        teacher = get_object_or_404(TeacherProfile, id=teacher_id)
        assistant = request.user.assistant_profile
        if not AssistantJob.objects.filter(assistant=assistant, teacher=teacher, is_active=True).exists():
            return Response({'error': 'صلاحية غير كافية.'}, status=status.HTTP_403_FORBIDDEN)

        limit = teacher.current_plan.group_limit if teacher.current_plan else 5
        if teacher.groups.count() >= limit:
            return Response({'error': 'المعلم تجاوز حد المجموعات في الباقة.'}, status=status.HTTP_400_BAD_REQUEST)

        name = str(request.data.get('name', '')).strip()
        grade = str(request.data.get('grade', '')).strip()
        if not name or not grade:
            return Response({'error': 'اسم المجموعة والصف الدراسي مطلوبان.'}, status=status.HTTP_400_BAD_REQUEST)

        group = Group.objects.create(teacher=teacher, name=name, grade=grade)
        return Response({
            'message': f"تم إنشاء مجموعة '{group.name}' للمعلم.",
            'group': GroupSerializer(group, context={'request': request}).data,
        }, status=status.HTTP_201_CREATED)


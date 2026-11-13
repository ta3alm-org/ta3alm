"""
api_v1/views_student.py
جميع نقاط النهاية الخاصة بالطالب (المجموعات، المحاضرات، أكواد الفيديو، الامتحانات، الدرجات، الترتيب، الحزم).
"""
from django.db import transaction
from django.db.models import Q, Sum
from django.shortcuts import get_object_or_404
from django.utils import timezone
from rest_framework import status
from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView

from core.models import Subject
from core.utils import send_notification
from exams.models import Exam, ExamResult
from students.models import (
    Enrollment,
    PerformanceLog,
    PackageEnrollment,
    VideoViewTracking,
    PackageExamResult,
)
from students.views import check_student_access, calculate_leaderboard
from teachers.models import Group, Lecture, VideoCode, CoursePackage

from .permissions import IsStudentRole, IsNotBanned
from .serializers import (
    EnrollmentSerializer,
    PackageEnrollmentSerializer,
    GroupSerializer,
    LectureSerializer,
    LectureStudentListSerializer,
    ExamSerializer,
    QuestionStudentSerializer,
    ExamResultSerializer,
    PackageExamResultSerializer,
    PerformanceLogSerializer,
    PDFFileSerializer,
    CoursePackageSerializer,
    TeacherCardSerializer,
    AssistantJobSerializer,
    VideoViewTrackingSerializer,
)


def _access_error_response(access_status: str, group: Group | None = None):
    teacher_name = group.teacher.user.first_name if group else ''
    messages_map = {
        'not_student': ('هذه الخدمة متاحة للطلاب فقط.', status.HTTP_403_FORBIDDEN),
        'teacher_expired': (f'اشتراك المستر {teacher_name} منتهي حالياً.', status.HTTP_403_FORBIDDEN),
        'not_enrolled': ('أنت غير مشترك في هذه المجموعة أو لم يتم قبول طلبك بعد.', status.HTTP_403_FORBIDDEN),
        'limit_exceeded': (f'تجاوزت المجموعة الحد الأقصى لباقة المستر {teacher_name}.', status.HTTP_403_FORBIDDEN),
        'group_locked_by_plan': ('هذه المجموعة مغلقة حالياً بسبب قيود باقة المعلم.', status.HTTP_403_FORBIDDEN),
    }
    msg, code = messages_map.get(access_status, ('غير مسموح بالوصول.', status.HTTP_403_FORBIDDEN))
    return Response({'error': msg, 'access_status': access_status}, status=code)


class StudentDashboardAPIView(APIView):
    """لوحة تحكم الطالب: المجموعات النشطة، المغلقة، طلبات الانتظار، والحزم المشتراة."""
    permission_classes = [IsAuthenticated, IsStudentRole]

    def get(self, request):
        if not hasattr(request.user, 'student_profile'):
            return Response({'error': 'يرجى استكمال الملف الشخصي أولاً.', 'require_complete_profile': True}, status=status.HTTP_400_BAD_REQUEST)

        student = request.user.student_profile
        enrollments = (
            student.enrollments
            .filter(is_active=True)
            .select_related('group__teacher__current_plan', 'group__teacher__user', 'group__teacher__subject')
        )
        pending_groups = (
            student.enrollments
            .filter(is_active=False)
            .select_related('group__teacher__user', 'group__teacher__subject')
        )
        my_packages = (
            PackageEnrollment.objects
            .filter(student=student, is_paid=True)
            .select_related('package__teacher__user', 'package__teacher__subject')
        )

        active_enrollments = []
        locked_enrollments = []
        for enroll in enrollments:
            allowed_ids = list(enroll.group.teacher.get_allowed_group_ids())
            if enroll.group.id in allowed_ids and enroll.group.teacher.has_active_subscription():
                active_enrollments.append(enroll)
            else:
                locked_enrollments.append(enroll)

        return Response({
            'active_groups': EnrollmentSerializer(active_enrollments, many=True, context={'request': request}).data,
            'locked_groups': EnrollmentSerializer(locked_enrollments, many=True, context={'request': request}).data,
            'pending_groups': EnrollmentSerializer(pending_groups, many=True, context={'request': request}).data,
            'my_packages': PackageEnrollmentSerializer(my_packages, many=True, context={'request': request}).data,
        })


class StudentSearchGroupsAPIView(APIView):
    """البحث عن المجموعات الدراسية بالاسم أو المعلم أو الصف أو المادة."""
    permission_classes = [IsAuthenticated, IsNotBanned]

    def get(self, request):
        groups = Group.objects.select_related('teacher__user', 'teacher__subject', 'teacher__current_plan').order_by('-created_at')
        query = request.query_params.get('q', '').strip()
        grade = request.query_params.get('grade', '').strip()
        subject_id = request.query_params.get('subject', '').strip()

        if query:
            groups = groups.filter(
                Q(name__icontains=query)
                | Q(teacher__user__first_name__icontains=query)
                | Q(teacher__user__last_name__icontains=query)
                | Q(teacher__subject__name__icontains=query)
            )
        if grade:
            groups = groups.filter(grade=grade)
        if subject_id:
            groups = groups.filter(teacher__subject_id=subject_id)

        enrollment_map = {}
        if request.user.role == 'student' and hasattr(request.user, 'student_profile'):
            for e in request.user.student_profile.enrollments.all():
                enrollment_map[e.group_id] = 'active' if e.is_active else 'pending'

        data = GroupSerializer(groups, many=True, context={'request': request}).data
        for item in data:
            item['enrollment_status'] = enrollment_map.get(item['id'], 'none')

        return Response({'groups': data})


class StudentJoinGroupAPIView(APIView):
    """إرسال طلب انضمام لمجموعة دراسية."""
    permission_classes = [IsAuthenticated, IsStudentRole]

    def post(self, request, group_id):
        student = request.user.student_profile
        group = get_object_or_404(Group, id=group_id)
        teacher = group.teacher

        if Enrollment.objects.filter(student=student, group=group).exists():
            return Response(
                {'error': 'أنت بالفعل عضو في هذه المجموعة أو الطلب قيد الانتظار.'},
                status=status.HTTP_400_BAD_REQUEST,
            )

        if teacher.get_total_students() >= teacher.get_student_limit():
            return Response(
                {'error': 'عفواً، لا يمكن الانضمام. لقد وصل المعلم للحد الأقصى من الطلاب.'},
                status=status.HTTP_400_BAD_REQUEST,
            )

        enroll = Enrollment.objects.create(student=student, group=group, is_active=False)
        send_notification(
            group.teacher.user,
            'طلب انضمام جديد',
            f'الطالب {student.user.first_name} طلب الانضمام لمجموعة {group.name}',
            f'/teacher/group/{group.id}/requests/',
        )
        return Response({
            'message': f"تم إرسال طلب الانضمام لمجموعة '{group.name}' بنجاح، في انتظار موافقة المعلم.",
            'enrollment': EnrollmentSerializer(enroll, context={'request': request}).data,
        }, status=status.HTTP_201_CREATED)


class StudentGroupContentAPIView(APIView):
    """محتوى المجموعة للطالب (المحاضرات، الامتحانات، الملفات، حالة الفتح)."""
    permission_classes = [IsAuthenticated, IsStudentRole]

    def get(self, request, group_id):
        group, access_status = check_student_access(request.user, group_id)
        if access_status != 'ok':
            return _access_error_response(access_status, group)

        student = request.user.student_profile
        lectures = group.lectures.filter(is_active=True).order_by('-created_at')
        # نتحقق بدقة من عدم انتهاء صلاحية الكود
        valid_unlocked_ids = set()
        for vc in VideoCode.objects.filter(used_by=student, lecture__group=group):
            if vc.current_views < vc.max_views:
                valid_unlocked_ids.add(vc.lecture_id)

        exams = group.exams.filter(is_active=True).order_by('-created_at')
        taken_map = {
            r.exam_id: r.score
            for r in ExamResult.objects.filter(student=student, exam__group=group)
        }
        pdfs = group.pdfs.all().order_by('-created_at')

        return Response({
            'group': GroupSerializer(group, context={'request': request}).data,
            'lectures': LectureStudentListSerializer(
                lectures, many=True, context={'unlocked_ids': valid_unlocked_ids}
            ).data,
            'exams': ExamSerializer(exams, many=True, context={'taken_map': taken_map}).data,
            'pdfs': PDFFileSerializer(pdfs, many=True).data,
        })


class StudentWatchGroupLectureAPIView(APIView):
    """مشاهدة محاضرة مجموعة أو تفعيل كود فيديو جديد."""
    permission_classes = [IsAuthenticated, IsStudentRole]

    def get(self, request, lecture_id):
        lecture = get_object_or_404(Lecture, id=lecture_id, is_active=True)
        if not lecture.group:
            return Response({'error': 'هذه المحاضرة لا تتبع مجموعة.'}, status=status.HTTP_400_BAD_REQUEST)

        group, access_status = check_student_access(request.user, lecture.group.id)
        if access_status != 'ok':
            return _access_error_response(access_status, group)

        student = request.user.student_profile
        active_code = VideoCode.objects.filter(lecture=lecture, used_by=student).order_by('-used_at').first()

        if not active_code or active_code.current_views >= active_code.max_views:
            return Response({
                'is_unlocked': False,
                'lecture': {
                    'id': lecture.id,
                    'title': lecture.title,
                    'description': lecture.description,
                },
                'message': 'يرجى إدخال كود المشاهدة لفتح الفيديو.' if not active_code else 'لقد استهلكت عدد مرات مشاهدة هذا الكود. يرجى إدخال كود جديد.',
            })

        # زيادة عداد المشاهدة عند طلب تشغيل الفيديو
        if request.query_params.get('record_view', 'true').lower() == 'true':
            active_code.current_views += 1
            active_code.save(update_fields=['current_views'])

        return Response({
            'is_unlocked': True,
            'lecture': LectureSerializer(lecture, context={'for_student': True}).data,
            'code_info': {
                'code': active_code.code,
                'current_views': active_code.current_views,
                'max_views': active_code.max_views,
                'remaining_views': max(active_code.max_views - active_code.current_views, 0),
            },
        })

    @transaction.atomic
    def post(self, request, lecture_id):
        """تفعيل كود مشاهدة جديد للمحاضرة."""
        lecture = get_object_or_404(Lecture, id=lecture_id, is_active=True)
        if not lecture.group:
            return Response({'error': 'هذه المحاضرة لا تتبع مجموعة.'}, status=status.HTTP_400_BAD_REQUEST)

        group, access_status = check_student_access(request.user, lecture.group.id)
        if access_status != 'ok':
            return _access_error_response(access_status, group)

        code_input = str(request.data.get('code', '')).strip().upper()
        if not code_input:
            return Response({'error': 'يرجى إدخال الكود.'}, status=status.HTTP_400_BAD_REQUEST)

        try:
            new_code = VideoCode.objects.select_for_update().get(
                code__iexact=code_input,
                lecture=lecture,
                is_used=False,
            )
        except VideoCode.DoesNotExist:
            return Response({'error': 'الكود غير صحيح أو مستخدم من قبل.'}, status=status.HTTP_400_BAD_REQUEST)

        new_code.is_used = True
        new_code.used_by = request.user.student_profile
        new_code.used_at = timezone.now()
        new_code.save()

        return Response({
            'message': 'تم تفعيل الكود بنجاح!',
            'is_unlocked': True,
            'lecture': LectureSerializer(lecture, context={'for_student': True}).data,
            'code_info': {
                'code': new_code.code,
                'current_views': new_code.current_views,
                'max_views': new_code.max_views,
                'remaining_views': new_code.max_views - new_code.current_views,
            },
        })


class StudentTakeGroupExamAPIView(APIView):
    """جلب أسئلة امتحان المجموعة وتصحيح الإجابات."""
    permission_classes = [IsAuthenticated, IsStudentRole]

    def get(self, request, exam_id):
        exam = get_object_or_404(Exam, id=exam_id)
        if not exam.group:
            return Response({'error': 'هذا الامتحان لا يتبع مجموعة.'}, status=status.HTTP_400_BAD_REQUEST)

        group, access_status = check_student_access(request.user, exam.group.id)
        if access_status != 'ok':
            return _access_error_response(access_status, group)

        if not exam.is_active:
            return Response({'error': 'هذا الامتحان مغلق حالياً.'}, status=status.HTTP_403_FORBIDDEN)

        student = request.user.student_profile
        existing = ExamResult.objects.filter(student=student, exam=exam).first()
        if existing:
            return Response({
                'error': 'لقد قمت بأداء هذا الامتحان مسبقاً.',
                'already_taken': True,
                'score': existing.score,
                'total_marks': exam.total_marks(),
            }, status=status.HTTP_400_BAD_REQUEST)

        questions = exam.questions.all()
        return Response({
            'exam': ExamSerializer(exam).data,
            'questions': QuestionStudentSerializer(questions, many=True, context={'request': request}).data,
        })

    @transaction.atomic
    def post(self, request, exam_id):
        exam = get_object_or_404(Exam, id=exam_id)
        if not exam.group:
            return Response({'error': 'هذا الامتحان لا يتبع مجموعة.'}, status=status.HTTP_400_BAD_REQUEST)

        group, access_status = check_student_access(request.user, exam.group.id)
        if access_status != 'ok':
            return _access_error_response(access_status, group)

        if not exam.is_active:
            return Response({'error': 'هذا الامتحان مغلق حالياً.'}, status=status.HTTP_403_FORBIDDEN)

        student = request.user.student_profile
        if ExamResult.objects.filter(student=student, exam=exam).exists():
            return Response({'error': 'لقد قمت بأداء هذا الامتحان مسبقاً.'}, status=status.HTTP_400_BAD_REQUEST)

        answers = request.data.get('answers', {})
        score = 0
        questions = exam.questions.all()
        for q in questions:
            selected = str(answers.get(str(q.id)) or answers.get(q.id) or request.data.get(f'question_{q.id}', '')).strip().upper()
            if selected == q.correct_answer:
                score += q.marks

        result = ExamResult.objects.create(student=student, exam=exam, score=score)
        total = exam.total_marks()
        return Response({
            'message': f'تم تسليم الامتحان بنجاح! درجتك: {score} من {total}',
            'score': score,
            'total_marks': total,
            'result': ExamResultSerializer(result).data,
        }, status=status.HTTP_201_CREATED)


class StudentGroupMarksAPIView(APIView):
    """سجل درجات الطالب وحضوره وامتحاناته داخل المجموعة."""
    permission_classes = [IsAuthenticated, IsStudentRole]

    def get(self, request, group_id):
        group, access_status = check_student_access(request.user, group_id)
        if access_status != 'ok':
            return _access_error_response(access_status, group)

        student = request.user.student_profile
        logs = PerformanceLog.objects.filter(student=student, group=group).order_by('-date', '-id')
        month = request.query_params.get('month')
        if month and str(month).isdigit():
            logs = logs.filter(date__month=int(month))

        exam_results = ExamResult.objects.filter(student=student, exam__group=group).select_related('exam').order_by('-submitted_at')

        return Response({
            'group': GroupSerializer(group, context={'request': request}).data,
            'performance_logs': PerformanceLogSerializer(logs, many=True).data,
            'exam_results': ExamResultSerializer(exam_results, many=True).data,
        })


class StudentGroupRankingAPIView(APIView):
    """لوحة شرف وترتيب الطلاب في المجموعة."""
    permission_classes = [IsAuthenticated, IsStudentRole]

    def get(self, request, group_id):
        group, access_status = check_student_access(request.user, group_id)
        if access_status != 'ok':
            return _access_error_response(access_status, group)

        raw_board = calculate_leaderboard(group)
        my_rank = next((item['rank'] for item in raw_board if item['student'] == request.user.student_profile), None)
        board_data = [
            {
                'rank': item['rank'],
                'student_id': item['student'].id,
                'student_name': f"{item['student'].user.first_name} {item['student'].user.last_name}".strip(),
                'total_score': item['total_score'],
                'is_me': item['student'] == request.user.student_profile,
            }
            for item in raw_board[:20]
        ]
        return Response({
            'my_rank': my_rank,
            'leaderboard': board_data,
        })


class StudentGroupContactAPIView(APIView):
    """بيانات التواصل مع المعلم والمساعدين النشطين للمجموعة."""
    permission_classes = [IsAuthenticated, IsStudentRole]

    def get(self, request, group_id):
        group, access_status = check_student_access(request.user, group_id)
        if access_status != 'ok':
            return _access_error_response(access_status, group)

        teacher = group.teacher
        assistants = teacher.assistants_jobs.filter(is_active=True).select_related('assistant__user')
        return Response({
            'teacher': TeacherCardSerializer(teacher, context={'request': request}).data,
            'assistants': AssistantJobSerializer(assistants, many=True, context={'request': request}).data,
        })


class StudentPackagesStoreAPIView(APIView):
    """متجر الحزم التعليمية الأونلاين."""
    permission_classes = [AllowAny]

    def get(self, request):
        packages = (
            CoursePackage.objects
            .select_related('teacher__user', 'teacher__subject', 'teacher__current_plan')
            .filter(is_active=True, teacher__current_plan__allow_online_packages=True)
            .order_by('-created_at')
        )
        grade = request.query_params.get('grade', '').strip()
        subject_id = request.query_params.get('subject', '').strip()
        query = request.query_params.get('q', '').strip()

        if grade:
            packages = packages.filter(grade=grade)
        if subject_id:
            packages = packages.filter(teacher__subject_id=subject_id)
        if query:
            packages = packages.filter(
                Q(title__icontains=query)
                | Q(teacher__user__first_name__icontains=query)
                | Q(teacher__user__last_name__icontains=query)
            )

        return Response({
            'packages': CoursePackageSerializer(packages, many=True, context={'request': request}).data,
        })


class StudentPackageDetailAPIView(APIView):
    """تفاصيل حزمة أونلاين وحالة اشتراك الطالب فيها."""
    permission_classes = [AllowAny]

    def get(self, request, package_id):
        package = get_object_or_404(CoursePackage, id=package_id)
        return Response(CoursePackageSerializer(package, context={'request': request}).data)


class StudentMyPackageContentAPIView(APIView):
    """محتوى الحزمة المشترك بها الطالب (محاضرات، امتحانات، ملفات، تقدم المشاهدة)."""
    permission_classes = [IsAuthenticated, IsStudentRole]

    def get(self, request, package_id):
        student = request.user.student_profile
        package = get_object_or_404(CoursePackage, id=package_id)

        if not PackageEnrollment.objects.filter(student=student, package=package, is_paid=True).exists():
            return Response({'error': 'يجب شراء الحزمة أولاً للوصول إلى محتواها.'}, status=status.HTTP_403_FORBIDDEN)

        lectures = package.lectures.all().order_by('-created_at')
        exams = package.exams.filter(is_active=True).order_by('-created_at')
        pdfs = package.pdfs.all().order_by('-created_at')

        trackers = {
            t.lecture_id: t
            for t in VideoViewTracking.objects.filter(student=student, package=package)
        }
        taken_map = {
            r.exam_id: r.score
            for r in PackageExamResult.objects.filter(student=student, package=package)
        }

        lectures_data = []
        for lec in lectures:
            tr = trackers.get(lec.id)
            views_used = tr.views_count if tr else 0
            lectures_data.append({
                'id': lec.id,
                'title': lec.title,
                'description': lec.description,
                'views_used': views_used,
                'view_limit': package.view_limit,
                'remaining_views': max(package.view_limit - views_used, 0),
                'is_completed': tr.is_completed if tr else False,
                'points_awarded': tr.points_awarded if tr else 0,
                'created_at': lec.created_at,
            })

        return Response({
            'package': CoursePackageSerializer(package, context={'request': request}).data,
            'lectures': lectures_data,
            'exams': ExamSerializer(exams, many=True, context={'taken_map': taken_map}).data,
            'pdfs': PDFFileSerializer(pdfs, many=True).data,
        })


class StudentWatchPackageLectureAPIView(APIView):
    """مشاهدة محاضرة داخل حزمة مدفوعة مع احتساب 10 نقاط والتحقق من حد المشاهدة."""
    permission_classes = [IsAuthenticated, IsStudentRole]

    @transaction.atomic
    def post(self, request, package_id, lecture_id):
        student = request.user.student_profile
        package = get_object_or_404(CoursePackage, id=package_id)
        lecture = get_object_or_404(Lecture, id=lecture_id)

        if not package.lectures.filter(id=lecture.id).exists():
            return Response({'error': 'هذه المحاضرة غير مدرجة ضمن الحزمة.'}, status=status.HTTP_404_NOT_FOUND)

        if not PackageEnrollment.objects.filter(student=student, package=package, is_paid=True).exists():
            return Response({'error': 'يجب شراء الحزمة أولاً.'}, status=status.HTTP_403_FORBIDDEN)

        tracker, _ = VideoViewTracking.objects.select_for_update().get_or_create(
            student=student, package=package, lecture=lecture
        )

        if tracker.views_count >= package.view_limit:
            return Response(
                {'error': 'لقد استهلكت عدد مرات مشاهدة هذا الفيديو في الباقة.'},
                status=status.HTTP_403_FORBIDDEN,
            )

        points_just_awarded = False
        if not tracker.is_completed:
            tracker.is_completed = True
            tracker.points_awarded = 10
            points_just_awarded = True

        tracker.views_count += 1
        tracker.save()

        return Response({
            'message': 'تم احتساب 10 درجات مشاهدة!' if points_just_awarded else 'مشاهدة ممتعة!',
            'points_just_awarded': points_just_awarded,
            'lecture': LectureSerializer(lecture, context={'for_student': True}).data,
            'tracker': VideoViewTrackingSerializer(tracker).data,
            'view_limit': package.view_limit,
            'remaining_views': max(package.view_limit - tracker.views_count, 0),
        })


class StudentTakePackageExamAPIView(APIView):
    """أداء وتصحيح امتحان داخل حزمة أونلاين."""
    permission_classes = [IsAuthenticated, IsStudentRole]

    def get(self, request, package_id, exam_id):
        student = request.user.student_profile
        package = get_object_or_404(CoursePackage, id=package_id)
        exam = get_object_or_404(Exam, id=exam_id)

        if not PackageEnrollment.objects.filter(student=student, package=package, is_paid=True).exists():
            return Response({'error': 'يجب شراء الحزمة أولاً.'}, status=status.HTTP_403_FORBIDDEN)

        existing = PackageExamResult.objects.filter(student=student, package=package, exam=exam).first()
        if existing:
            return Response({
                'error': 'لقد أديت هذا الامتحان داخل الحزمة مسبقاً.',
                'already_taken': True,
                'score': existing.score,
                'total_marks': exam.total_marks(),
            }, status=status.HTTP_400_BAD_REQUEST)

        questions = exam.questions.all()
        return Response({
            'exam': ExamSerializer(exam).data,
            'questions': QuestionStudentSerializer(questions, many=True, context={'request': request}).data,
        })

    @transaction.atomic
    def post(self, request, package_id, exam_id):
        student = request.user.student_profile
        package = get_object_or_404(CoursePackage, id=package_id)
        exam = get_object_or_404(Exam, id=exam_id)

        if not PackageEnrollment.objects.filter(student=student, package=package, is_paid=True).exists():
            return Response({'error': 'يجب شراء الحزمة أولاً.'}, status=status.HTTP_403_FORBIDDEN)

        if PackageExamResult.objects.filter(student=student, package=package, exam=exam).exists():
            return Response({'error': 'لقد أديت هذا الامتحان داخل الحزمة مسبقاً.'}, status=status.HTTP_400_BAD_REQUEST)

        answers = request.data.get('answers', {})
        score = 0
        for q in exam.questions.all():
            selected = str(answers.get(str(q.id)) or answers.get(q.id) or request.data.get(f'question_{q.id}', '')).strip().upper()
            if selected == q.correct_answer:
                score += q.marks

        result = PackageExamResult.objects.create(
            student=student, package=package, exam=exam, score=score
        )
        total = exam.total_marks()
        return Response({
            'message': f'تم تسليم الامتحان. درجتك: {score} من {total}',
            'score': score,
            'total_marks': total,
            'result': PackageExamResultSerializer(result).data,
        }, status=status.HTTP_201_CREATED)


class StudentPackageMarksAndRankingAPIView(APIView):
    """درجات الطالب ونقاط المشاهدة ولوحة الشرف داخل الحزمة."""
    permission_classes = [IsAuthenticated, IsStudentRole]

    def get(self, request, package_id):
        student = request.user.student_profile
        package = get_object_or_404(CoursePackage, id=package_id)

        if not PackageEnrollment.objects.filter(student=student, package=package, is_paid=True).exists():
            return Response({'error': 'يجب شراء الحزمة أولاً.'}, status=status.HTTP_403_FORBIDDEN)

        exam_results = PackageExamResult.objects.filter(student=student, package=package).select_related('exam')
        video_points = VideoViewTracking.objects.filter(student=student, package=package, is_completed=True).select_related('lecture')
        total_score = sum(r.score for r in exam_results) + sum(v.points_awarded for v in video_points)

        enrollments = package.enrollments.filter(is_paid=True).select_related('student__user')
        leaderboard = []
        for enroll in enrollments:
            std = enroll.student
            v_pts = VideoViewTracking.objects.filter(student=std, package=package).aggregate(t=Sum('points_awarded'))['t'] or 0
            e_pts = PackageExamResult.objects.filter(student=std, package=package).aggregate(t=Sum('score'))['t'] or 0
            leaderboard.append({
                'student_id': std.id,
                'student_name': f"{std.user.first_name} {std.user.last_name}".strip(),
                'score': v_pts + e_pts,
                'is_me': std == student,
            })

        leaderboard.sort(key=lambda x: x['score'], reverse=True)
        for idx, item in enumerate(leaderboard):
            item['rank'] = idx + 1

        my_rank = next((item['rank'] for item in leaderboard if item['is_me']), None)

        return Response({
            'total_score': total_score,
            'my_rank': my_rank,
            'exam_results': PackageExamResultSerializer(exam_results, many=True).data,
            'video_points': VideoViewTrackingSerializer(video_points, many=True).data,
            'leaderboard': leaderboard[:30],
        })

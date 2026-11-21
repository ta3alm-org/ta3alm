"""api_v1.views.student.groups
Extracted from api_v1/views_student.py.
"""

from django.db import transaction
from django.db.models import Q
from django.shortcuts import get_object_or_404
from django.utils import timezone
from rest_framework import status
from rest_framework.permissions import (
    AllowAny,
    IsAuthenticated,
)
from rest_framework.response import Response
from rest_framework.views import APIView
from api_v1.device_security_service import check_web_ios_only_lecture_access
from api_v1.video_security import (
    clear_watch_window,
    grant_watch_window,
    has_active_watch_window,
)
from exams.models import (
    Exam,
    ExamResult,
)
from students.models import (
    Enrollment,
    PerformanceLog,
    PackageEnrollment,
)
from students.views import (
    check_student_access,
    calculate_leaderboard,
)
from teachers.models import (
    Group,
    Lecture,
    VideoCode,
)
from api_v1.permissions import IsStudentRole
from api_v1.serializers import (
    EnrollmentSerializer,
    PackageEnrollmentSerializer,
    GroupSerializer,
    LectureSerializer,
    LectureStudentListSerializer,
    ExamSerializer,
    QuestionStudentSerializer,
    ExamResultSerializer,
    PerformanceLogSerializer,
    PDFFileSerializer,
    TeacherCardSerializer,
    AssistantJobSerializer,
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
    """البحث عن المجموعات الدراسية بالاسم أو المعلم أو الصف أو المادة (متاح للزوار والطلاب)."""
    permission_classes = [AllowAny]

    def get(self, request):
        groups = (
            Group.objects
            .select_related('teacher__user', 'teacher__subject', 'teacher__current_plan')
            .filter(teacher__is_approved=True, teacher__user__is_banned=False)
            .order_by('-created_at')
        )
        query = request.query_params.get('q', '').strip()
        grade = request.query_params.get('grade', '').strip()
        subject_id = request.query_params.get('subject', '').strip()
        teacher_id = request.query_params.get('teacher_id', '').strip()

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
            if subject_id.isdigit():
                groups = groups.filter(teacher__subject_id=int(subject_id))
            else:
                groups = groups.filter(teacher__subject__name__icontains=subject_id)
        if teacher_id and teacher_id.isdigit():
            groups = groups.filter(teacher_id=int(teacher_id))

        enrollment_map = {}
        user = getattr(request, 'user', None)
        if user and user.is_authenticated and getattr(user, 'role', '') == 'student' and hasattr(user, 'student_profile'):
            for e in user.student_profile.enrollments.all():
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

        if not teacher.is_approved or teacher.user.is_banned:
            return Response(
                {'error': 'هذا المعلم غير متاح للانضمام حالياً.'},
                status=status.HTTP_400_BAD_REQUEST,
            )

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
        # نتحقق بدقة من عدم انتهاء صلاحية الكود أو وجود نافذة مشاهدة نشطة
        if request.query_params.get('clear_watch') == '1' or request.query_params.get('exited_player') == '1':
            clear_watch_window(request.user)

        valid_unlocked_ids = set()
        now = timezone.now()
        for vc in VideoCode.objects.filter(used_by=student, lecture__group=group):
            in_watch_window = has_active_watch_window(request.user, vc.lecture_id, now=now)
            if vc.current_views < vc.max_views or (in_watch_window and vc.current_views <= vc.max_views):
                valid_unlocked_ids.add(vc.lecture_id)

        exams = group.exams.filter(is_active=True).order_by('-created_at')
        taken_map = {
            r.exam_id: r.score
            for r in ExamResult.objects.filter(student=student, exam__group=group)
        }
        pdfs = group.pdfs.all().order_by('-created_at')

        ios_access = check_web_ios_only_lecture_access(request, request.user)
        web_lectures_allowed = bool(ios_access.get('allowed'))

        return Response({
            'group': GroupSerializer(group, context={'request': request}).data,
            'lectures': (
                LectureStudentListSerializer(
                    lectures, many=True, context={'unlocked_ids': valid_unlocked_ids}
                ).data
                if web_lectures_allowed
                else []
            ),
            'lectures_blocked': not web_lectures_allowed,
            'lectures_block_reason': '' if web_lectures_allowed else (ios_access.get('error') or ''),
            'lectures_block_code': '' if web_lectures_allowed else (ios_access.get('code') or 'WEB_LECTURES_IOS_ONLY'),
            'exams': ExamSerializer(exams, many=True, context={'taken_map': taken_map}).data,
            'pdfs': PDFFileSerializer(pdfs, many=True, context={'request': request}).data,
        })


def _is_in_student_watch_window(user, lecture, window_minutes: int = 20) -> bool:
    return has_active_watch_window(user, lecture.id)


def _mark_student_watch_window(user, lecture) -> None:
    grant_watch_window(user, lecture.id)


class StudentWatchGroupLectureAPIView(APIView):
    """مشاهدة محاضرة مجموعة أو تفعيل كود فيديو جديد."""
    permission_classes = [IsAuthenticated, IsStudentRole]

    @transaction.atomic
    def get(self, request, lecture_id):
        ios_access = check_web_ios_only_lecture_access(request, request.user)
        if not ios_access.get('allowed'):
            return Response(
                {
                    'error': ios_access.get('error'),
                    'blocked': True,
                    'code': ios_access.get('code') or 'WEB_LECTURES_IOS_ONLY',
                    'device_kind': ios_access.get('device_kind'),
                },
                status=status.HTTP_403_FORBIDDEN,
            )

        lecture = get_object_or_404(Lecture, id=lecture_id, is_active=True)
        if not lecture.group:
            return Response({'error': 'هذه المحاضرة لا تتبع مجموعة.'}, status=status.HTTP_400_BAD_REQUEST)

        group, access_status = check_student_access(request.user, lecture.group.id)
        if access_status != 'ok':
            return _access_error_response(access_status, group)

        student = request.user.student_profile
        active_code = (
            VideoCode.objects.select_for_update()
            .filter(lecture=lecture, used_by=student)
            .order_by('-used_at')
            .first()
        )
        in_window = _is_in_student_watch_window(request.user, lecture)

        can_resume = bool(active_code and in_window and active_code.current_views <= active_code.max_views)
        if not active_code or (active_code.current_views >= active_code.max_views and not can_resume):
            return Response({
                'is_unlocked': False,
                'lecture': {
                    'id': lecture.id,
                    'title': lecture.title,
                    'description': lecture.description,
                },
                'message': 'يرجى إدخال كود المشاهدة لفتح الفيديو.' if not active_code else 'لقد استهلكت عدد مرات مشاهدة هذا الكود. يرجى إدخال كود جديد.',
            })

        # زيادة عداد المشاهدة مرة واحدة فقط خلال نافذة المشاهدة النشطة (إلزامي دون تجاوز)
        if not in_window:
            active_code.current_views += 1
            active_code.save(update_fields=['current_views'])
            _mark_student_watch_window(request.user, lecture)

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
        ios_access = check_web_ios_only_lecture_access(request, request.user)
        if not ios_access.get('allowed'):
            return Response(
                {
                    'error': ios_access.get('error'),
                    'blocked': True,
                    'code': ios_access.get('code') or 'WEB_LECTURES_IOS_ONLY',
                    'device_kind': ios_access.get('device_kind'),
                },
                status=status.HTTP_403_FORBIDDEN,
            )

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

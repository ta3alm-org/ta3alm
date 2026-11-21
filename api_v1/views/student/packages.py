"""api_v1.views.student.packages
Extracted from api_v1/views_student.py.
"""

from django.db import transaction
from django.db.models import (
    Q,
    Sum,
)
from django.shortcuts import get_object_or_404
from rest_framework import status
from rest_framework.permissions import (
    AllowAny,
    IsAuthenticated,
)
from rest_framework.response import Response
from rest_framework.views import APIView
from api_v1.device_security_service import check_web_ios_only_lecture_access
from api_v1.video_security import clear_watch_window
from exams.models import Exam
from students.models import (
    PackageEnrollment,
    VideoViewTracking,
    PackageExamResult,
)
from teachers.models import (
    Lecture,
    CoursePackage,
)
from api_v1.permissions import IsStudentRole
from api_v1.serializers import (
    LectureSerializer,
    ExamSerializer,
    QuestionStudentSerializer,
    PackageExamResultSerializer,
    PDFFileSerializer,
    CoursePackageSerializer,
    VideoViewTrackingSerializer,
)

from api_v1.views.student.groups import (
    _is_in_student_watch_window,
    _mark_student_watch_window,
)


class StudentPackagesStoreAPIView(APIView):
    """متجر الحزم التعليمية الأونلاين."""
    permission_classes = [AllowAny]

    def get(self, request):
        packages = (
            CoursePackage.objects
            .select_related('teacher__user', 'teacher__subject', 'teacher__current_plan')
            .filter(
                is_active=True,
                teacher__is_approved=True,
                teacher__user__is_banned=False,
                teacher__current_plan__allow_online_packages=True,
            )
            .order_by('-created_at')
        )
        grade = request.query_params.get('grade', '').strip()
        subject_id = request.query_params.get('subject', '').strip()
        teacher_id = request.query_params.get('teacher_id', '').strip()
        query = request.query_params.get('q', '').strip()

        if grade:
            packages = packages.filter(grade=grade)
        if subject_id:
            if subject_id.isdigit():
                packages = packages.filter(teacher__subject_id=int(subject_id))
            else:
                packages = packages.filter(teacher__subject__name__icontains=subject_id)
        if teacher_id and teacher_id.isdigit():
            packages = packages.filter(teacher_id=int(teacher_id))
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
        if request.query_params.get('clear_watch') == '1' or request.query_params.get('exited_player') == '1':
            clear_watch_window(request.user)
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

        ios_access = check_web_ios_only_lecture_access(request, request.user)
        web_lectures_allowed = bool(ios_access.get('allowed'))

        return Response({
            'package': CoursePackageSerializer(package, context={'request': request}).data,
            'lectures': lectures_data if web_lectures_allowed else [],
            'lectures_blocked': not web_lectures_allowed,
            'lectures_block_reason': '' if web_lectures_allowed else (ios_access.get('error') or ''),
            'lectures_block_code': '' if web_lectures_allowed else (ios_access.get('code') or 'WEB_LECTURES_IOS_ONLY'),
            'exams': ExamSerializer(exams, many=True, context={'taken_map': taken_map}).data,
            'pdfs': PDFFileSerializer(pdfs, many=True, context={'request': request}).data,
        })


class StudentWatchPackageLectureAPIView(APIView):
    """مشاهدة محاضرة داخل حزمة مدفوعة مع احتساب 10 نقاط والتحقق من حد المشاهدة."""
    permission_classes = [IsAuthenticated, IsStudentRole]

    @transaction.atomic
    def post(self, request, package_id, lecture_id):
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
        in_window = _is_in_student_watch_window(request.user, lecture)

        if tracker.views_count >= package.view_limit and not (in_window and tracker.views_count <= package.view_limit):
            return Response(
                {'error': 'لقد استهلكت عدد مرات مشاهدة هذا الفيديو في الباقة.'},
                status=status.HTTP_403_FORBIDDEN,
            )

        points_just_awarded = False
        if not in_window:
            if not tracker.is_completed:
                tracker.is_completed = True
                tracker.points_awarded = 10
                points_just_awarded = True

            tracker.views_count += 1
            tracker.save()
            _mark_student_watch_window(request.user, lecture)

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
        if request.query_params.get('clear_watch') == '1' or request.query_params.get('exited_player') == '1':
            clear_watch_window(request.user)
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

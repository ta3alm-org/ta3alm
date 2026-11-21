"""api_v1.views.teacher.students
Extracted from api_v1/views_teacher.py.
"""

from django.db import transaction
from django.db.models import Q
from django.shortcuts import get_object_or_404
from rest_framework import status
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView
from accounts.models import StudentProfile
from exams.models import (
    Exam,
    Question,
)
from students.models import (
    Enrollment,
    PerformanceLog,
)
from teachers.models import (
    Group,
    Lecture,
)
from teachers.views import (
    get_group_permission,
    calculate_leaderboard,
)
from api_v1.permissions import IsTeacherOrAssistantRole
from api_v1.serializers import (
    EnrollmentSerializer,
    PerformanceLogSerializer,
)


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

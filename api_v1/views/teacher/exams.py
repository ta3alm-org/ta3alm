"""api_v1.views.teacher.exams
Extracted from api_v1/views_teacher.py.
"""

from django.db.models import Q
from django.shortcuts import get_object_or_404
from rest_framework import status
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView
from exams.models import (
    Exam,
    Question,
)
from students.models import PackageExamResult
from teachers.views import (
    get_group_permission,
    get_package_permission,
)
from api_v1.permissions import IsTeacherOrAssistantRole
from api_v1.serializers import (
    ExamSerializer,
    QuestionTeacherSerializer,
    ExamResultSerializer,
    PackageExamResultSerializer,
)


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

        allow_images = True
        questions = exam.questions.all()
        q_search = request.query_params.get('q', '').strip()

        if exam.group:
            results = exam.results.select_related('student__user').order_by('-score')
            if q_search:
                results = results.filter(
                    Q(student__user__first_name__icontains=q_search)
                    | Q(student__user__last_name__icontains=q_search)
                    | Q(student__user__phone__icontains=q_search)
                )
            results_data = ExamResultSerializer(results, many=True).data
        else:
            results = PackageExamResult.objects.filter(exam=exam).select_related('student__user').order_by('-score')
            if q_search:
                results = results.filter(
                    Q(student__user__first_name__icontains=q_search)
                    | Q(student__user__last_name__icontains=q_search)
                    | Q(student__user__phone__icontains=q_search)
                )
            results_data = PackageExamResultSerializer(results, many=True).data

        return Response({
            'exam': ExamSerializer(exam).data,
            'allow_images': allow_images,
            'questions': QuestionTeacherSerializer(questions, many=True, context={'request': request}).data,
            'results': results_data,
        })

    def patch(self, request, exam_id):
        """تعديل بيانات الامتحان (العنوان، الوصف، المدة، الحالة)."""
        exam = get_object_or_404(Exam, id=exam_id)
        allowed, _ = _check_exam_permission(request, exam)
        if not allowed:
            return Response({'error': 'صلاحية غير كافية.'}, status=status.HTTP_403_FORBIDDEN)

        if 'title' in request.data:
            exam.title = str(request.data['title']).strip()
        if 'description' in request.data:
            exam.description = str(request.data['description']).strip()
        if 'duration_minutes' in request.data:
            exam.duration_minutes = int(request.data['duration_minutes'])
        if 'is_active' in request.data:
            exam.is_active = bool(request.data['is_active'])
        exam.save()
        return Response({
            'message': 'تم تحديث بيانات الامتحان بنجاح.',
            'exam': ExamSerializer(exam).data,
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

        allow_images = True
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

        allow_images = True
        for field in ('text', 'option_a', 'option_b', 'option_c', 'option_d', 'correct_answer'):
            if field in request.data:
                setattr(question, field, str(request.data[field]).strip())
        if 'marks' in request.data:
            question.marks = int(request.data['marks'])
        if request.data.get('clear_image') in (True, 'true', 'True', '1', 'on') or request.data.get('remove_image') in (True, 'true', 'True', '1', 'on'):
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

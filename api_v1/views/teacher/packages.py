"""api_v1.views.teacher.packages
Extracted from api_v1/views_teacher.py.
"""

from decimal import Decimal
from django.db import transaction
from django.shortcuts import get_object_or_404
from rest_framework import status
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView
from assistants.models import AssistantJob
from core.models import SiteSetting
from exams.models import (
    Exam,
    Question,
)
from teachers.models import (
    TeacherProfile,
    Lecture,
    CoursePackage,
)
from teachers.views import (
    get_package_permission,
    calculate_package_leaderboard,
)
from api_v1.permissions import IsTeacherOrAssistantRole
from api_v1.serializers import (
    LectureSerializer,
    PDFFileSerializer,
    ExamSerializer,
    CoursePackageSerializer,
    PackageEnrollmentSerializer,
)


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
        avail_groups = package.teacher.groups.filter(grade=package.grade).prefetch_related('lectures', 'exams')
        available_groups = [
            {
                'id': g.id,
                'name': g.name,
                'lectures': LectureSerializer(g.lectures.all(), many=True).data,
                'exams': ExamSerializer(g.exams.all(), many=True).data,
            }
            for g in avail_groups
        ]

        site_setting = SiteSetting.load()
        gross_revenue = enrollments.count() * package.price
        net_revenue = float((Decimal(str(gross_revenue)) * site_setting.teacher_share_ratio).quantize(Decimal('0.01')))

        return Response({
            'package': CoursePackageSerializer(package, context={'request': request}).data,
            'is_owner': is_owner,
            'lectures': LectureSerializer(package.lectures.all(), many=True).data,
            'exams': ExamSerializer(package.exams.all(), many=True).data,
            'pdfs': PDFFileSerializer(package.pdfs.all(), many=True, context={'request': request}).data,
            'students': PackageEnrollmentSerializer(enrollments, many=True, context={'request': request}).data,
            'total_revenue': gross_revenue,
            'gross_revenue': gross_revenue,
            'net_revenue': net_revenue,
            'platform_commission_percentage': site_setting.platform_commission_percentage,
            'available_groups': available_groups,
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

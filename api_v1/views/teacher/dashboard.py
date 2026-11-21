"""api_v1.views.teacher.dashboard
Extracted from api_v1/views_teacher.py.
"""

from django.shortcuts import get_object_or_404
from rest_framework import status
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView
from core.models import (
    SiteSetting,
    reconcile_teacher_wallet,
)
from core.notifications_service import maybe_notify_teacher_subscription_expiry
from teachers.models import (
    Group,
    Wallet,
)
from teachers.views import get_group_permission
from api_v1.permissions import (
    IsTeacherRole,
    IsTeacherOrAssistantRole,
)
from api_v1.serializers import (
    GroupSerializer,
    LectureSerializer,
    PDFFileSerializer,
    ExamSerializer,
    WalletSerializer,
    SubscriptionPlanSerializer,
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
        wallet = reconcile_teacher_wallet(teacher) or Wallet.objects.get_or_create(teacher=teacher)[0]
        site_setting = SiteSetting.load()
        maybe_notify_teacher_subscription_expiry(teacher)

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
            'platform_commission_percentage': site_setting.platform_commission_percentage,
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

        other_groups_qs = (
            group.teacher.groups
            .filter(grade=group.grade)
            .exclude(id=group.id)
            .prefetch_related('lectures', 'exams')
        )
        other_groups = [
            {
                'id': og.id,
                'name': og.name,
                'grade_display': og.get_grade_display(),
                'lectures': LectureSerializer(og.lectures.all(), many=True).data,
                'exams': ExamSerializer(og.exams.all(), many=True).data,
            }
            for og in other_groups_qs
        ]

        return Response({
            'group': GroupSerializer(group, context={'request': request}).data,
            'is_owner': is_owner,
            'pending_count': pending_count,
            'lectures': LectureSerializer(lectures, many=True).data,
            'exams': ExamSerializer(exams, many=True).data,
            'pdfs': PDFFileSerializer(pdfs, many=True, context={'request': request}).data,
            'other_groups': other_groups,
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

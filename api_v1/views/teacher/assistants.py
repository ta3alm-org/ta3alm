"""api_v1.views.teacher.assistants
Extracted from api_v1/views_teacher.py.
"""

from django.shortcuts import get_object_or_404
from rest_framework import status
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView
from assistants.models import (
    AssistantProfile,
    AssistantJob,
)
from teachers.models import (
    TeacherProfile,
    Group,
)
from api_v1.permissions import (
    IsTeacherRole,
    IsAssistantRole,
)
from api_v1.serializers import (
    GroupSerializer,
    AssistantJobSerializer,
    TeacherCardSerializer,
)


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

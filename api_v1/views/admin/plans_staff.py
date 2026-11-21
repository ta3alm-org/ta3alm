"""api_v1.views.admin.plans_staff
Extracted from api_v1/views_admin.py.
"""

import random
import string
from django.contrib.auth import get_user_model
from django.db import transaction
from django.shortcuts import get_object_or_404
from rest_framework import status
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView
from core.models import (
    Subject,
    CurriculumUnit,
    CurriculumLesson,
)
from dashboard_admin.models import (
    AdminProfile,
    AdminRole,
    AuditLog,
)
from teachers.models import SubscriptionPlan
from api_v1.permissions import IsPlatformOwner
from api_v1.serializers import (
    SubscriptionPlanSerializer,
    AdminProfileSerializer,
    AuditLogSerializer,
    CurriculumUnitSerializer,
    SubjectSerializer,
)

User = get_user_model()


class AdminPlansAndStaffAPIView(APIView):
    """إدارة الباقات، المناهج الدراسية، المواد، فريق الإدارة، وسجل الأحداث للمالك."""
    permission_classes = [IsAuthenticated, IsPlatformOwner]

    def get(self, request):
        plans = SubscriptionPlan.objects.all().order_by('price')
        staff = AdminProfile.objects.select_related('user', 'appointed_by').order_by('admin_role')
        action_filter = request.query_params.get('action_filter', '').strip()
        logs_qs = AuditLog.objects.select_related('admin').order_by('-created_at')
        if action_filter:
            logs_qs = logs_qs.filter(action=action_filter)
        units_qs = CurriculumUnit.objects.select_related('subject').prefetch_related('lessons').order_by('grade', 'subject', 'term', 'order')
        subjects = Subject.objects.all().order_by('name')

        return Response({
            'plans': SubscriptionPlanSerializer(plans, many=True).data,
            'staff': AdminProfileSerializer(staff, many=True).data,
            'admin_roles': [{'code': c, 'name': str(l)} for c, l in AdminRole.choices],
            'audit_logs': AuditLogSerializer(logs_qs[:100], many=True).data,
            'curriculum_units': CurriculumUnitSerializer(units_qs, many=True).data,
            'subjects': SubjectSerializer(subjects, many=True).data,
        })

    @transaction.atomic
    def post(self, request):
        action = request.data.get('action')
        if action == 'add_plan':
            plan = SubscriptionPlan.objects.create(
                name=str(request.data.get('name', '')).strip(),
                price=int(request.data.get('price', 0)),
                description=str(request.data.get('description', '')).strip(),
                student_limit=int(request.data.get('student_limit', 1000)),
                group_limit=int(request.data.get('group_limit', 5)),
                assistant_limit=int(request.data.get('assistant_limit', 2)),
                allow_online_packages=bool(request.data.get('allow_online_packages', False)),
                allow_question_images=bool(request.data.get('allow_question_images', False)),
                is_default=bool(request.data.get('is_default', False)),
            )
            AuditLog.log(request, AuditLog.ACTION_ADD_PLAN, target_label=plan.name, target_id=plan.id)
            return Response({'message': 'تم إضافة الباقة.', 'plan': SubscriptionPlanSerializer(plan).data}, status=status.HTTP_201_CREATED)

        if action == 'edit_plan':
            plan = get_object_or_404(SubscriptionPlan, id=request.data.get('plan_id'))
            for f in ('name', 'description'):
                if f in request.data:
                    setattr(plan, f, str(request.data[f]).strip())
            for f in ('price', 'student_limit', 'group_limit', 'assistant_limit'):
                if f in request.data:
                    setattr(plan, f, int(request.data[f]))
            for f in ('allow_online_packages', 'allow_question_images', 'is_default'):
                if f in request.data:
                    setattr(plan, f, bool(request.data[f]))
            plan.save()
            AuditLog.log(request, AuditLog.ACTION_EDIT_PLAN, target_label=plan.name, target_id=plan.id)
            return Response({'message': 'تم تحديث الباقة بنجاح.', 'plan': SubscriptionPlanSerializer(plan).data})

        if action == 'delete_plan':
            plan = get_object_or_404(SubscriptionPlan, id=request.data.get('plan_id'))
            name = plan.name
            plan.delete()
            AuditLog.log(request, AuditLog.ACTION_DEL_PLAN, target_label=name)
            return Response({'message': 'تم حذف الباقة.'})

        if action == 'create_staff':
            first_name = str(request.data.get('first_name', '')).strip()
            last_name = str(request.data.get('last_name', '')).strip()
            email = str(request.data.get('email', '')).strip().lower()
            phone = str(request.data.get('phone', '')).strip()
            password = str(request.data.get('password', '')).strip()
            admin_role = str(request.data.get('admin_role', AdminRole.MODERATOR))
            notes = str(request.data.get('notes', '')).strip()

            if not all([first_name, email, phone, password]):
                return Response({'error': 'يرجى ملء جميع الحقول الأساسية.'}, status=status.HTTP_400_BAD_REQUEST)
            if User.objects.filter(email__iexact=email).exists():
                return Response({'error': 'البريد الإلكتروني مسجل مسبقاً.'}, status=status.HTTP_400_BAD_REQUEST)
            if User.objects.filter(phone=phone).exists():
                return Response({'error': 'رقم الهاتف مسجل مسبقاً.'}, status=status.HTTP_400_BAD_REQUEST)

            chars = string.ascii_uppercase + string.digits
            custom_id = 'M' + ''.join(random.choices(chars, k=6))
            new_user = User.objects.create_user(
                username=email,
                email=email,
                password=password,
                first_name=first_name,
                last_name=last_name,
                phone=phone,
                role='admin',
                custom_id=custom_id,
            )
            prof = AdminProfile.objects.create(
                user=new_user,
                admin_role=admin_role,
                notes=notes,
                is_active_admin=True,
                appointed_by=request.user,
            )
            return Response({'message': 'تم إنشاء حساب المسؤول بنجاح.', 'staff': AdminProfileSerializer(prof).data}, status=status.HTTP_201_CREATED)

        if action == 'appoint_staff':
            email = str(request.data.get('email', '')).strip()
            admin_role = str(request.data.get('admin_role', AdminRole.MODERATOR))
            notes = str(request.data.get('notes', '')).strip()
            target = get_object_or_404(User, email__iexact=email)
            if target.is_superuser:
                return Response({'error': 'المالك لا يحتاج لبروفايل إداري.'}, status=status.HTTP_400_BAD_REQUEST)
            target.role = 'admin'
            target.save(update_fields=['role'])
            prof, _ = AdminProfile.objects.update_or_create(
                user=target,
                defaults={
                    'admin_role': admin_role,
                    'notes': notes,
                    'is_active_admin': True,
                    'appointed_by': request.user,
                },
            )
            return Response({'message': 'تم تعيين المسؤول بنجاح.', 'staff': AdminProfileSerializer(prof).data})

        if action == 'remove_staff':
            prof = get_object_or_404(AdminProfile, id=request.data.get('profile_id'))
            prof.user.role = 'student'
            prof.user.save(update_fields=['role'])
            prof.delete()
            return Response({'message': 'تم إزالة المسؤول من الفريق الإداري.'})

        if action == 'add_curriculum_unit':
            title = str(request.data.get('title', '')).strip()
            subject_id = request.data.get('subject_id')
            grade = str(request.data.get('grade', '')).strip()
            term = str(request.data.get('term', '1')).strip()
            order = int(request.data.get('order', 1))
            lessons_raw = request.data.get('lessons', [])

            if not title or not subject_id or not grade:
                return Response({'error': 'عنوان الوحدة والمادة والصف الدراسي مطلوبة.'}, status=status.HTTP_400_BAD_REQUEST)

            unit = CurriculumUnit.objects.create(
                title=title,
                subject_id=subject_id,
                grade=grade,
                term=term,
                order=order,
            )
            for idx, item in enumerate(lessons_raw):
                l_title = str(item.get('title', '') if isinstance(item, dict) else item).strip()
                if l_title:
                    CurriculumLesson.objects.create(
                        unit=unit,
                        title=l_title,
                        order=int(item.get('order', idx + 1)) if isinstance(item, dict) else (idx + 1),
                    )
            return Response({
                'message': 'تم إضافة الوحدة الدراسية ودروسها بنجاح.',
                'unit': CurriculumUnitSerializer(unit).data,
            }, status=status.HTTP_201_CREATED)

        if action == 'edit_curriculum_unit':
            unit = get_object_or_404(CurriculumUnit, id=request.data.get('unit_id'))
            if 'title' in request.data:
                unit.title = str(request.data['title']).strip()
            if 'subject_id' in request.data and request.data['subject_id']:
                unit.subject_id = request.data['subject_id']
            if 'grade' in request.data:
                unit.grade = str(request.data['grade']).strip()
            if 'term' in request.data:
                unit.term = str(request.data['term']).strip()
            if 'order' in request.data:
                unit.order = int(request.data['order'])
            unit.save()

            if 'lessons' in request.data and isinstance(request.data['lessons'], list):
                unit.lessons.all().delete()
                for idx, item in enumerate(request.data['lessons']):
                    l_title = str(item.get('title', '') if isinstance(item, dict) else item).strip()
                    if l_title:
                        CurriculumLesson.objects.create(
                            unit=unit,
                            title=l_title,
                            order=int(item.get('order', idx + 1)) if isinstance(item, dict) else (idx + 1),
                        )
            return Response({
                'message': 'تم تحديث الوحدة الدراسية بنجاح.',
                'unit': CurriculumUnitSerializer(unit).data,
            })

        if action == 'delete_curriculum_unit':
            unit = get_object_or_404(CurriculumUnit, id=request.data.get('unit_id'))
            unit.delete()
            return Response({'message': 'تم حذف الوحدة الدراسية.'})

        if action == 'add_subject':
            name = str(request.data.get('name', '')).strip()
            if not name:
                return Response({'error': 'يرجى إدخال اسم المادة.'}, status=status.HTTP_400_BAD_REQUEST)
            sub, _ = Subject.objects.get_or_create(name=name)
            return Response({'message': 'تم إضافة المادة الدراسية.', 'subject': SubjectSerializer(sub).data}, status=status.HTTP_201_CREATED)

        if action == 'delete_subject':
            sub = get_object_or_404(Subject, id=request.data.get('subject_id'))
            sub.delete()
            return Response({'message': 'تم حذف المادة الدراسية.'})

        return Response({'error': 'إجراء غير صالح.'}, status=status.HTTP_400_BAD_REQUEST)

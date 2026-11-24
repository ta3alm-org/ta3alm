"""
api_v1/views/admin/content_hub.py
مركز إدارة المحتوى والمجموعات والحزم الشامل للإدارة (الأدمن له صلاحية كاملة على كل المعلمين والمجموعات والباقات).
"""
from __future__ import annotations

from decimal import Decimal, InvalidOperation
from django.db import transaction
from django.db.models import Count, Q
from django.shortcuts import get_object_or_404
from rest_framework import status
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView

from accounts.models import StudentProfile
from api_v1.permissions import IsPlatformAdmin
from core.constants import GRADE_CHOICES
from dashboard_admin.models import AuditLog
from exams.models import Exam
from students.models import Enrollment, PackageEnrollment
from teachers.models import (
    CoursePackage,
    Group,
    GroupChatMessage,
    Lecture,
    PDFFile,
    TeacherProfile,
)


def _find_student_profile(identifier: str):
    q = str(identifier or '').strip()
    if not q:
        return None
    if q.isdigit():
        by_sp = StudentProfile.objects.filter(id=int(q)).select_related('user').first()
        if by_sp:
            return by_sp
    return (
        StudentProfile.objects.select_related('user')
        .filter(
            Q(user__email__iexact=q)
            | Q(user__phone=q)
            | Q(user__custom_id__iexact=q)
            | Q(user__username__iexact=q)
        )
        .first()
    )


class AdminContentHubAPIView(APIView):
    """جلب وإدارة كل المعلمين والمجموعات والحزم الدراسية في المنصة من مكان واحد منظم."""
    permission_classes = [IsAuthenticated, IsPlatformAdmin]

    def get(self, request):
        teacher_id = str(request.query_params.get('teacher_id') or '').strip()
        grade = str(request.query_params.get('grade') or '').strip()
        q = str(request.query_params.get('q') or '').strip()

        teachers_qs = (
            TeacherProfile.objects.select_related('user', 'subject', 'current_plan')
            .annotate(
                groups_count=Count('groups', distinct=True),
                packages_count=Count('packages', distinct=True),
            )
            .order_by('user__first_name', 'user__last_name', 'id')
        )

        groups_qs = (
            Group.objects.select_related('teacher__user', 'teacher__subject')
            .annotate(
                active_students=Count('enrollments', filter=Q(enrollments__is_active=True), distinct=True),
                pending_students=Count('enrollments', filter=Q(enrollments__is_active=False), distinct=True),
                lectures_cnt=Count('lectures', distinct=True),
                exams_cnt=Count('exams', distinct=True),
                pdfs_cnt=Count('pdfs', distinct=True),
                chat_cnt=Count('chat_messages', distinct=True),
            )
            .order_by('-created_at', '-id')
        )

        packages_qs = (
            CoursePackage.objects.select_related('teacher__user', 'teacher__subject')
            .annotate(
                lectures_cnt=Count('lectures', distinct=True),
                exams_cnt=Count('exams', distinct=True),
                pdfs_cnt=Count('pdfs', distinct=True),
                subs_cnt=Count('enrollments', filter=Q(enrollments__is_paid=True), distinct=True),
            )
            .order_by('-created_at', '-id')
        )

        if teacher_id.isdigit():
            tid = int(teacher_id)
            groups_qs = groups_qs.filter(teacher_id=tid)
            packages_qs = packages_qs.filter(teacher_id=tid)
        if grade:
            groups_qs = groups_qs.filter(grade=grade)
            packages_qs = packages_qs.filter(grade=grade)
        if q:
            groups_qs = groups_qs.filter(
                Q(name__icontains=q)
                | Q(teacher__user__first_name__icontains=q)
                | Q(teacher__user__last_name__icontains=q)
                | Q(teacher__user__email__icontains=q)
            )
            packages_qs = packages_qs.filter(
                Q(title__icontains=q)
                | Q(description__icontains=q)
                | Q(teacher__user__first_name__icontains=q)
                | Q(teacher__user__last_name__icontains=q)
            )

        teachers_data = [
            {
                'id': tp.id,
                'user_id': tp.user_id,
                'name': tp.user.get_full_name() or tp.user.username,
                'email': tp.user.email,
                'subject_name': tp.subject.name if tp.subject else '',
                'is_approved': bool(tp.is_approved),
                'groups_count': tp.groups_count,
                'packages_count': tp.packages_count,
            }
            for tp in teachers_qs
        ]

        groups_data = [
            {
                'id': g.id,
                'name': g.name,
                'grade': g.grade,
                'grade_display': g.get_grade_display(),
                'teacher_id': g.teacher_id,
                'teacher_name': g.teacher.user.get_full_name() or g.teacher.user.username,
                'subject_name': g.teacher.subject.name if g.teacher.subject else '',
                'is_chat_locked': g.is_chat_locked,
                'students_count': g.active_students,
                'pending_count': g.pending_students,
                'lectures_count': g.lectures_cnt,
                'exams_count': g.exams_cnt,
                'pdfs_count': g.pdfs_cnt,
                'chat_messages_count': g.chat_cnt,
                'created_at': g.created_at.isoformat(),
            }
            for g in groups_qs
        ]

        packages_data = [
            {
                'id': p.id,
                'title': p.title,
                'description': p.description,
                'grade': p.grade,
                'grade_display': p.get_grade_display(),
                'price': float(p.price),
                'is_active': p.is_active,
                'teacher_id': p.teacher_id,
                'teacher_name': p.teacher.user.get_full_name() or p.teacher.user.username,
                'subject_name': p.teacher.subject.name if p.teacher.subject else '',
                'lectures_count': p.lectures_cnt,
                'exams_count': p.exams_cnt,
                'pdfs_count': p.pdfs_cnt,
                'subscribers_count': p.subs_cnt,
                'created_at': p.created_at.isoformat(),
            }
            for p in packages_qs
        ]

        return Response({
            'stats': {
                'teachers_count': TeacherProfile.objects.count(),
                'groups_count': Group.objects.count(),
                'packages_count': CoursePackage.objects.count(),
                'lectures_count': Lecture.objects.count(),
                'exams_count': Exam.objects.count(),
                'pdfs_count': PDFFile.objects.count(),
                'active_enrollments_count': Enrollment.objects.filter(is_active=True).count(),
                'locked_chats_count': Group.objects.filter(is_chat_locked=True).count(),
            },
            'grades': [{'value': code, 'label': str(label)} for code, label in GRADE_CHOICES],
            'teachers': teachers_data,
            'groups': groups_data,
            'packages': packages_data,
        })

    @transaction.atomic
    def post(self, request):
        action = str(request.data.get('action') or '').strip()
        valid_grades = {code for code, _ in GRADE_CHOICES}

        if action == 'create_group':
            teacher = get_object_or_404(TeacherProfile, id=request.data.get('teacher_id'))
            name = str(request.data.get('name') or '').strip()
            grade = str(request.data.get('grade') or '').strip()
            if not name or grade not in valid_grades:
                return Response({'error': 'اسم المجموعة والصف الدراسي الصحيح مطلوبان.'}, status=status.HTTP_400_BAD_REQUEST)
            group = Group.objects.create(teacher=teacher, name=name[:100], grade=grade)
            AuditLog.log(request, AuditLog.ACTION_EDIT_USER, target_label=f'إنشاء مجموعة {group.name}', target_id=group.id)
            return Response({'message': f'تم إنشاء المجموعة «{group.name}».', 'group_id': group.id}, status=status.HTTP_201_CREATED)

        if action == 'update_group':
            group = get_object_or_404(Group, id=request.data.get('group_id'))
            if 'name' in request.data and str(request.data['name']).strip():
                group.name = str(request.data['name']).strip()[:100]
            if 'grade' in request.data and str(request.data['grade']).strip() in valid_grades:
                group.grade = str(request.data['grade']).strip()
            if 'teacher_id' in request.data and str(request.data['teacher_id']).isdigit():
                group.teacher = get_object_or_404(TeacherProfile, id=int(request.data['teacher_id']))
            if 'is_chat_locked' in request.data:
                group.is_chat_locked = str(request.data['is_chat_locked']).lower() in ('1', 'true', 'yes')
            group.save()
            AuditLog.log(request, AuditLog.ACTION_EDIT_USER, target_label=f'تحديث مجموعة {group.name}', target_id=group.id)
            return Response({'message': f'تم تحديث المجموعة «{group.name}».'})

        if action == 'delete_group':
            group = get_object_or_404(Group, id=request.data.get('group_id'))
            name = group.name
            gid = group.id
            group.delete()
            AuditLog.log(request, AuditLog.ACTION_DELETE, target_label=f'حذف مجموعة {name}', target_id=gid)
            return Response({'message': f'تم حذف المجموعة «{name}».'})

        if action == 'toggle_group_chat_lock':
            group = get_object_or_404(Group, id=request.data.get('group_id'))
            group.is_chat_locked = not group.is_chat_locked
            group.save(update_fields=['is_chat_locked'])
            return Response({
                'message': 'تم قفل شات المجموعة.' if group.is_chat_locked else 'تم فتح شات المجموعة.',
                'is_chat_locked': group.is_chat_locked,
            })

        if action == 'enroll_student_in_group':
            group = get_object_or_404(Group, id=request.data.get('group_id'))
            sp = _find_student_profile(request.data.get('identifier'))
            if not sp:
                return Response({'error': 'لم يتم العثور على طالب بهذا البريد أو الهاتف أو الكود.'}, status=status.HTTP_404_NOT_FOUND)
            enrollment, created = Enrollment.objects.update_or_create(
                student=sp,
                group=group,
                defaults={'is_active': True},
            )
            return Response({
                'message': f'تم تفعيل اشتراك الطالب {sp.user.get_full_name() or sp.user.username} في {group.name}.',
                'enrollment_id': enrollment.id,
            }, status=status.HTTP_201_CREATED if created else status.HTTP_200_OK)

        if action == 'create_package':
            teacher = get_object_or_404(TeacherProfile, id=request.data.get('teacher_id'))
            title = str(request.data.get('title') or '').strip()
            grade = str(request.data.get('grade') or '').strip()
            description = str(request.data.get('description') or '').strip()
            is_active = str(request.data.get('is_active', 'true')).lower() in ('1', 'true', 'yes', 'on')
            try:
                price = Decimal(str(request.data.get('price') or '0').strip())
            except (InvalidOperation, ValueError):
                price = Decimal('0')
            if not title or grade not in valid_grades:
                return Response({'error': 'عنوان الحزمة والصف الدراسي الصحيح مطلوبان.'}, status=status.HTTP_400_BAD_REQUEST)
            pkg = CoursePackage.objects.create(
                teacher=teacher,
                title=title[:200],
                grade=grade,
                price=max(price, Decimal('0')),
                description=description,
                is_active=is_active,
            )
            AuditLog.log(request, AuditLog.ACTION_EDIT_USER, target_label=f'إنشاء باقة {pkg.title}', target_id=pkg.id)
            return Response({'message': f'تم إنشاء الباقة «{pkg.title}».', 'package_id': pkg.id}, status=status.HTTP_201_CREATED)

        if action == 'update_package':
            pkg = get_object_or_404(CoursePackage, id=request.data.get('package_id'))
            if 'title' in request.data and str(request.data['title']).strip():
                pkg.title = str(request.data['title']).strip()[:200]
            if 'grade' in request.data and str(request.data['grade']).strip() in valid_grades:
                pkg.grade = str(request.data['grade']).strip()
            if 'description' in request.data:
                pkg.description = str(request.data['description']).strip()
            if 'price' in request.data:
                try:
                    pkg.price = max(Decimal(str(request.data['price']).strip()), Decimal('0'))
                except (InvalidOperation, ValueError):
                    pass
            if 'teacher_id' in request.data and str(request.data['teacher_id']).isdigit():
                pkg.teacher = get_object_or_404(TeacherProfile, id=int(request.data['teacher_id']))
            if 'is_active' in request.data:
                pkg.is_active = str(request.data['is_active']).lower() in ('1', 'true', 'yes', 'on')
            pkg.save()
            AuditLog.log(request, AuditLog.ACTION_EDIT_USER, target_label=f'تحديث باقة {pkg.title}', target_id=pkg.id)
            return Response({'message': f'تم تحديث الباقة «{pkg.title}».'})

        if action == 'delete_package':
            pkg = get_object_or_404(CoursePackage, id=request.data.get('package_id'))
            title = pkg.title
            pid = pkg.id
            pkg.delete()
            AuditLog.log(request, AuditLog.ACTION_DELETE, target_label=f'حذف باقة {title}', target_id=pid)
            return Response({'message': f'تم حذف الباقة «{title}».'})

        if action == 'toggle_package_active':
            pkg = get_object_or_404(CoursePackage, id=request.data.get('package_id'))
            pkg.is_active = not pkg.is_active
            pkg.save(update_fields=['is_active'])
            return Response({
                'message': 'تم تفعيل الباقة.' if pkg.is_active else 'تم إيقاف الباقة.',
                'is_active': pkg.is_active,
            })

        if action == 'grant_package_student':
            pkg = get_object_or_404(CoursePackage, id=request.data.get('package_id'))
            sp = _find_student_profile(request.data.get('identifier'))
            if not sp:
                return Response({'error': 'لم يتم العثور على طالب بهذا البريد أو الهاتف أو الكود.'}, status=status.HTTP_404_NOT_FOUND)
            pe, created = PackageEnrollment.objects.update_or_create(
                student=sp,
                package=pkg,
                defaults={'is_paid': True},
            )
            return Response({
                'message': f'تم تفعيل الباقة «{pkg.title}» للطالب {sp.user.get_full_name() or sp.user.username}.',
                'enrollment_id': pe.id,
            }, status=status.HTTP_201_CREATED if created else status.HTTP_200_OK)

        return Response({'error': 'إجراء غير صالح.'}, status=status.HTTP_400_BAD_REQUEST)

"""api_v1.views.teacher.lectures
Extracted from api_v1/views_teacher.py.
"""

import os
import uuid
from django.core.files.storage import default_storage
from django.shortcuts import get_object_or_404
from rest_framework import status
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView
from teachers.models import (
    Lecture,
    VideoCode,
    PDFFile,
)
from teachers.views import (
    get_group_permission,
    get_package_permission,
)
from api_v1.permissions import IsTeacherOrAssistantRole
from api_v1.serializers import (
    LectureSerializer,
    VideoCodeSerializer,
    PDFFileSerializer,
)


class TeacherGroupLecturesAPIView(APIView):
    """إدارة محاضرات المجموعة (عرض وإضافة)."""
    permission_classes = [IsAuthenticated, IsTeacherOrAssistantRole]

    def get(self, request, group_id):
        group, _ = get_group_permission(request, group_id, permission_type='videos')
        if not group:
            return Response({'error': 'ليس لديك صلاحية لإدارة المحاضرات.'}, status=status.HTTP_403_FORBIDDEN)
        lectures = group.lectures.all().order_by('-created_at')
        q = request.query_params.get('q', '').strip()
        if q:
            lectures = lectures.filter(title__icontains=q)
        return Response({'lectures': LectureSerializer(lectures, many=True).data})

    def post(self, request, group_id):
        group, _ = get_group_permission(request, group_id, permission_type='videos')
        if not group:
            return Response({'error': 'ليس لديك صلاحية لإضافة محاضرات.'}, status=status.HTTP_403_FORBIDDEN)

        title = str(request.data.get('title', '')).strip()
        video_link = str(request.data.get('video_link', '')).strip()
        description = str(request.data.get('description', '')).strip()

        if not title or not video_link:
            return Response({'error': 'عنوان المحاضرة ورابط الفيديو مطلوبان.'}, status=status.HTTP_400_BAD_REQUEST)

        lecture = Lecture.objects.create(
            group=group,
            title=title,
            video_link=video_link,
            description=description,
        )
        return Response({
            'message': 'تم نشر المحاضرة بنجاح!',
            'lecture': LectureSerializer(lecture).data,
        }, status=status.HTTP_201_CREATED)


class TeacherLectureActionAPIView(APIView):
    """تفعيل/إخفاء أو حذف محاضرة."""
    permission_classes = [IsAuthenticated, IsTeacherOrAssistantRole]

    def post(self, request, lecture_id):
        lecture = get_object_or_404(Lecture, id=lecture_id)
        if lecture.group:
            group, _ = get_group_permission(request, lecture.group.id, permission_type='videos')
            if not group:
                return Response({'error': 'صلاحية غير كافية.'}, status=status.HTTP_403_FORBIDDEN)
        else:
            pkg = lecture.packages.first()
            if not pkg or not get_package_permission(request, pkg.id, permission_type='videos')[0]:
                return Response({'error': 'صلاحية غير كافية.'}, status=status.HTTP_403_FORBIDDEN)

        lecture.is_active = not lecture.is_active
        lecture.save(update_fields=['is_active'])
        return Response({
            'message': 'تم تحديث حالة المحاضرة.',
            'is_active': lecture.is_active,
        })

    def delete(self, request, lecture_id):
        lecture = get_object_or_404(Lecture, id=lecture_id)
        if lecture.group:
            group, _ = get_group_permission(request, lecture.group.id, permission_type='videos')
            if not group:
                return Response({'error': 'صلاحية غير كافية.'}, status=status.HTTP_403_FORBIDDEN)
        else:
            pkg = lecture.packages.first()
            if not pkg or not get_package_permission(request, pkg.id, permission_type='videos')[0]:
                return Response({'error': 'صلاحية غير كافية.'}, status=status.HTTP_403_FORBIDDEN)

        lecture.delete()
        return Response({'message': 'تم حذف المحاضرة بنجاح.'})


class TeacherVideoCodesAPIView(APIView):
    """عرض وتوليد أكواد المشاهدة لمحاضرة في مجموعة."""
    permission_classes = [IsAuthenticated, IsTeacherOrAssistantRole]

    def get(self, request, lecture_id):
        lecture = get_object_or_404(Lecture, id=lecture_id)
        if not lecture.group:
            return Response({'error': 'هذه المحاضرة تابعة لحزمة أونلاين ولا تستخدم أكواد.'}, status=status.HTTP_400_BAD_REQUEST)
        group, _ = get_group_permission(request, lecture.group.id, permission_type='videos')
        if not group:
            return Response({'error': 'صلاحية غير كافية.'}, status=status.HTTP_403_FORBIDDEN)

        codes = lecture.codes.select_related('used_by__user').order_by('is_used', '-id')
        return Response({
            'lecture': LectureSerializer(lecture).data,
            'unused_count': lecture.codes.filter(is_used=False).count(),
            'codes': VideoCodeSerializer(codes, many=True).data,
        })

    def post(self, request, lecture_id):
        lecture = get_object_or_404(Lecture, id=lecture_id)
        if not lecture.group:
            return Response({'error': 'هذه المحاضرة تابعة لحزمة أونلاين ولا تستخدم أكواد.'}, status=status.HTTP_400_BAD_REQUEST)
        group, _ = get_group_permission(request, lecture.group.id, permission_type='videos')
        if not group:
            return Response({'error': 'صلاحية غير كافية.'}, status=status.HTTP_403_FORBIDDEN)

        try:
            amount = min(max(int(request.data.get('amount', 10)), 1), 100)
            views_limit = max(int(request.data.get('views_limit', 1)), 1)
        except (ValueError, TypeError):
            return Response({'error': 'أدخل أرقاماً صحيحة.'}, status=status.HTTP_400_BAD_REQUEST)

        new_codes = []
        for _ in range(amount):
            while True:
                code_str = VideoCode.generate_random_code()
                if not VideoCode.objects.filter(code=code_str).exists():
                    vc = VideoCode.objects.create(lecture=lecture, code=code_str, max_views=views_limit)
                    new_codes.append(vc)
                    break

        return Response({
            'message': f'تم توليد {len(new_codes)} كود (بحد {views_limit} مشاهدات).',
            'generated_codes': VideoCodeSerializer(new_codes, many=True).data,
        }, status=status.HTTP_201_CREATED)


class TeacherPDFsAPIView(APIView):
    """إضافة وحذف ملفات PDF في المجموعة أو الحزمة."""
    permission_classes = [IsAuthenticated, IsTeacherOrAssistantRole]

    def post(self, request, group_id=None, package_id=None):
        title = str(request.data.get('title', '')).strip()
        uploaded_file = request.FILES.get('file')
        link = str(request.data.get('link', '')).strip()

        if not title:
            return Response({'error': 'عنوان الملف مطلوب.'}, status=status.HTTP_400_BAD_REQUEST)

        group = None
        package = None
        if group_id:
            group, _ = get_group_permission(request, group_id, permission_type='videos')
            if not group:
                return Response({'error': 'صلاحية غير كافية.'}, status=status.HTTP_403_FORBIDDEN)
        elif package_id:
            package, _ = get_package_permission(request, package_id, permission_type='videos')
            if not package:
                return Response({'error': 'صلاحية غير كافية.'}, status=status.HTTP_403_FORBIDDEN)
        else:
            return Response({'error': 'يرجى تحديد المجموعة أو الحزمة.'}, status=status.HTTP_400_BAD_REQUEST)

        if uploaded_file:
            ext = os.path.splitext(uploaded_file.name)[1].lower() or '.pdf'
            if ext not in ('.pdf', '.doc', '.docx', '.ppt', '.pptx'):
                return Response(
                    {'error': 'نوع الملف غير مدعوم. يُسمح بملفات PDF والمستندات فقط.'},
                    status=status.HTTP_400_BAD_REQUEST,
                )
            saved_path = default_storage.save(f"pdfs/{uuid.uuid4().hex[:16]}{ext}", uploaded_file)
            resolved_link = default_storage.url(saved_path)
        elif link:
            resolved_link = link
        else:
            return Response(
                {'error': 'يرجى رفع ملف PDF أو إدخال رابط الملف.'},
                status=status.HTTP_400_BAD_REQUEST,
            )

        if group is not None:
            pdf = PDFFile.objects.create(group=group, title=title, link=resolved_link)
        else:
            pdf = PDFFile.objects.create(group=None, title=title, link=resolved_link)
            package.pdfs.add(pdf)

        return Response({
            'message': 'تم إضافة الملف بنجاح.',
            'pdf': PDFFileSerializer(pdf, context={'request': request}).data,
        }, status=status.HTTP_201_CREATED)

    def delete(self, request, pdf_id):
        pdf = get_object_or_404(PDFFile, id=pdf_id)
        if pdf.group:
            group, _ = get_group_permission(request, pdf.group.id, permission_type='videos')
            if not group:
                return Response({'error': 'صلاحية غير كافية.'}, status=status.HTTP_403_FORBIDDEN)
        else:
            pkg = pdf.packages.first()
            if not pkg or not get_package_permission(request, pkg.id, permission_type='videos')[0]:
                return Response({'error': 'صلاحية غير كافية.'}, status=status.HTTP_403_FORBIDDEN)

        pdf.delete()
        return Response({'message': 'تم حذف الملف بنجاح.'})

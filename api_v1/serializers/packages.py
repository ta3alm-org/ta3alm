"""api_v1.serializers.packages
Extracted from api_v1/serializers.py.
"""

from rest_framework import serializers
from teachers.models import CoursePackage
from students.models import PackageEnrollment

from api_v1.serializers.catalog import TeacherCardSerializer


class CoursePackageSerializer(serializers.ModelSerializer):
    teacher = TeacherCardSerializer(read_only=True)
    grade_display = serializers.CharField(source='get_grade_display', read_only=True)
    image_url = serializers.SerializerMethodField()
    lectures_count = serializers.SerializerMethodField()
    exams_count = serializers.SerializerMethodField()
    pdfs_count = serializers.SerializerMethodField()
    students_count = serializers.SerializerMethodField()
    is_enrolled = serializers.SerializerMethodField()

    class Meta:
        model = CoursePackage
        fields = [
            'id', 'teacher', 'title', 'grade', 'grade_display',
            'description', 'price', 'image', 'image_url',
            'view_limit', 'is_active',
            'lectures_count', 'exams_count', 'pdfs_count', 'students_count',
            'is_enrolled', 'created_at',
        ]
        read_only_fields = ['id', 'teacher', 'created_at']

    def get_image_url(self, obj):
        if not obj.image:
            return None
        request = self.context.get('request')
        try:
            return request.build_absolute_uri(obj.image.url) if request else obj.image.url
        except Exception:
            return str(obj.image)

    def get_lectures_count(self, obj):
        return obj.lectures.count()

    def get_exams_count(self, obj):
        return obj.exams.count()

    def get_pdfs_count(self, obj):
        return obj.pdfs.count()

    def get_students_count(self, obj):
        return obj.enrollments.filter(is_paid=True).count()

    def get_is_enrolled(self, obj):
        request = self.context.get('request')
        if request and request.user.is_authenticated and request.user.role == 'student':
            if hasattr(request.user, 'student_profile'):
                return PackageEnrollment.objects.filter(
                    student=request.user.student_profile,
                    package=obj,
                    is_paid=True,
                ).exists()
        return False


class PackageEnrollmentSerializer(serializers.ModelSerializer):
    package = CoursePackageSerializer(read_only=True)
    student_id = serializers.IntegerField(source='student.id', read_only=True)
    student_name = serializers.SerializerMethodField()
    student_phone = serializers.CharField(source='student.user.phone', read_only=True)
    parent_phone = serializers.CharField(source='student.parent_phone', read_only=True)
    student_custom_id = serializers.CharField(source='student.user.custom_id', read_only=True)

    class Meta:
        model = PackageEnrollment
        fields = [
            'id', 'student_id', 'student_name', 'student_phone',
            'parent_phone', 'student_custom_id',
            'package', 'is_paid', 'joined_at',
        ]

    def get_student_name(self, obj):
        u = obj.student.user
        return f"{u.first_name} {u.last_name}".strip() or u.username

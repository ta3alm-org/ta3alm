"""api_v1.serializers.academics
Extracted from api_v1/serializers.py.
"""

from rest_framework import serializers
from teachers.models import (
    Group,
    Lecture,
    VideoCode,
    PDFFile,
)
from students.models import (
    Enrollment,
    PerformanceLog,
    VideoViewTracking,
    PackageExamResult,
)
from exams.models import (
    Exam,
    Question,
    ExamResult,
)

from api_v1.serializers.catalog import TeacherCardSerializer


class GroupSerializer(serializers.ModelSerializer):
    teacher = TeacherCardSerializer(read_only=True)
    grade_display = serializers.CharField(source='get_grade_display', read_only=True)
    students_count = serializers.SerializerMethodField()
    pending_count = serializers.SerializerMethodField()
    lectures_count = serializers.SerializerMethodField()
    exams_count = serializers.SerializerMethodField()
    is_allowed_by_plan = serializers.SerializerMethodField()

    class Meta:
        model = Group
        fields = [
            'id', 'name', 'grade', 'grade_display', 'teacher',
            'students_count', 'pending_count', 'lectures_count', 'exams_count',
            'is_allowed_by_plan', 'created_at',
        ]
        read_only_fields = ['id', 'teacher', 'created_at']

    def get_students_count(self, obj):
        if hasattr(obj, 'active_students_count'):
            return obj.active_students_count
        return obj.enrollments.filter(is_active=True).count()

    def get_pending_count(self, obj):
        if hasattr(obj, 'pending_students_count'):
            return obj.pending_students_count
        return obj.enrollments.filter(is_active=False).count()

    def get_lectures_count(self, obj):
        return obj.lectures.count()

    def get_exams_count(self, obj):
        return obj.exams.count()

    def get_is_allowed_by_plan(self, obj):
        allowed_ids = list(obj.teacher.get_allowed_group_ids())
        return obj.id in allowed_ids


class LectureSerializer(serializers.ModelSerializer):
    youtube_video_id = serializers.SerializerMethodField()
    group_name = serializers.CharField(source='group.name', default='', read_only=True)
    has_native_asset = serializers.SerializerMethodField()
    source_type = serializers.SerializerMethodField()

    class Meta:
        model = Lecture
        fields = [
            'id', 'group', 'group_name', 'title', 'video_link',
            'youtube_video_id', 'has_native_asset', 'source_type',
            'description', 'is_active', 'created_at',
        ]
        read_only_fields = ['id', 'group', 'created_at']

    def get_youtube_video_id(self, obj):
        return obj.get_video_id()

    def get_has_native_asset(self, obj):
        asset = getattr(obj, 'video_asset', None)
        return bool(asset and asset.is_native_protected)

    def get_source_type(self, obj):
        asset = getattr(obj, 'video_asset', None)
        if asset and asset.is_native_protected:
            return asset.source_type
        return 'youtube_legacy' if obj.get_video_id() else 'external_legacy'

    def to_representation(self, instance):
        data = super().to_representation(instance)
        asset = getattr(instance, 'video_asset', None)
        # عدم تسريب رابط الفيديو الأصلي للطلاب نهائياً
        if self.context.get('hide_raw_url_for_student') or self.context.get('for_student', False) or (
            asset and asset.is_native_protected and self.context.get('for_student', False)
        ):
            data['video_link'] = ''
            data['youtube_video_id'] = None
        return data


class LectureStudentListSerializer(serializers.ModelSerializer):
    """يعرض للطالب بيانات المحاضرة وحالة الفتح دون تسريب رابط الفيديو قبل فتحه بالكود."""
    is_unlocked = serializers.SerializerMethodField()

    class Meta:
        model = Lecture
        fields = ['id', 'title', 'description', 'is_active', 'is_unlocked', 'created_at']

    def get_is_unlocked(self, obj):
        unlocked_ids = self.context.get('unlocked_ids', set())
        return obj.id in unlocked_ids


class VideoCodeSerializer(serializers.ModelSerializer):
    used_by_name = serializers.SerializerMethodField()
    is_expired = serializers.SerializerMethodField()

    class Meta:
        model = VideoCode
        fields = [
            'id', 'lecture', 'code', 'max_views', 'current_views',
            'is_used', 'used_by', 'used_by_name', 'used_at', 'is_expired',
        ]

    def get_used_by_name(self, obj):
        if obj.used_by and obj.used_by.user:
            return f"{obj.used_by.user.first_name} {obj.used_by.user.last_name}".strip()
        return None

    def get_is_expired(self, obj):
        return obj.is_expired()


class PDFFileSerializer(serializers.ModelSerializer):
    file_url = serializers.SerializerMethodField()

    class Meta:
        model = PDFFile
        fields = ['id', 'group', 'title', 'link', 'file_url', 'created_at']
        read_only_fields = ['id', 'group', 'file_url', 'created_at']

    def get_file_url(self, obj):
        raw_link = (getattr(obj, 'link', '') or '').strip()
        if not raw_link:
            return ''
        if raw_link.startswith(('http://', 'https://')):
            return raw_link
        request = self.context.get('request') if self.context else None
        if request is not None:
            return request.build_absolute_uri(raw_link)
        return raw_link


class QuestionTeacherSerializer(serializers.ModelSerializer):
    """للمعلم والمساعد: يشمل الإجابة الصحيحة."""
    image_url = serializers.SerializerMethodField()

    class Meta:
        model = Question
        fields = [
            'id', 'exam', 'text', 'image', 'image_url',
            'option_a', 'option_b', 'option_c', 'option_d',
            'correct_answer', 'marks',
        ]
        read_only_fields = ['id', 'exam']

    def get_image_url(self, obj):
        if not obj.image:
            return None
        request = self.context.get('request')
        try:
            return request.build_absolute_uri(obj.image.url) if request else obj.image.url
        except Exception:
            return str(obj.image)


class QuestionStudentSerializer(serializers.ModelSerializer):
    """للطالب أثناء تأدية الامتحان: لا يُرسل حقل correct_answer نهائياً."""
    image_url = serializers.SerializerMethodField()

    class Meta:
        model = Question
        fields = [
            'id', 'text', 'image_url',
            'option_a', 'option_b', 'option_c', 'option_d', 'marks',
        ]

    def get_image_url(self, obj):
        if not obj.image:
            return None
        request = self.context.get('request')
        try:
            return request.build_absolute_uri(obj.image.url) if request else obj.image.url
        except Exception:
            return str(obj.image)


class ExamSerializer(serializers.ModelSerializer):
    total_marks = serializers.SerializerMethodField()
    questions_count = serializers.SerializerMethodField()
    is_taken = serializers.SerializerMethodField()
    student_score = serializers.SerializerMethodField()

    class Meta:
        model = Exam
        fields = [
            'id', 'group', 'title', 'description', 'duration_minutes',
            'is_active', 'total_marks', 'questions_count',
            'is_taken', 'student_score', 'created_at',
        ]
        read_only_fields = ['id', 'group', 'created_at']

    def get_total_marks(self, obj):
        return obj.total_marks()

    def get_questions_count(self, obj):
        return obj.questions.count()

    def get_is_taken(self, obj):
        taken_map = self.context.get('taken_map', {})
        return obj.id in taken_map

    def get_student_score(self, obj):
        taken_map = self.context.get('taken_map', {})
        return taken_map.get(obj.id)


class ExamResultSerializer(serializers.ModelSerializer):
    student_name = serializers.SerializerMethodField()
    student_phone = serializers.CharField(source='student.user.phone', read_only=True)
    student_custom_id = serializers.CharField(source='student.user.custom_id', read_only=True)
    exam_title = serializers.CharField(source='exam.title', read_only=True)
    exam_total_marks = serializers.SerializerMethodField()

    class Meta:
        model = ExamResult
        fields = [
            'id', 'student', 'student_name', 'student_phone', 'student_custom_id',
            'exam', 'exam_title', 'exam_total_marks', 'score', 'submitted_at',
        ]

    def get_student_name(self, obj):
        u = obj.student.user
        return f"{u.first_name} {u.last_name}".strip() or u.username

    def get_exam_total_marks(self, obj):
        return obj.exam.total_marks()


class PackageExamResultSerializer(serializers.ModelSerializer):
    student_name = serializers.SerializerMethodField()
    student_phone = serializers.CharField(source='student.user.phone', read_only=True)
    exam_title = serializers.CharField(source='exam.title', read_only=True)
    exam_total_marks = serializers.SerializerMethodField()

    class Meta:
        model = PackageExamResult
        fields = [
            'id', 'student', 'student_name', 'student_phone',
            'package', 'exam', 'exam_title', 'exam_total_marks',
            'score', 'submitted_at',
        ]

    def get_student_name(self, obj):
        u = obj.student.user
        return f"{u.first_name} {u.last_name}".strip() or u.username

    def get_exam_total_marks(self, obj):
        return obj.exam.total_marks()


class PerformanceLogSerializer(serializers.ModelSerializer):
    student_name = serializers.SerializerMethodField()
    group_name = serializers.CharField(source='group.name', read_only=True)

    class Meta:
        model = PerformanceLog
        fields = [
            'id', 'student', 'student_name', 'group', 'group_name',
            'date', 'session_number', 'is_present',
            'homework_score', 'homework_max',
            'class_exam_score', 'class_exam_max',
            'recitation_score', 'recitation_max',
            'comprehensive_exam_score', 'comprehensive_exam_max',
            'note',
        ]
        read_only_fields = ['id', 'student', 'group', 'date']

    def get_student_name(self, obj):
        u = obj.student.user
        return f"{u.first_name} {u.last_name}".strip() or u.username


class EnrollmentSerializer(serializers.ModelSerializer):
    student_id = serializers.IntegerField(source='student.id', read_only=True)
    student_user_id = serializers.IntegerField(source='student.user.id', read_only=True)
    student_name = serializers.SerializerMethodField()
    student_phone = serializers.CharField(source='student.user.phone', read_only=True)
    parent_phone = serializers.CharField(source='student.parent_phone', read_only=True)
    student_custom_id = serializers.CharField(source='student.user.custom_id', read_only=True)
    group = GroupSerializer(read_only=True)

    class Meta:
        model = Enrollment
        fields = [
            'id', 'student_id', 'student_user_id', 'student_name',
            'student_phone', 'parent_phone', 'student_custom_id',
            'group', 'is_active', 'joined_at',
        ]

    def get_student_name(self, obj):
        u = obj.student.user
        return f"{u.first_name} {u.last_name}".strip() or u.username


class VideoViewTrackingSerializer(serializers.ModelSerializer):
    lecture_title = serializers.CharField(source='lecture.title', read_only=True)

    class Meta:
        model = VideoViewTracking
        fields = [
            'id', 'package', 'lecture', 'lecture_title',
            'views_count', 'is_completed', 'points_awarded',
        ]

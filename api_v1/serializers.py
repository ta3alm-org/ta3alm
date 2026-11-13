"""
api_v1/serializers.py
جميع الـ Serializers الخاصة بالمنصة مع التحقق من صحة المدخلات وحماية البيانات الحساسة.
"""
from django.contrib.auth import get_user_model
from rest_framework import serializers

from accounts.models import StudentProfile
from teachers.models import (
    SubscriptionPlan,
    TeacherProfile,
    Group,
    Lecture,
    VideoCode,
    PDFFile,
    CoursePackage,
    PaymentTransaction,
    Wallet,
    WithdrawRequest,
)
from students.models import (
    Enrollment,
    PerformanceLog,
    PackageEnrollment,
    VideoViewTracking,
    PackageExamResult,
)
from exams.models import Exam, Question, ExamResult
from assistants.models import AssistantProfile, AssistantJob
from core.models import (
    SiteSetting,
    Notification,
    Subject,
    ManualPayment,
    CurriculumUnit,
    CurriculumLesson,
)
from dashboard_admin.models import AdminProfile, AuditLog

User = get_user_model()


class SubjectSerializer(serializers.ModelSerializer):
    class Meta:
        model = Subject
        fields = ['id', 'name']


class SubscriptionPlanSerializer(serializers.ModelSerializer):
    class Meta:
        model = SubscriptionPlan
        fields = [
            'id', 'name', 'price', 'description',
            'student_limit', 'group_limit', 'assistant_limit',
            'allow_online_packages', 'allow_question_images', 'is_default',
        ]


class UserPublicSerializer(serializers.ModelSerializer):
    full_name = serializers.SerializerMethodField()
    role_display = serializers.CharField(source='get_role_display', read_only=True)

    class Meta:
        model = User
        fields = [
            'id', 'username', 'first_name', 'last_name', 'full_name',
            'email', 'phone', 'custom_id', 'role', 'role_display',
        ]

    def get_full_name(self, obj):
        return f"{obj.first_name} {obj.last_name}".strip() or obj.username


class UserDetailSerializer(serializers.ModelSerializer):
    full_name = serializers.SerializerMethodField()
    role_display = serializers.CharField(source='get_role_display', read_only=True)
    is_profile_complete = serializers.SerializerMethodField()
    profile_data = serializers.SerializerMethodField()

    class Meta:
        model = User
        fields = [
            'id', 'username', 'first_name', 'last_name', 'full_name',
            'email', 'phone', 'national_id', 'custom_id',
            'role', 'role_display', 'is_banned', 'is_superuser',
            'is_profile_complete', 'profile_data', 'date_joined',
        ]
        read_only_fields = ['id', 'username', 'custom_id', 'role', 'is_banned', 'is_superuser', 'date_joined']

    def get_full_name(self, obj):
        return f"{obj.first_name} {obj.last_name}".strip() or obj.username

    def get_is_profile_complete(self, obj):
        if obj.is_superuser or obj.role == 'admin':
            return True
        if not obj.custom_id:
            return False
        if obj.role == 'student':
            return hasattr(obj, 'student_profile') and bool(obj.student_profile.parent_phone)
        if obj.role == 'teacher':
            return hasattr(obj, 'teacher_profile') and bool(obj.teacher_profile.subject_id)
        if obj.role == 'assistant':
            return hasattr(obj, 'assistant_profile') and bool(obj.assistant_profile.phone)
        return True

    def get_profile_data(self, obj):
        request = self.context.get('request')
        if obj.role == 'student' and hasattr(obj, 'student_profile'):
            sp = obj.student_profile
            return {
                'student_profile_id': sp.id,
                'parent_phone': sp.parent_phone,
            }
        if obj.role == 'teacher' and hasattr(obj, 'teacher_profile'):
            tp = obj.teacher_profile
            img_url = None
            if tp.image:
                try:
                    img_url = request.build_absolute_uri(tp.image.url) if request else tp.image.url
                except Exception:
                    img_url = str(tp.image)
            return {
                'teacher_profile_id': tp.id,
                'bio': tp.bio,
                'subject_id': tp.subject_id,
                'subject_name': tp.subject.name if tp.subject else '',
                'image': img_url,
                'has_active_subscription': tp.has_active_subscription(),
                'days_remaining': tp.days_remaining(),
                'subscription_end_date': tp.subscription_end_date,
                'current_plan': SubscriptionPlanSerializer(tp.current_plan).data if tp.current_plan else None,
            }
        if obj.role == 'assistant' and hasattr(obj, 'assistant_profile'):
            ap = obj.assistant_profile
            return {
                'assistant_profile_id': ap.id,
                'phone': ap.phone,
            }
        if (obj.is_superuser or obj.role == 'admin'):
            ap = getattr(obj, 'admin_profile', None)
            return {
                'admin_role': ap.admin_role if ap else 'owner',
                'is_owner': obj.is_superuser or (ap.is_owner if ap else False),
                'can_manage_users': obj.is_superuser or (ap.can_manage_users if ap else False),
                'can_delete_users': obj.is_superuser or (ap.can_delete_users if ap else False),
                'can_view_finance': obj.is_superuser or (ap.can_view_finance if ap else False),
                'can_manage_plans': obj.is_superuser or (ap.can_manage_plans if ap else False),
                'can_view_audit_log': obj.is_superuser or (ap.can_view_audit_log if ap else False),
            }
        return {}


class TeacherCardSerializer(serializers.ModelSerializer):
    first_name = serializers.CharField(source='user.first_name', read_only=True)
    last_name = serializers.CharField(source='user.last_name', read_only=True)
    full_name = serializers.SerializerMethodField()
    phone = serializers.CharField(source='user.phone', read_only=True)
    custom_id = serializers.CharField(source='user.custom_id', read_only=True)
    subject_name = serializers.CharField(source='subject.name', default='', read_only=True)
    image_url = serializers.SerializerMethodField()
    has_active_subscription = serializers.SerializerMethodField()

    class Meta:
        model = TeacherProfile
        fields = [
            'id', 'first_name', 'last_name', 'full_name', 'phone', 'custom_id',
            'bio', 'subject', 'subject_name', 'image', 'image_url',
            'has_active_subscription',
        ]

    def get_full_name(self, obj):
        return f"{obj.user.first_name} {obj.user.last_name}".strip() or obj.user.username

    def get_image_url(self, obj):
        if not obj.image:
            return None
        request = self.context.get('request')
        try:
            return request.build_absolute_uri(obj.image.url) if request else obj.image.url
        except Exception:
            return str(obj.image)

    def get_has_active_subscription(self, obj):
        return obj.has_active_subscription()


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

    class Meta:
        model = Lecture
        fields = [
            'id', 'group', 'group_name', 'title', 'video_link',
            'youtube_video_id', 'description', 'is_active', 'created_at',
        ]
        read_only_fields = ['id', 'group', 'created_at']

    def get_youtube_video_id(self, obj):
        return obj.get_video_id()


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
    class Meta:
        model = PDFFile
        fields = ['id', 'group', 'title', 'link', 'created_at']
        read_only_fields = ['id', 'group', 'created_at']


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


class VideoViewTrackingSerializer(serializers.ModelSerializer):
    lecture_title = serializers.CharField(source='lecture.title', read_only=True)

    class Meta:
        model = VideoViewTracking
        fields = [
            'id', 'package', 'lecture', 'lecture_title',
            'views_count', 'is_completed', 'points_awarded',
        ]


class WalletSerializer(serializers.ModelSerializer):
    class Meta:
        model = Wallet
        fields = ['id', 'balance', 'total_earnings']


class WithdrawRequestSerializer(serializers.ModelSerializer):
    method_display = serializers.CharField(source='get_method_display', read_only=True)
    teacher_name = serializers.SerializerMethodField()
    teacher_phone = serializers.CharField(source='wallet.teacher.user.phone', read_only=True)

    class Meta:
        model = WithdrawRequest
        fields = [
            'id', 'amount', 'method', 'method_display',
            'details', 'is_paid', 'teacher_name', 'teacher_phone', 'created_at',
        ]
        read_only_fields = ['id', 'is_paid', 'created_at']

    def get_teacher_name(self, obj):
        u = obj.wallet.teacher.user
        return f"{u.first_name} {u.last_name}".strip() or u.username


class AssistantJobSerializer(serializers.ModelSerializer):
    assistant_id = serializers.IntegerField(source='assistant.id', read_only=True)
    assistant_name = serializers.SerializerMethodField()
    assistant_phone = serializers.CharField(source='assistant.phone', read_only=True)
    assistant_custom_id = serializers.CharField(source='assistant.user.custom_id', read_only=True)
    teacher = TeacherCardSerializer(read_only=True)

    class Meta:
        model = AssistantJob
        fields = [
            'id', 'assistant_id', 'assistant_name', 'assistant_phone', 'assistant_custom_id',
            'teacher', 'is_active', 'joined_at',
            'can_manage_students', 'can_manage_exams',
            'can_manage_videos', 'can_manage_packages',
        ]

    def get_assistant_name(self, obj):
        u = obj.assistant.user
        return f"{u.first_name} {u.last_name}".strip() or u.username


class NotificationSerializer(serializers.ModelSerializer):
    class Meta:
        model = Notification
        fields = ['id', 'title', 'message', 'link', 'is_read', 'created_at']


class ManualPaymentSerializer(serializers.ModelSerializer):
    user_name = serializers.SerializerMethodField()
    user_phone = serializers.CharField(source='user.phone', read_only=True)
    status_display = serializers.CharField(source='get_status_display', read_only=True)
    payment_type_display = serializers.CharField(source='get_payment_type_display', read_only=True)
    receipt_image_url = serializers.SerializerMethodField()

    class Meta:
        model = ManualPayment
        fields = [
            'id', 'user', 'user_name', 'user_phone',
            'amount', 'payment_type', 'payment_type_display',
            'status', 'status_display', 'target_id',
            'phone_number', 'receipt_image', 'receipt_image_url', 'created_at',
        ]
        read_only_fields = ['id', 'user', 'status', 'created_at']

    def get_user_name(self, obj):
        return f"{obj.user.first_name} {obj.user.last_name}".strip() or obj.user.username

    def get_receipt_image_url(self, obj):
        if not obj.receipt_image:
            return None
        request = self.context.get('request')
        try:
            return request.build_absolute_uri(obj.receipt_image.url) if request else obj.receipt_image.url
        except Exception:
            return str(obj.receipt_image)


class CurriculumLessonSerializer(serializers.ModelSerializer):
    class Meta:
        model = CurriculumLesson
        fields = ['id', 'title', 'order']


class CurriculumUnitSerializer(serializers.ModelSerializer):
    lessons = CurriculumLessonSerializer(many=True, read_only=True)
    subject_name = serializers.CharField(source='subject.name', read_only=True)
    grade_display = serializers.CharField(source='get_grade_display', read_only=True)
    term_display = serializers.CharField(source='get_term_display', read_only=True)

    class Meta:
        model = CurriculumUnit
        fields = [
            'id', 'title', 'subject', 'subject_name',
            'grade', 'grade_display', 'term', 'term_display',
            'order', 'lessons',
        ]


class AdminProfileSerializer(serializers.ModelSerializer):
    user = UserPublicSerializer(read_only=True)
    admin_role_display = serializers.CharField(source='get_admin_role_display', read_only=True)
    appointed_by_name = serializers.SerializerMethodField()

    class Meta:
        model = AdminProfile
        fields = [
            'id', 'user', 'admin_role', 'admin_role_display',
            'is_active_admin', 'notes', 'appointed_by_name', 'appointed_at',
        ]

    def get_appointed_by_name(self, obj):
        if obj.appointed_by:
            return f"{obj.appointed_by.first_name} {obj.appointed_by.last_name}".strip() or obj.appointed_by.username
        return '-'


class AuditLogSerializer(serializers.ModelSerializer):
    admin_name = serializers.SerializerMethodField()
    action_display = serializers.CharField(source='get_action_display', read_only=True)

    class Meta:
        model = AuditLog
        fields = [
            'id', 'admin', 'admin_name', 'action', 'action_display',
            'target_label', 'target_id', 'details', 'ip_address', 'created_at',
        ]

    def get_admin_name(self, obj):
        if obj.admin:
            return f"{obj.admin.first_name} {obj.admin.last_name}".strip() or obj.admin.username
        return 'محذوف'


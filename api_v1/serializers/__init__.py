"""
api_v1/serializers package compatibility exports.
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
from exams.models import (
    Exam,
    Question,
    ExamResult,
)
from assistants.models import (
    AssistantProfile,
    AssistantJob,
)
from core.models import (
    SiteSetting,
    Notification,
    FCMDeviceToken,
    Subject,
    ManualPayment,
    CurriculumUnit,
    CurriculumLesson,
)
from dashboard_admin.models import (
    AdminProfile,
    AuditLog,
)

from api_v1.serializers.accounts import User
from api_v1.serializers.catalog import (
    SubjectSerializer,
    SubscriptionPlanSerializer,
    TeacherCardSerializer,
)
from api_v1.serializers.accounts import (
    UserDetailSerializer,
    UserPublicSerializer,
)
from api_v1.serializers.academics import (
    EnrollmentSerializer,
    ExamResultSerializer,
    ExamSerializer,
    GroupSerializer,
    LectureSerializer,
    LectureStudentListSerializer,
    PDFFileSerializer,
    PackageExamResultSerializer,
    PerformanceLogSerializer,
    QuestionStudentSerializer,
    QuestionTeacherSerializer,
    VideoCodeSerializer,
    VideoViewTrackingSerializer,
)
from api_v1.serializers.packages import (
    CoursePackageSerializer,
    PackageEnrollmentSerializer,
)
from api_v1.serializers.finance import (
    ManualPaymentSerializer,
    WalletSerializer,
    WithdrawRequestSerializer,
)
from api_v1.serializers.staff import (
    AdminProfileSerializer,
    AssistantJobSerializer,
    AuditLogSerializer,
)
from api_v1.serializers.notifications import (
    FCMDeviceTokenSerializer,
    NotificationSerializer,
)
from api_v1.serializers.curriculum import (
    CurriculumLessonSerializer,
    CurriculumUnitSerializer,
)

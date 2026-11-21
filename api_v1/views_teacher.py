"""
Compatibility facade for api_v1.views_teacher.
"""

import os
import uuid
from decimal import Decimal
from django.core.files.storage import default_storage
from django.db import transaction
from django.db.models import (
    Q,
    Sum,
)
from django.shortcuts import get_object_or_404
from rest_framework import status
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView
from accounts.models import StudentProfile
from assistants.models import (
    AssistantProfile,
    AssistantJob,
)
from core.models import (
    SiteSetting,
    reconcile_teacher_wallet,
)
from core.notifications_service import maybe_notify_teacher_subscription_expiry
from exams.models import (
    Exam,
    Question,
    ExamResult,
)
from students.models import (
    Enrollment,
    PerformanceLog,
    PackageEnrollment,
    VideoViewTracking,
    PackageExamResult,
)
from teachers.models import (
    TeacherProfile,
    SubscriptionPlan,
    Group,
    Lecture,
    VideoCode,
    PDFFile,
    CoursePackage,
    Wallet,
    WithdrawRequest,
)
from teachers.views import (
    get_group_permission,
    get_package_permission,
    calculate_leaderboard,
    calculate_package_leaderboard,
)
from api_v1.permissions import (
    IsTeacherRole,
    IsAssistantRole,
    IsTeacherOrAssistantRole,
)
from api_v1.serializers import (
    GroupSerializer,
    LectureSerializer,
    VideoCodeSerializer,
    PDFFileSerializer,
    ExamSerializer,
    QuestionTeacherSerializer,
    ExamResultSerializer,
    PackageExamResultSerializer,
    EnrollmentSerializer,
    PerformanceLogSerializer,
    CoursePackageSerializer,
    PackageEnrollmentSerializer,
    WalletSerializer,
    WithdrawRequestSerializer,
    SubscriptionPlanSerializer,
    AssistantJobSerializer,
    TeacherCardSerializer,
)

from api_v1.views.teacher.dashboard import (
    TeacherDashboardAPIView,
    TeacherGroupDetailAPIView,
)
from api_v1.views.teacher.lectures import (
    TeacherGroupLecturesAPIView,
    TeacherLectureActionAPIView,
    TeacherPDFsAPIView,
    TeacherVideoCodesAPIView,
)
from api_v1.views.teacher.exams import (
    TeacherExamDetailAPIView,
    TeacherGroupExamsAPIView,
    TeacherQuestionDetailAPIView,
    _check_exam_permission,
)
from api_v1.views.teacher.students import (
    TeacherBulkLogAPIView,
    TeacherGroupRankingAndImportAPIView,
    TeacherGroupStudentsAPIView,
    TeacherStudentFullLogAPIView,
)
from api_v1.views.teacher.packages import (
    TeacherPackageDetailAPIView,
    TeacherPackagesAPIView,
)
from api_v1.views.teacher.wallet import TeacherWalletAPIView
from api_v1.views.teacher.assistants import (
    AssistantDashboardAPIView,
    AssistantTeacherGroupsAPIView,
    TeacherManageAssistantsAPIView,
)

"""
Compatibility facade for api_v1.views_student.
"""

from datetime import timedelta
from django.core.cache import cache
from django.db import transaction
from django.db.models import (
    Q,
    Sum,
)
from django.shortcuts import get_object_or_404
from django.utils import timezone
from rest_framework import status
from rest_framework.permissions import (
    AllowAny,
    IsAuthenticated,
)
from rest_framework.response import Response
from rest_framework.views import APIView
from api_v1.models import PlaybackSession
from api_v1.device_security_service import check_web_ios_only_lecture_access
from api_v1.video_security import (
    clear_watch_window,
    grant_watch_window,
    has_active_watch_window,
)
from core.models import Subject
from core.utils import send_notification
from exams.models import (
    Exam,
    ExamResult,
)
from students.models import (
    Enrollment,
    PerformanceLog,
    PackageEnrollment,
    VideoViewTracking,
    PackageExamResult,
)
from students.views import (
    check_student_access,
    calculate_leaderboard,
)
from teachers.models import (
    Group,
    Lecture,
    VideoCode,
    CoursePackage,
)
from api_v1.permissions import (
    IsStudentRole,
    IsNotBanned,
)
from api_v1.serializers import (
    EnrollmentSerializer,
    PackageEnrollmentSerializer,
    GroupSerializer,
    LectureSerializer,
    LectureStudentListSerializer,
    ExamSerializer,
    QuestionStudentSerializer,
    ExamResultSerializer,
    PackageExamResultSerializer,
    PerformanceLogSerializer,
    PDFFileSerializer,
    CoursePackageSerializer,
    TeacherCardSerializer,
    AssistantJobSerializer,
    VideoViewTrackingSerializer,
)

from api_v1.views.student.groups import (
    StudentDashboardAPIView,
    StudentGroupContactAPIView,
    StudentGroupContentAPIView,
    StudentGroupMarksAPIView,
    StudentGroupRankingAPIView,
    StudentJoinGroupAPIView,
    StudentSearchGroupsAPIView,
    StudentTakeGroupExamAPIView,
    StudentWatchGroupLectureAPIView,
    _access_error_response,
    _is_in_student_watch_window,
    _mark_student_watch_window,
)
from api_v1.views.student.packages import (
    StudentMyPackageContentAPIView,
    StudentPackageDetailAPIView,
    StudentPackageMarksAndRankingAPIView,
    StudentPackagesStoreAPIView,
    StudentTakePackageExamAPIView,
    StudentWatchPackageLectureAPIView,
)

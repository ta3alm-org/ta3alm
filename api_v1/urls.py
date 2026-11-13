"""
api_v1/urls.py
خريطة روابط REST API v1 الكاملة تحت /api/v1/
"""
from django.urls import path
from teachers import views as legacy_teacher_views

from .schema import OpenAPISchemaView, SwaggerUIView
from .views_auth import (
    LoginAPIView,
    RegisterAPIView,
    CompleteProfileAPIView,
    TokenRefreshAPIView,
    LogoutAPIView,
    MeProfileAPIView,
    ChangePasswordAPIView,
    ResetPasswordByNationalIdAPIView,
    GoogleLoginAPIView,
    OneTimeLoginAPIView,
    GoogleMobileCallbackView,
)
from .views_public import (
    PublicHomeAPIView,
    PublicMetadataAPIView,
    PublicPlansAPIView,
    PlatformGuideAPIView,
    CurriculumLookupAPIView,
    NotificationsAPIView,
    MarkNotificationReadAPIView,
    ManualCheckoutAPIView,
)
from .views_student import (
    StudentDashboardAPIView,
    StudentSearchGroupsAPIView,
    StudentJoinGroupAPIView,
    StudentGroupContentAPIView,
    StudentWatchGroupLectureAPIView,
    StudentTakeGroupExamAPIView,
    StudentGroupMarksAPIView,
    StudentGroupRankingAPIView,
    StudentGroupContactAPIView,
    StudentPackagesStoreAPIView,
    StudentPackageDetailAPIView,
    StudentMyPackageContentAPIView,
    StudentWatchPackageLectureAPIView,
    StudentTakePackageExamAPIView,
    StudentPackageMarksAndRankingAPIView,
)
from .views_teacher import (
    TeacherDashboardAPIView,
    TeacherGroupDetailAPIView,
    TeacherGroupLecturesAPIView,
    TeacherLectureActionAPIView,
    TeacherVideoCodesAPIView,
    TeacherPDFsAPIView,
    TeacherGroupExamsAPIView,
    TeacherExamDetailAPIView,
    TeacherQuestionDetailAPIView,
    TeacherGroupStudentsAPIView,
    TeacherStudentFullLogAPIView,
    TeacherBulkLogAPIView,
    TeacherGroupRankingAndImportAPIView,
    TeacherPackagesAPIView,
    TeacherPackageDetailAPIView,
    TeacherWalletAPIView,
    TeacherManageAssistantsAPIView,
    AssistantDashboardAPIView,
    AssistantTeacherGroupsAPIView,
)
from .views_admin import (
    AdminDashboardAPIView,
    AdminToggleMaintenanceAPIView,
    AdminManageUsersAPIView,
    AdminFinanceAPIView,
    AdminPlansAndStaffAPIView,
    AdminSupportInboxAPIView,
)
from .views_video import (
    VideoAuthorizeAPIView,
    VideoHeartbeatAPIView,
    VideoProgressAPIView,
    ContinueWatchingAPIView,
    VideoBookmarksAPIView,
    VideoSessionRevokeAPIView,
    ProtectedVideoStreamProxyAPIView,
    PlayIntegrityChallengeAPIView,
    PlayIntegrityVerifyAPIView,
)

urlpatterns = [
    # OpenAPI & Swagger Docs
    path('schema/', OpenAPISchemaView.as_view(), name='api_v1_schema'),
    path('docs/', SwaggerUIView.as_view(), name='api_v1_docs'),

    # Legacy compatibility endpoints
    path('teachers/', legacy_teacher_views.api_all_teachers, name='api_v1_legacy_teachers'),
    path('packages/', legacy_teacher_views.api_all_packages, name='api_v1_legacy_packages'),

    # 1. Authentication & Profile
    path('auth/login/', LoginAPIView.as_view(), name='api_v1_login'),
    path('auth/register/', RegisterAPIView.as_view(), name='api_v1_register'),
    path('auth/complete-profile/', CompleteProfileAPIView.as_view(), name='api_v1_complete_profile'),
    path('auth/refresh/', TokenRefreshAPIView.as_view(), name='api_v1_token_refresh'),
    path('auth/logout/', LogoutAPIView.as_view(), name='api_v1_logout'),
    path('auth/me/', MeProfileAPIView.as_view(), name='api_v1_me'),
    path('auth/change-password/', ChangePasswordAPIView.as_view(), name='api_v1_change_password'),
    path('auth/reset-password-nid/', ResetPasswordByNationalIdAPIView.as_view(), name='api_v1_reset_password_nid'),
    path('auth/google/', GoogleLoginAPIView.as_view(), name='api_v1_google_login'),
    path('auth/google/callback/', GoogleMobileCallbackView.as_view(), name='api_v1_google_mobile_callback'),
    path('auth/one-time-login/', OneTimeLoginAPIView.as_view(), name='api_v1_one_time_login'),

    # 2. Public & General
    path('public/home/', PublicHomeAPIView.as_view(), name='api_v1_public_home'),
    path('public/metadata/', PublicMetadataAPIView.as_view(), name='api_v1_public_metadata'),
    path('public/plans/', PublicPlansAPIView.as_view(), name='api_v1_public_plans'),
    path('public/guide/', PlatformGuideAPIView.as_view(), name='api_v1_public_guide'),
    path('curriculum/lessons/', CurriculumLookupAPIView.as_view(), name='api_v1_curriculum_lessons'),
    path('notifications/', NotificationsAPIView.as_view(), name='api_v1_notifications'),
    path('notifications/<int:notif_id>/read/', MarkNotificationReadAPIView.as_view(), name='api_v1_notification_read'),
    path('notifications/read-all/', MarkNotificationReadAPIView.as_view(), name='api_v1_notifications_read_all'),
    path('payments/manual-checkout/', ManualCheckoutAPIView.as_view(), name='api_v1_manual_checkout'),

    # 3. Student Endpoints
    path('student/dashboard/', StudentDashboardAPIView.as_view(), name='api_v1_student_dashboard'),
    path('student/groups/search/', StudentSearchGroupsAPIView.as_view(), name='api_v1_student_search_groups'),
    path('student/groups/<int:group_id>/join/', StudentJoinGroupAPIView.as_view(), name='api_v1_student_join_group'),
    path('student/groups/<int:group_id>/content/', StudentGroupContentAPIView.as_view(), name='api_v1_student_group_content'),
    path('student/lectures/<int:lecture_id>/watch/', StudentWatchGroupLectureAPIView.as_view(), name='api_v1_student_watch_lecture'),
    path('student/exams/<int:exam_id>/take/', StudentTakeGroupExamAPIView.as_view(), name='api_v1_student_take_exam'),
    path('student/groups/<int:group_id>/marks/', StudentGroupMarksAPIView.as_view(), name='api_v1_student_group_marks'),
    path('student/groups/<int:group_id>/ranking/', StudentGroupRankingAPIView.as_view(), name='api_v1_student_group_ranking'),
    path('student/groups/<int:group_id>/contact/', StudentGroupContactAPIView.as_view(), name='api_v1_student_group_contact'),
    path('student/packages/', StudentPackagesStoreAPIView.as_view(), name='api_v1_student_packages'),
    path('student/packages/<int:package_id>/', StudentPackageDetailAPIView.as_view(), name='api_v1_student_package_detail'),
    path('student/packages/<int:package_id>/content/', StudentMyPackageContentAPIView.as_view(), name='api_v1_student_package_content'),
    path('student/packages/<int:package_id>/lectures/<int:lecture_id>/watch/', StudentWatchPackageLectureAPIView.as_view(), name='api_v1_student_watch_pkg_lecture'),
    path('student/packages/<int:package_id>/exams/<int:exam_id>/take/', StudentTakePackageExamAPIView.as_view(), name='api_v1_student_take_pkg_exam'),
    path('student/packages/<int:package_id>/marks/', StudentPackageMarksAndRankingAPIView.as_view(), name='api_v1_student_package_marks'),

    # 4. Teacher & Assistant Endpoints
    path('teacher/dashboard/', TeacherDashboardAPIView.as_view(), name='api_v1_teacher_dashboard'),
    path('teacher/groups/<int:group_id>/', TeacherGroupDetailAPIView.as_view(), name='api_v1_teacher_group_detail'),
    path('teacher/groups/<int:group_id>/lectures/', TeacherGroupLecturesAPIView.as_view(), name='api_v1_teacher_group_lectures'),
    path('teacher/lectures/<int:lecture_id>/', TeacherLectureActionAPIView.as_view(), name='api_v1_teacher_lecture_action'),
    path('teacher/lectures/<int:lecture_id>/codes/', TeacherVideoCodesAPIView.as_view(), name='api_v1_teacher_video_codes'),
    path('teacher/groups/<int:group_id>/pdfs/', TeacherPDFsAPIView.as_view(), name='api_v1_teacher_group_pdfs'),
    path('teacher/packages/<int:package_id>/pdfs/', TeacherPDFsAPIView.as_view(), name='api_v1_teacher_package_pdfs'),
    path('teacher/pdfs/<int:pdf_id>/', TeacherPDFsAPIView.as_view(), name='api_v1_teacher_delete_pdf'),
    path('teacher/groups/<int:group_id>/exams/', TeacherGroupExamsAPIView.as_view(), name='api_v1_teacher_group_exams'),
    path('teacher/exams/<int:exam_id>/', TeacherExamDetailAPIView.as_view(), name='api_v1_teacher_exam_detail'),
    path('teacher/questions/<int:question_id>/', TeacherQuestionDetailAPIView.as_view(), name='api_v1_teacher_question_detail'),
    path('teacher/groups/<int:group_id>/students/', TeacherGroupStudentsAPIView.as_view(), name='api_v1_teacher_group_students'),
    path('teacher/groups/<int:group_id>/students/<int:student_id>/logs/', TeacherStudentFullLogAPIView.as_view(), name='api_v1_teacher_student_logs'),
    path('teacher/groups/<int:group_id>/bulk-log/', TeacherBulkLogAPIView.as_view(), name='api_v1_teacher_bulk_log'),
    path('teacher/groups/<int:group_id>/ranking/', TeacherGroupRankingAndImportAPIView.as_view(), name='api_v1_teacher_group_ranking'),
    path('teacher/packages/', TeacherPackagesAPIView.as_view(), name='api_v1_teacher_packages'),
    path('teacher/packages/<int:package_id>/', TeacherPackageDetailAPIView.as_view(), name='api_v1_teacher_package_detail'),
    path('teacher/wallet/', TeacherWalletAPIView.as_view(), name='api_v1_teacher_wallet'),
    path('teacher/assistants/', TeacherManageAssistantsAPIView.as_view(), name='api_v1_teacher_assistants'),

    # Assistant-specific
    path('assistant/dashboard/', AssistantDashboardAPIView.as_view(), name='api_v1_assistant_dashboard'),
    path('assistant/teachers/<int:teacher_id>/groups/', AssistantTeacherGroupsAPIView.as_view(), name='api_v1_assistant_teacher_groups'),

    # 5. Admin & Owner Endpoints
    path('admin/dashboard/', AdminDashboardAPIView.as_view(), name='api_v1_admin_dashboard'),
    path('admin/maintenance/toggle/', AdminToggleMaintenanceAPIView.as_view(), name='api_v1_admin_maintenance_toggle'),
    path('admin/users/', AdminManageUsersAPIView.as_view(), name='api_v1_admin_users'),
    path('admin/finance/', AdminFinanceAPIView.as_view(), name='api_v1_admin_finance'),
    path('admin/plans-staff/', AdminPlansAndStaffAPIView.as_view(), name='api_v1_admin_plans_staff'),
    path('admin/support/', AdminSupportInboxAPIView.as_view(), name='api_v1_admin_support'),

    # 6. Secure Video Playback & Progress & App Integrity
    path('videos/continue-watching/', ContinueWatchingAPIView.as_view(), name='api_v1_video_continue_watching'),
    path('videos/<int:lecture_id>/authorize/', VideoAuthorizeAPIView.as_view(), name='api_v1_video_authorize'),
    path('videos/<int:lecture_id>/heartbeat/', VideoHeartbeatAPIView.as_view(), name='api_v1_video_heartbeat'),
    path('videos/<int:lecture_id>/progress/', VideoProgressAPIView.as_view(), name='api_v1_video_progress'),
    path('videos/<int:lecture_id>/bookmarks/', VideoBookmarksAPIView.as_view(), name='api_v1_video_bookmarks'),
    path('videos/bookmarks/<int:bookmark_id>/', VideoBookmarksAPIView.as_view(), name='api_v1_video_bookmark_delete'),
    path('videos/sessions/<uuid:session_id>/revoke/', VideoSessionRevokeAPIView.as_view(), name='api_v1_video_session_revoke'),
    path('videos/stream/<str:playback_token>/', ProtectedVideoStreamProxyAPIView.as_view(), name='api_v1_video_stream_proxy'),
    path('security/integrity/challenge/', PlayIntegrityChallengeAPIView.as_view(), name='api_v1_integrity_challenge'),
    path('security/integrity/verify/', PlayIntegrityVerifyAPIView.as_view(), name='api_v1_integrity_verify'),
]

